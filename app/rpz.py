"""离线 RPZ（Response Policy Zone）求值。

不发起任何真实 DNS 查询：输入**按顺序给出的 RPZ 区域文本**（策略区，
序号越小优先级越高）与一条 DNS 查询结果（``qname`` / ``qtype`` /
``response`` 的 answer/authority/additional 三个记录区），按 RPZ
（BIND Response Policy Zones）的触发器语义离线求值。

支持四种触发器（owner 相对策略区源点编码）：

- **QNAME**：owner 直接位于区顶之下（不含特殊分支），名称精确或
  ``*.`` 通配匹配（通配只匹配一个标签）；
- **RESPONSE-IP**：``<前缀长度>.<反向地址标签>.rpz-ip.<apex>``，
  IPv4 反向字节、IPv6 反向半字节（nibble），前缀编码匹配；
- **NSDNAME**：``<名称>.rpz-nsdname.<apex>``，名称精确或 ``*.``
  通配，匹配应答中的 NS 目标名（目标名位于触发名之下即命中）；
- **NSIP**：``<前缀长度>.<反向地址标签>.rpz-nsip.<apex>``，
  匹配应答中名称服务器的地址（answer/authority 的 NS 目标，其
  A/AAAA 由三个记录区中随响应提供的记录给出）。

选规则：**先选序号最小的、含任一触发器命中的策略区**，再在该区内按
``QNAME → RESPONSE-IP → NSDNAME → NSIP`` 的触发器次序与**最长匹配**
选出唯一规则（精确名长于通配；地址前缀更长；owner/目标相同的重复规则
去重；其余并列按 owner 确定唯一顺序）。

CNAME 动作目标：``.`` → NXDOMAIN、``*.`` → NODATA、``rpz-passthru.``
→ 放行并终止后续策略区、``rpz-drop.`` → 丢弃、``rpz-tcp-only.`` →
仅 TCP；其它目标用于改写（rewrite）。无任何命中为 unchanged。

解析期错误（422）：非法 RPZ 反向前缀（``invalid_prefix``）、区外
owner（``owner_out_of_zone``）、冲突 RRset（``conflict_rrset``）与
区域文本结构错误（``zone_parse_error``）。记录书写顺序不改变求值结果。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .review import ReviewError
from .zoneparse import (
    ZoneParseError,
    _logical_lines,
    _parse_duration,
    _TOKEN_RE,
    validate_name,
)

# 触发器次序（数值越小越优先）
TRIGGER_ORDER = {
    "qname": 0,
    "response-ip": 1,
    "nsdname": 2,
    "nsip": 3,
}
# 特殊 CNAME 动作目标 → 动作码（主文件中均为根点结尾的绝对名）
SPECIAL_ACTIONS = {
    ".": "nxdomain",
    "*.": "nodata",
    "rpz-passthru.": "passthru",
    "rpz-drop.": "drop",
    "rpz-tcp-only.": "tcp-only",
}
_BRANCHES = ("rpz-ip", "rpz-nsdname", "rpz-nsip")
_LABEL_RE = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")
_QTYPE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


# ---------------------------------------------------------------------------
# RPZ 区域解析
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """一条规范化的 RPZ 策略规则。"""

    kind: str  # qname / response-ip / nsdname / nsip
    zone_index: int
    zone_origin: str
    owner: str  # 记录 owner（小写绝对名）
    ttl: int
    action: str  # nxdomain/nodata/passthru/drop/tcp-only/rewrite
    target: str | None = None  # rewrite 时的目标名
    # 名称触发器：触发名（小写绝对名），is_wildcard 表示首标签为 *
    trigger_name: str | None = None
    is_wildcard: bool = False
    # 地址触发器：前缀网络与前缀长度
    network: object = None
    prefix_len: int | None = None

    def describe(self) -> dict:
        entry = {
            "trigger": self.kind,
            "zone_index": self.zone_index,
            "zone": self.zone_origin,
            "owner": self.owner,
            "ttl": self.ttl,
            "action": self.action,
        }
        if self.target is not None:
            entry["target"] = self.target
        if self.prefix_len is not None:
            entry["prefix_len"] = self.prefix_len
        return entry


def _validate_wild_name(token: str) -> None:
    """校验一个 RPZ 名（允许 ``*`` 作为首标签的精确单标签）。"""
    if token == ".":
        return
    bare = token[:-1]
    if len(bare) > 253:
        raise ValueError(f"名称超过 253 字节: {token!r}")
    for pos, label in enumerate(bare.split(".")):
        if label == "*":
            if pos != 0:
                raise ValueError(f"通配符 '*' 只能作为首标签: {token!r}")
            continue
        if not _LABEL_RE.fullmatch(label):
            raise ValueError(f"非法名称标签: {label!r}（来自 {token!r}）")


def _join_origin(name: str, origin: str) -> str:
    """把相对名补到源点之下（源点为根 ``.`` 时直接加根点）。"""
    if origin == ".":
        return name + "."
    return f"{name}.{origin}"


def _normalize_owner(token: str, origin: str) -> str:
    """规范化 RPZ 记录 owner（支持 ``@`` 与 ``*.`` 首标签通配）。"""
    low = token.lower().strip()
    if low == "@":
        absolute = origin
    elif low == ".":
        absolute = "."
    elif low.endswith("."):
        absolute = low
    else:
        absolute = _join_origin(low, origin)
    _validate_wild_name(absolute)
    return absolute


def _normalize_target(token: str, origin: str) -> str:
    """规范化 CNAME 动作目标（支持 ``*.`` 首标签通配与相对名）。"""
    low = token.lower().strip()
    if low == ".":
        return "."
    absolute = low if low.endswith(".") else _join_origin(low, origin)
    _validate_wild_name(absolute)
    return absolute


def _strip_zone_suffix(owner: str, suffix: str) -> str | None:
    """owner 恰好位于 suffix 之下时返回子前缀（不含尾点），否则 None。"""
    if owner == suffix:
        return ""
    tail = "." + suffix
    if owner.endswith(tail):
        return owner[: -len(tail)]
    return None


def _decode_ip_prefix(prefix: str) -> tuple[object, int]:
    """解码 RPZ 反向前缀编码（``<len>[.<反向标签>...]``）。

    返回 (ip_network, prefix_len)。标签数 0..4 视为 IPv4（每标签
    0..255 字节），5..32 视为 IPv6（每标签单个十六进制半字节）；
    标签数必须恰好为 ceil(prefix_len/8)（v4）或 ceil(prefix_len/4)
    （v6），且主机位为零——否则前缀编码非法（422）。
    """
    labels = prefix.split(".") if prefix else []
    length_token = labels[0]
    if not length_token.isdigit():
        raise ValueError(f"RPZ 地址触发器前缀长度非法: {length_token!r}")
    prefix_len = int(length_token)
    data = labels[1:]

    if len(data) <= 4:
        # IPv4：反向字节
        if prefix_len > 32:
            raise ValueError(f"IPv4 RPZ 前缀长度超出 32: /{prefix_len}")
        expect = (prefix_len + 7) // 8
        if expect != len(data):
            raise ValueError(
                f"IPv4 RPZ 前缀 /{prefix_len} 需要恰好 {expect} 个反向字节"
                f"标签，实际 {len(data)} 个: {prefix!r}"
            )
        octets: list[int] = []
        for label in data:
            if not label.isdigit() or not 0 <= int(label) <= 255:
                raise ValueError(
                    f"IPv4 RPZ 反向字节标签必须是 0..255: {label!r}"
                )
            octets.append(int(label))
        octets.reverse()
        octets.extend([0] * (4 - len(octets)))
        address = ipaddress.IPv4Address(bytes(octets))
        network = ipaddress.IPv4Network((address, prefix_len), strict=False)
        if int(address) & int(network.hostmask) != 0:
            raise ValueError(
                f"RPZ 前缀 {prefix!r} 的主机位非零（规范前缀要求主机位为 0）"
            )
        return network, prefix_len

    # IPv6：反向半字节
    if len(data) > 32:
        raise ValueError(
            f"RPZ 地址触发器反向标签过多（超过 32 个半字节）: {prefix!r}"
        )
    if prefix_len < 17:
        # 与 BIND 一致：半字节（>4 标签）形式无法表达 IPv6 /16 及以下
        raise ValueError(
            f"半字节编码的 IPv6 RPZ 前缀不能短于 /17: /{prefix_len}"
        )
    if prefix_len > 128:
        raise ValueError(f"IPv6 RPZ 前缀长度超出 128: /{prefix_len}")
    expect = (prefix_len + 3) // 4
    if expect != len(data):
        raise ValueError(
            f"IPv6 RPZ 前缀 /{prefix_len} 需要恰好 {expect} 个反向半字节"
            f"标签，实际 {len(data)} 个: {prefix!r}"
        )
    nibbles: list[int] = []
    for label in data:
        if not re.fullmatch(r"[0-9a-fA-F]", label):
            raise ValueError(
                f"IPv6 RPZ 反向半字节标签必须是单个十六进制数字: {label!r}"
            )
        nibbles.append(int(label, 16))
    nibbles.reverse()
    nibbles.extend([0] * (32 - len(nibbles)))
    packed = bytes(
        (nibbles[i] << 4) | nibbles[i + 1] for i in range(0, 32, 2)
    )
    address = ipaddress.IPv6Address(packed)
    network = ipaddress.IPv6Network((address, prefix_len), strict=False)
    if int(address) & int(network.hostmask) != 0:
        raise ValueError(
            f"RPZ 前缀 {prefix!r} 的主机位非零（规范前缀要求主机位为 0）"
        )
    return network, prefix_len


def _classify_owner(owner: str, origin: str) -> tuple[str, str]:
    """把记录 owner 分类为触发器，返回 (kind, 子前缀)。

    子前缀对名称触发器为触发名（相对区顶），对地址触发器为反向编码。
    分支本身的根 owner（子前缀为空）交由调用方按语义拒绝。
    """
    best: tuple[str, str] | None = None  # (branch, 完整后缀)
    for branch in _BRANCHES:
        suffix = _join_origin(branch, origin)
        sub = _strip_zone_suffix(owner, suffix)
        if sub is not None and (best is None or len(suffix) > len(best[1])):
            best = (branch, suffix)
    if best is None:
        if origin == ".":
            # 根源点：子前缀即去掉根点的全名
            return "qname", owner[:-1] if owner != "." else ""
        sub = _strip_zone_suffix(owner, origin)
        assert sub is not None
        return "qname", sub
    branch, suffix = best
    sub = _strip_zone_suffix(owner, suffix)
    assert sub is not None
    if branch == "rpz-nsdname":
        return "nsdname", sub
    return ("response-ip" if branch == "rpz-ip" else "nsip"), sub


class _ParseAbort(Exception):
    """parse_rpz_zone 内部：已登记错误，立即结束本区解析。"""


def parse_rpz_zone(
    text: str,
    zone_index: int,
    errors: list[dict],
) -> tuple[str, list[Rule]] | None:
    """解析一段 RPZ 区域文本为 (源点, 规则列表)；出错追加 errors 并返回 None。"""
    origin: str | None = None
    current_ttl: int | None = None
    last_owner: str | None = None
    # owner -> [ttl, set(CNAME 目标)]，随后固化为 Rule
    collected: dict[str, list] = {}
    # 存在非 CNAME 元数据（A/AAAA）的 owner，用于 CNAME 排他冲突检测
    other_owners: set[str] = set()
    soa_seen = False

    def fail(code: str, message: str, line_no: int | None = None):
        if line_no is not None:
            message = f"第 {line_no} 行: {message}"
        errors.append({"index": zone_index, "code": code, "message": message})
        raise _ParseAbort

    try:
        logical_lines = list(_logical_lines(text))
    except ZoneParseError as exc:
        errors.append({
            "index": zone_index,
            "code": "zone_parse_error",
            "message": str(exc),
        })
        return None

    try:
        for line_no, line in logical_lines:
            tokens = line.split()
            head = tokens[0].lower()

            if head == "$origin":
                if len(tokens) != 2:
                    fail("zone_parse_error",
                         "$ORIGIN 需要恰好一个参数", line_no)
                value = tokens[1].lower()
                if not value.endswith("."):
                    fail("zone_parse_error",
                         "RPZ 区域的 $ORIGIN 必须是绝对名", line_no)
                try:
                    validate_name(value)
                except ZoneParseError as exc:
                    fail("zone_parse_error", f"非法 $ORIGIN: {exc}", line_no)
                if origin is not None and value != origin:
                    fail("zone_parse_error",
                         "RPZ 区域不允许在中途改变 $ORIGIN", line_no)
                origin = value
                continue

            if head == "$ttl":
                if len(tokens) != 2:
                    fail("zone_parse_error",
                         "$TTL 需要恰好一个参数", line_no)
                try:
                    current_ttl = _parse_duration(tokens[1], line_no)
                except ZoneParseError as exc:
                    fail("zone_parse_error", str(exc), line_no)
                continue

            if head.startswith("$"):
                fail("zone_parse_error",
                     f"不支持的指令: {tokens[0]}", line_no)

            if origin is None:
                fail("zone_parse_error",
                     "缺少 $ORIGIN 指令，无法确定 RPZ 策略区源点", line_no)

            # 属名省略：以空白开头的行继承上一条属名
            if line[:1].isspace():
                if last_owner is None:
                    fail("zone_parse_error", "首条记录不能省略属名", line_no)
                owner = last_owner
                body = line.lstrip()
            else:
                gap = re.search(r"\s", line)
                if gap is None:
                    fail("zone_parse_error",
                         "记录缺少 TTL/类型/RDATA 字段", line_no)
                owner_token = line[: gap.start()]
                body = line[gap.end():].lstrip()
                try:
                    owner = _normalize_owner(owner_token, origin)
                except ValueError as exc:
                    fail("zone_parse_error", str(exc), line_no)
                last_owner = owner

            if origin != "." and owner != "." and not (
                owner == origin or owner.endswith("." + origin)
            ):
                fail(
                    "owner_out_of_zone",
                    f"记录 owner {owner} 位于 RPZ 策略区 {origin} 之外",
                    line_no,
                )

            ttl: int | None = None
            rtype: str | None = None
            rdata_start = None
            pos = 0
            while True:
                while pos < len(body) and body[pos].isspace():
                    pos += 1
                match = _TOKEN_RE.match(body, pos)
                if match is None:
                    break
                tok = match.group(0)
                low = tok.lower()
                if (ttl is None and re.fullmatch(r"\d+[smhdwSMHDW]", tok)) or (
                    ttl is None and low.isdigit()
                ):
                    try:
                        ttl = _parse_duration(tok, line_no)
                    except ZoneParseError as exc:
                        fail("zone_parse_error", str(exc), line_no)
                elif low == "in":
                    pass
                elif low in ("soa", "ns", "cname", "a", "aaaa"):
                    rtype = low.upper()
                    rdata_start = match.end()
                    break
                else:
                    fail(
                        "conflict_rrset",
                        f"RPZ 策略区仅支持 SOA/NS/A/AAAA（区元数据）与 "
                        f"CNAME（触发器动作）记录，无法处理 {tok!r}",
                        line_no,
                    )
                pos = match.end()

            if rtype is None:
                fail("zone_parse_error", "记录缺少 RR 类型", line_no)
            if ttl is None:
                if current_ttl is None:
                    fail("zone_parse_error",
                         "记录省略了 TTL 且此前没有 $TTL 指令", line_no)
                ttl = current_ttl

            rdata_tokens = body[rdata_start:].split()

            if rtype == "SOA":
                if owner != origin:
                    fail("zone_parse_error",
                         "SOA 必须位于区顶（当前源点）", line_no)
                if soa_seen:
                    fail("conflict_rrset",
                         "区顶只允许一个 SOA RRset", line_no)
                soa_seen = True
                # RPZ 求值不使用 SOA 内容，但必须是可解析的 7 字段
                if len(rdata_tokens) != 7:
                    fail("zone_parse_error",
                         "SOA RDATA 应为 7 个字段 (mname rname serial "
                         "refresh retry expire minimum)", line_no)
                continue

            if rtype == "NS":
                if owner != origin:
                    fail(
                        "conflict_rrset",
                        f"非区顶 NS 记录 {owner} 不能作为 RPZ 策略规则"
                        "（RPZ 策略规则只接受 CNAME 动作）",
                        line_no,
                    )
                if len(rdata_tokens) != 1:
                    fail("zone_parse_error",
                         "NS 只能有一个目标字段", line_no)
                target = rdata_tokens[0].lower()
                if target != "." and not target.endswith("."):
                    target += "."
                try:
                    validate_name(target)
                except ZoneParseError as exc:
                    fail("zone_parse_error", f"NS 目标非法: {exc}", line_no)
                continue

            if rtype in ("A", "AAAA"):
                # 本服务的 RPZ 触发器只由 CNAME 动作编码；A/AAAA 是策略区
                # 自身的名称服务器地址（含区内 glue）等元数据，校验地址
                # 合法但不参与求值。触发器 owner 上 CNAME 与其它类型并存
                # 属于冲突 RRset（CNAME 排他）。
                if owner in collected:
                    fail(
                        "conflict_rrset",
                        f"触发器 owner {owner} 同时存在 CNAME 与 {rtype}"
                        " RRset（CNAME 必须独占 owner）",
                        line_no,
                    )
                if not rdata_tokens:
                    fail("zone_parse_error",
                         f"{rtype} 缺少地址字段", line_no)
                for token in rdata_tokens:
                    try:
                        if rtype == "A":
                            ipaddress.IPv4Address(token)
                        else:
                            ipaddress.IPv6Address(token)
                    except ValueError as exc:
                        fail("zone_parse_error",
                             f"非法 {rtype} 地址 {token!r}: {exc}", line_no)
                other_owners.add(owner)
                continue

            # CNAME：触发器规则
            if owner == origin:
                fail(
                    "conflict_rrset",
                    "区顶 CNAME 不能作为 RPZ 策略规则（区顶仅允许 SOA/NS）",
                    line_no,
                )
            if owner in other_owners:
                fail(
                    "conflict_rrset",
                    f"触发器 owner {owner} 同时存在 CNAME 与其它类型 RRset"
                    "（CNAME 必须独占 owner）",
                    line_no,
                )
            if len(rdata_tokens) != 1:
                fail("conflict_rrset",
                     "CNAME 只能有一个目标字段（单点 RRset）", line_no)
            try:
                target = _normalize_target(rdata_tokens[0], origin)
            except ValueError as exc:
                fail("zone_parse_error", str(exc), line_no)

            entry = collected.get(owner)
            if entry is None:
                collected[owner] = [ttl, {target}]
            else:
                if entry[0] != ttl:
                    fail(
                        "conflict_rrset",
                        f"{owner} CNAME 的同一 RRset 出现不同 TTL: "
                        f"{entry[0]} 与 {ttl}",
                        line_no,
                    )
                entry[1].add(target)
    except _ParseAbort:
        return None

    assert origin is not None

    # 语义固化：owner → 触发器分类与前缀解码
    rules: list[Rule] = []
    for owner, (ttl, targets) in collected.items():
        if len(targets) > 1:
            errors.append({
                "index": zone_index,
                "code": "conflict_rrset",
                "message": f"{owner} CNAME 单点 RRset 出现多个不同目标: "
                           + ", ".join(sorted(targets)),
            })
            return None
        target = next(iter(targets))
        action = SPECIAL_ACTIONS.get(target, "rewrite")
        rewrite_target = target if action == "rewrite" else None
        kind, sub = _classify_owner(owner, origin)

        if kind in ("qname", "nsdname"):
            if kind == "nsdname" and not sub:
                errors.append({
                    "index": zone_index,
                    "code": "invalid_prefix",
                    "message": f"rpz-nsdname 分支根 {owner} 不是合法的 "
                               "NSDNAME 触发器（缺少触发名）",
                })
                return None
            wildcard = sub.split(".", 1)[0] == "*"
            trigger_name = _join_origin(sub, origin)
            rules.append(Rule(
                kind=kind, zone_index=zone_index, zone_origin=origin,
                owner=owner, ttl=ttl, action=action, target=rewrite_target,
                trigger_name=trigger_name, is_wildcard=wildcard,
            ))
        else:
            if sub.split(".", 1)[0] == "*":
                errors.append({
                    "index": zone_index,
                    "code": "invalid_prefix",
                    "message": f"{owner} 所在地址触发器分支不支持 '*' 通配"
                               "（地址触发器使用反向前缀编码）",
                })
                return None
            try:
                network, prefix_len = _decode_ip_prefix(sub)
            except ValueError as exc:
                errors.append({
                    "index": zone_index,
                    "code": "invalid_prefix",
                    "message": str(exc),
                })
                return None
            rules.append(Rule(
                kind=kind, zone_index=zone_index, zone_origin=origin,
                owner=owner, ttl=ttl, action=action, target=rewrite_target,
                network=network, prefix_len=prefix_len,
            ))

    return origin, rules


# ---------------------------------------------------------------------------
# 请求中的 DNS 查询结果
# ---------------------------------------------------------------------------

_ADDRESS_TYPES = ("A", "AAAA")
_SECTIONS = ("answer", "authority", "additional")
_RCODES = ("NOERROR", "NXDOMAIN", "SERVFAIL", "REFUSED")


@dataclass(frozen=True)
class _RespRecord:
    name: str
    rtype: str
    ttl: int
    rdata: str


def _fqdn(value: str, field: str) -> str:
    name = value.strip().lower()
    if name != "." and not name.endswith("."):
        name += "."
    try:
        validate_name(name)
    except ZoneParseError as exc:
        raise ReviewError("invalid_request",
                          f"{field} 非法: {exc}", 400) from exc
    return name


def _parse_response_record(value, where: str) -> _RespRecord:
    if not isinstance(value, dict):
        raise ReviewError("invalid_request", f"{where} 必须是记录对象", 400)
    name = value.get("name")
    rtype = value.get("type")
    rdata = value.get("rdata")
    if not isinstance(name, str) or not name.strip():
        raise ReviewError(
            "invalid_request", f"{where}.name 必须是非空字符串", 400)
    if not isinstance(rtype, str) or not rtype.strip():
        raise ReviewError(
            "invalid_request", f"{where}.type 必须是非空字符串", 400)
    if not isinstance(rdata, str):
        raise ReviewError(
            "invalid_request", f"{where}.rdata 必须是字符串", 400)
    ttl = value.get("ttl", 0)
    if isinstance(ttl, bool) or not isinstance(ttl, int) \
            or not 0 <= ttl < 2**31:
        raise ReviewError(
            "invalid_request", f"{where}.ttl 必须是 0..2^31-1 的整数", 400)

    norm_name = _fqdn(name, f"{where}.name")
    norm_type = rtype.strip().upper()
    text = rdata.strip()

    if norm_type in _ADDRESS_TYPES:
        try:
            canonical = (
                str(ipaddress.IPv4Address(text))
                if norm_type == "A"
                else str(ipaddress.IPv6Address(text)).lower()
            )
        except ValueError as exc:
            raise ReviewError(
                "invalid_record",
                f"{where} 的 {norm_type} RDATA 非法: {exc}",
                422,
                [{"record": where, "message": str(exc)}],
            ) from exc
    elif norm_type == "NS":
        target = text.lower()
        if target != "." and not target.endswith("."):
            target += "."
        try:
            validate_name(target)
        except ZoneParseError as exc:
            raise ReviewError(
                "invalid_record",
                f"{where} 的 NS RDATA 非法: {exc}",
                422,
                [{"record": where, "message": str(exc)}],
            ) from exc
        canonical = target
    else:
        # 不解释其它类型（CNAME/SOA/RRSIG 等），RPZ 触发器也不使用它们
        canonical = text
    return _RespRecord(norm_name, norm_type, ttl, canonical)


# ---------------------------------------------------------------------------
# 匹配
# ---------------------------------------------------------------------------

def _qname_match(rule: Rule, name: str) -> bool:
    """QNAME 触发器匹配：精确或单标签通配（``*.x.`` 不匹配多级名字）。"""
    trigger = rule.trigger_name
    if trigger is None:
        return False
    if not rule.is_wildcard:
        return name == trigger
    base = trigger[2:]  # 去掉 "*."
    if not name.endswith("." + base):
        return False
    left = name[: -(len(base) + 1)]
    return left != "" and "." not in left


def _nsdname_match(rule: Rule, name: str) -> bool:
    """NSDNAME 匹配：精确触发名时 NS 名等于或位于其下；通配只下探一级。"""
    if rule.is_wildcard:
        return _qname_match(rule, name)
    trigger = rule.trigger_name
    return trigger is not None and (
        name == trigger or name.endswith("." + trigger))


def _name_key(rule: Rule):
    # 精确优先于通配，再按触发名标签数（最长匹配），最后 owner/目标定序
    depth = 1 if rule.is_wildcard else 0
    labels = len(rule.trigger_name.rstrip(".").split("."))
    return (depth, -labels, rule.owner, rule.target or "")


def _best_name_rule(
    rules: list[Rule], name: str, matcher
) -> Rule | None:
    hits = [rule for rule in rules if matcher(rule, name)]
    return sorted(hits, key=_name_key)[0] if hits else None


def _addr_matches(
    rules: list[Rule], addresses: list[ipaddress._BaseAddress]
) -> list[tuple[Rule, str]]:
    """返回全部命中的 (规则, 地址)，按选择优先级排序并按规则去重。

    一条规则命中多个地址时只保留排序最靠前的地址；整体顺序为
    最长前缀优先、同长 IPv4 先于 IPv6、再按地址与 owner 确定唯一顺序。
    """
    best_by_rule: dict[Rule, tuple] = {}
    for rule in rules:
        network = rule.network
        for address in addresses:
            if network is None or address.version != network.version:
                continue
            if address not in network:
                continue
            sort_key = (-rule.prefix_len, address.version,
                        address.packed, rule.owner)
            current = best_by_rule.get(rule)
            if current is None or sort_key < current[0]:
                best_by_rule[rule] = (sort_key, str(address))
    ordered = sorted(
        best_by_rule.items(),
        key=lambda item: item[1][0],
    )
    return [(rule, value[1]) for rule, value in ordered]


def _name_matches(
    rules: list[Rule], names: list[str], matcher
) -> list[tuple[Rule, str]]:
    """返回全部命中的 (规则, 名称)，按选择优先级排序并按规则去重。"""
    best_by_rule: dict[Rule, tuple] = {}
    for name in names:
        for rule in rules:
            if not matcher(rule, name):
                continue
            sort_key = (*_name_key(rule),)
            current = best_by_rule.get(rule)
            if current is None or sort_key < current[0]:
                best_by_rule[rule] = (sort_key, name)
    ordered = sorted(best_by_rule.items(), key=lambda item: item[1][0])
    return [(rule, value[1]) for rule, value in ordered]


# ---------------------------------------------------------------------------
# 求值编排
# ---------------------------------------------------------------------------

def evaluate_rpz(payload: dict) -> dict:
    """执行一次离线 RPZ 求值，返回可直接序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    zones_text = payload.get("zones")
    if not isinstance(zones_text, list) or not zones_text:
        raise ReviewError(
            "invalid_request", "zones 必须是非空的 RPZ 区域文本字符串数组",
            400,
        )

    errors: list[dict] = []
    parsed_zones: list[tuple[int, str, list[Rule]]] = []
    for position, text in enumerate(zones_text):
        if not isinstance(text, str) or not text.strip():
            raise ReviewError(
                "invalid_request",
                f"zones[{position}] 必须是非空 RPZ 区域文本字符串",
                400,
            )
        parsed = parse_rpz_zone(text, position, errors)
        if parsed is not None:
            parsed_zones.append((position, parsed[0], parsed[1]))
    if errors:
        raise ReviewError(
            errors[0]["code"], "RPZ 区域解析失败", 422, errors)

    qname_raw = payload.get("qname")
    if not isinstance(qname_raw, str) or not qname_raw.strip():
        raise ReviewError(
            "invalid_request", "qname 必须是非空域名", 400)
    qname = _fqdn(qname_raw, "qname")

    qtype = payload.get("qtype", "A")
    if not isinstance(qtype, str) or not _QTYPE_RE.fullmatch(qtype.strip()):
        raise ReviewError(
            "invalid_request",
            f"qtype 必须是非空类型字符串（如 A/AAAA/MX）: {qtype!r}",
            400,
        )
    qtype = qtype.strip().upper()

    response_in = payload.get("response", {})
    if response_in is None:
        response_in = {}
    if not isinstance(response_in, dict):
        raise ReviewError("invalid_request", "response 必须是对象", 400)
    rcode = str(response_in.get("rcode", "NOERROR")).strip().upper()
    if rcode not in _RCODES:
        raise ReviewError(
            "invalid_request",
            f"response.rcode 必须是 {'/'.join(_RCODES)} 之一: {rcode!r}",
            400,
        )

    sections: dict[str, list[_RespRecord]] = {}
    for section in _SECTIONS:
        records_in = response_in.get(section, [])
        if not isinstance(records_in, list):
            raise ReviewError(
                "invalid_request",
                f"response.{section} 必须是记录数组", 400)
        sections[section] = [
            _parse_response_record(item, f"response.{section}[{i}]")
            for i, item in enumerate(records_in)
        ]

    # 触发器输入：
    # - answer 中全部 A/AAAA 地址 → RESPONSE-IP；
    # - answer/authority 中 NS RDATA → NSDNAME；
    # - 三个区中以 NS 目标名为 owner 的 A/AAAA（胶水等）→ NSIP。
    answer_ips: list[ipaddress._BaseAddress] = []
    ns_names: list[str] = []
    addr_by_name: dict[str, list[ipaddress._BaseAddress]] = {}
    for section in _SECTIONS:
        for record in sections[section]:
            if record.rtype in _ADDRESS_TYPES:
                addr_by_name.setdefault(record.name, []).append(
                    ipaddress.ip_address(record.rdata))
                if section == "answer":
                    answer_ips.append(ipaddress.ip_address(record.rdata))
            elif record.rtype == "NS" and section in ("answer", "authority") \
                    and record.rdata not in ns_names:
                ns_names.append(record.rdata)
    nsip_addresses: list[ipaddress._BaseAddress] = []
    for ns_name in ns_names:
        for address in addr_by_name.get(ns_name, []):
            if address not in nsip_addresses:
                nsip_addresses.append(address)

    # ---- 逐策略区求值 ----
    trace: list[dict] = []
    candidates: list[dict] = []
    chosen: Rule | None = None
    chosen_value: str | None = None
    stopped_by_passthru = False

    for zone_index, zone_origin, rules in parsed_zones:
        by_kind: dict[str, list[Rule]] = {
            kind: [] for kind in TRIGGER_ORDER}
        for rule in rules:
            by_kind[rule.kind].append(rule)

        q_hit = _best_name_rule(by_kind["qname"], qname, _qname_match)
        ip_matches = _addr_matches(by_kind["response-ip"], answer_ips)
        nsd_matches = _name_matches(
            by_kind["nsdname"], sorted(ns_names), _nsdname_match)
        nsip_matches = _addr_matches(by_kind["nsip"], nsip_addresses)

        def first_of(matches):
            return matches[0] if matches else (None, None)

        trigger_results = [
            ("qname", q_hit, qname if q_hit else None),
            ("response-ip", *first_of(ip_matches)),
            ("nsdname", *first_of(nsd_matches)),
            ("nsip", *first_of(nsip_matches)),
        ]
        all_trigger_matches = {
            "qname": [(q_hit, qname)] if q_hit else [],
            "response-ip": ip_matches,
            "nsdname": nsd_matches,
            "nsip": nsip_matches,
        }

        zone_event: dict = {
            "zone_index": zone_index,
            "zone": zone_origin,
            "triggers": [],
        }
        first: tuple[str, Rule, str | None] | None = None
        for kind, rule, matched_value in trigger_results:
            matched = rule is not None
            trigger_event = {"trigger": kind, "matched": matched}
            if matched:
                trigger_event["rule"] = rule.describe()
                trigger_event["matched_value"] = matched_value
                if first is None:
                    first = (kind, rule, matched_value)
            zone_event["triggers"].append(trigger_event)
            # 候选：该触发器下全部命中规则（同触发器的并列匹配也列出）
            for matched_rule, matched_name in all_trigger_matches[kind]:
                entry = matched_rule.describe()
                entry["matched_value"] = matched_name
                candidates.append(entry)

        if first is None:
            zone_event["outcome"] = "no_match"
            trace.append(zone_event)
            continue

        zone_event["outcome"] = first[0]
        zone_event["rule"] = first[1].describe()
        trace.append(zone_event)

        if chosen is None:
            chosen = first[1]
            chosen_value = first[2]
            if chosen.action == "passthru":
                # 放行：PASSTHRU 终止后续策略区
                stopped_by_passthru = True
                break

    # 候选按 (策略区序号, 触发器次序, owner) 排序，保证与记录顺序无关
    candidates.sort(key=lambda c: (
        c["zone_index"], TRIGGER_ORDER[c["trigger"]], c["owner"]))

    zones_summary = [
        {"zone_index": index, "zone": origin, "rule_count": len(rules)}
        for index, origin, rules in parsed_zones
    ]
    base = {
        "qname": qname,
        "qtype": qtype,
        "rcode": rcode,
        "candidates": candidates,
        "trace": trace,
        "zones": zones_summary,
    }

    if chosen is None:
        return {
            **base,
            "result": "unchanged",
            "action": "unchanged",
            "matched_rule": None,
            "selection_reason": "no_trigger_matched",
        }

    result = {
        **base,
        "result": chosen.action,
        "action": chosen.action,
        "matched_rule": chosen.describe(),
        "matched_value": chosen_value,
    }
    if chosen.action == "rewrite":
        result["rewrite_target"] = chosen.target
    if stopped_by_passthru:
        result["selection_reason"] = (
            "passthru_terminates_further_policy_zones")
    else:
        result["selection_reason"] = (
            "lowest_zone_index_then_trigger_order_and_longest_match")
    return result
