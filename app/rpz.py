"""离线 RPZ（Response Policy Zone，策略区）求值。

不发起任何真实 DNS 查询：输入**按顺序给出的若干 RPZ 区域文本**与一条
DNS 查询结果（qname/qtype/protocol + answer/authority/additional），
按 RFC 草案 ``draft-ietf-dnsop-dns-rpz`` 的触发器语义离线求值得出策略结论。

触发器（本服务支持其中四种，次序即优先级）：

1. ``QNAME``      策略 owner 直接位于区下（无保留后缀）；
2. ``RESPONSE-IP`` owner 后缀为 ``<rel>.rpz-response-ip.<apex>``，匹配
   answer 中 A/AAAA 的地址；
3. ``NSDNAME``    owner 后缀为 ``<rel>.rpz-nsdname.<apex>``，匹配
   authority/answer 中 NS 的目标名；
4. ``NSIP``       owner 后缀为 ``<rel>.rpz-nsip.<apex>``，匹配属于这些
   NS 目标的胶水 A/AAAA 地址。

名称匹配：精确，或最左标签为 ``*`` 的 ``*.`` 通配（通配恰好匹配一个
标签），最长（标签数最多）的触发器获胜。地址按 RPZ 反向前缀编码匹配
（如 ``32.2.0.192.rpz-response-ip.<apex>``；IPv6 为逆序 nibble），
最长前缀获胜。

策略选择：先选**序号最小**（zones 数组下标最小）的含命中规则的策略区，
再在该区内按 ``QNAME -> RESPONSE-IP -> NSDNAME -> NSIP`` 的触发器次序，
每种触发器内取唯一的最长匹配规则。

CNAME 动作目标：``.`` -> NXDOMAIN、``*.`` -> NODATA、``rpz-passthru.``
-> 放行并**终止**后续策略区、``rpz-drop.`` -> 丢弃、
``rpz-tcp-only.`` -> 仅 TCP（UDP 查询命中时回截断响应促使改用 TCP；
TCP 查询下该规则视为不存在）；其它目标用于改写（CNAME 到该目标）。
任何动作都在第一个命中策略区结束；无任何命中返回 unchanged。记录书写
顺序重排不改变结论。

加载期错误（422）：非法触发器前缀编码、区外 owner、区顶策略 CNAME、
同一 owner 冲突的 RRset（CNAME 与其它类型共存、或多个不同 CNAME 目标）。
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .review import ReviewError
from .zoneparse import ZoneParseError, parse_zone, validate_name

# 触发器固定优先级（下标越小越优先）
TRIGGER_ORDER = ("qname", "response-ip", "nsdname", "nsip")
_TRIGGER_SUFFIX = {
    "response-ip": "rpz-response-ip",
    "nsip": "rpz-nsip",
    "nsdname": "rpz-nsdname",
}
_IP_TRIGGERS = frozenset(("response-ip", "nsip"))
_ADDRESS_TYPES = frozenset(("A", "AAAA"))

# 保留 CNAME 动作目标（小写绝对名）
TARGET_NXDOMAIN = "."
TARGET_NODATA = "*."
TARGET_PASSTHRU = "rpz-passthru."
TARGET_DROP = "rpz-drop."
TARGET_TCP_ONLY = "rpz-tcp-only."
SPECIAL_TARGETS = frozenset((
    TARGET_NXDOMAIN, TARGET_NODATA, TARGET_PASSTHRU,
    TARGET_DROP, TARGET_TCP_ONLY,
))

_SECTIONS = ("answer", "authority", "additional")


# ---------------------------------------------------------------------------
# 策略规则
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Rule:
    """一条规范化后的 RPZ 策略规则（一条 CNAME RR）。"""

    zone_index: int
    zone_origin: str
    trigger: str  # qname / response-ip / nsdname / nsip
    owner: str  # 小写绝对 owner（可能以 "*." 开头）
    ttl: int
    target: str  # CNAME 动作目标（小写绝对名）
    wildcard: bool
    # 名称触发器：相对区顶的匹配模式（"."=区顶自身）；
    # 地址触发器：解码后的 (网络, 前缀长度)
    name_pattern: str | None = None
    network: object | None = None
    prefix_len: int | None = None

    @property
    def action(self) -> str:
        """原始动作类型（特殊目标之一或 rewrite）。"""
        if self.target == TARGET_NXDOMAIN:
            return "nxdomain"
        if self.target == TARGET_NODATA:
            return "nodata"
        if self.target == TARGET_PASSTHRU:
            return "passthru"
        if self.target == TARGET_DROP:
            return "drop"
        if self.target == TARGET_TCP_ONLY:
            return "tcp-only"
        return "rewrite"

    def to_dict(self) -> dict:
        data = {
            "zone_index": self.zone_index,
            "zone_origin": self.zone_origin,
            "trigger": self.trigger,
            "owner": self.owner,
            "ttl": self.ttl,
            "target": self.target,
            "action": self.action,
            "match": "wildcard" if self.wildcard else "exact",
        }
        if self.trigger in _IP_TRIGGERS:
            data["prefix_len"] = self.prefix_len
            data["network"] = str(self.network)
        else:
            data["name_pattern"] = self.name_pattern
        return data


# ---------------------------------------------------------------------------
# 名称 / 地址工具
# ---------------------------------------------------------------------------

def _labels(name: str) -> list[str]:
    if name == ".":
        return []
    return name.rstrip(".").split(".")


def _ends_with_labels(labels: list[str], suffix: list[str]) -> bool:
    return len(labels) >= len(suffix) and labels[-len(suffix):] == suffix


def classify_trigger(owner: str, apex: str) -> tuple[str, list[str], bool]:
    """按 owner 与区顶判定触发器类型。

    返回 (trigger, 去掉保留后缀/通配标签后的 rel 标签序列, wildcard)。
    rel 为空表示匹配区顶自身。
    """
    labels = _labels(owner)
    wildcard = bool(labels and labels[0] == "*")
    if wildcard:
        labels = labels[1:]
    apex_labels = _labels(apex)
    for trigger, suffix_name in _TRIGGER_SUFFIX.items():
        suffix = [suffix_name] + apex_labels
        if _ends_with_labels(labels, suffix):
            return trigger, labels[: -len(suffix)], wildcard
    if not _ends_with_labels(labels, apex_labels):
        raise ValueError(f"owner {owner} 不在区 {apex} 内")
    return "qname", labels[: -len(apex_labels)], wildcard


def decode_ip_prefix(rel: list[str], wildcard: bool) -> tuple[object, int]:
    """解码 RPZ 反向前缀 owner 的相对部分为 (ip_network, 前缀长度)。

    地址标签自前缀长度向保留后缀方向为**低位 -> 高位**排列，短编码
    省略的是低位单元（右侧补 0）。完整形式如 ``32.3.2.0.192`` 解码为
    192.0.2.3/32；短编码如 ``24.2.0.192`` 解码为 192.0.2.0/24、
    ``8.192`` 为 192.0.0.0/8、``16.168.192`` 为 192.168.0.0/16；
    IPv6 为至多 32 个逆序 nibble，规则相同。
    """
    if wildcard or not rel:
        raise ValueError("地址触发器缺少前缀长度标签")
    plen_token, addr_labels = rel[0], rel[1:]
    if not plen_token.isdigit():
        raise ValueError(f"前缀长度标签必须是十进制非负整数: {plen_token!r}")
    plen = int(plen_token)

    has_hex = any(any(c in "abcdef" for c in lab) for lab in addr_labels)
    if has_hex:
        family = 6
    elif len(addr_labels) <= 4:
        family = 4
    elif len(addr_labels) <= 32:
        family = 6
    else:
        raise ValueError(
            f"地址标签数 {len(addr_labels)} 超出 IPv6 的 32 个 nibble"
        )

    if family == 4:
        if len(addr_labels) > 4:
            raise ValueError("IPv4 触发器至多 4 个逆序字节标签")
        octets = []
        for lab in addr_labels:
            if not lab.isdigit() or not 0 <= int(lab) <= 255:
                raise ValueError(f"IPv4 逆序字节标签非法: {lab!r}")
            octets.append(int(lab))
        # addr_labels 自左向右为低位 -> 高位；缺失的是低位（右侧补 0）
        normal = list(reversed(octets)) + [0] * (4 - len(octets))
        if plen > 32:
            raise ValueError(f"IPv4 前缀长度超出 32: {plen}")
        address = ipaddress.IPv4Address(bytes(normal))
        return ipaddress.ip_network(f"{address}/{plen}", strict=False), plen

    # IPv6：32 个 nibble，自左向右低位 -> 高位；缺失的低位右侧补 0
    if len(addr_labels) > 32:
        raise ValueError("IPv6 触发器至多 32 个逆序 nibble 标签")
    nibbles: list[int] = []
    for lab in addr_labels:
        if len(lab) != 1 or lab not in "0123456789abcdef":
            raise ValueError(
                f"IPv6 逆序 nibble 标签必须是单个十六进制字符: {lab!r}"
            )
        nibbles.append(int(lab, 16))
    normal = list(reversed(nibbles)) + [0] * (32 - len(nibbles))
    value = 0
    for nib in normal:
        value = (value << 4) | nib
    if plen > 128:
        raise ValueError(f"IPv6 前缀长度超出 128: {plen}")
    address = ipaddress.IPv6Address(value)
    return ipaddress.ip_network(f"{address}/{plen}", strict=False), plen


# ---------------------------------------------------------------------------
# 区域加载与语义校验
# ---------------------------------------------------------------------------

@dataclass
class LoadedZone:
    index: int
    origin: str
    rules: list[Rule]
    ignored: list[dict]


def _within(name: str, apex: str) -> bool:
    labels = _labels(name)
    apex_labels = _labels(apex)
    return _ends_with_labels(labels, apex_labels)


def load_policy_zone(text: str, index: int) -> LoadedZone:
    """解析并校验一个 RPZ 策略区，抽出策略规则。

    结构性记录（区顶 SOA/NS、区顶 NS 的 in-bailiwick 胶水）保留但不产生
    规则。加载期错误以 :class:`ReviewError`（422）抛出。
    """
    try:
        zone = parse_zone(text, allow_wildcard=True)
    except ZoneParseError as exc:
        raise ReviewError(
            "rpz_zone_parse_error",
            f"zones[{index}] 区域解析失败: {exc}",
            422,
            [{"index": index, "message": str(exc)}],
        ) from exc

    apex = zone.origin
    apex_ns = zone.get(apex, "NS")
    ns_targets: set[str] = set()
    if apex_ns is not None:
        ns_targets.update(apex_ns.rdata)

    rules: list[Rule] = []
    ignored: list[dict] = []
    # owner -> (rtype -> RRset)，用于冲突 RRset 检测
    by_owner: dict[str, dict[str, object]] = {}
    for (owner, rtype), rrset in zone.rrsets.items():
        by_owner.setdefault(owner, {})[rtype] = rrset

    for (owner, rtype), rrset in sorted(
        zone.rrsets.items(), key=lambda kv: kv[0]
    ):
        if rtype == "SOA":
            continue
        labels = _labels(owner)
        wildcard = bool(labels and labels[0] == "*")
        # 区顶（含通配区顶无意义名）处理
        is_at_apex = (not wildcard) and owner == apex

        if rtype == "NS":
            if is_at_apex:
                ignored.append({"owner": owner, "rtype": "NS",
                                "reason": "apex_structural"})
                continue
            # RPZ 区不解释区中 NS：区外 owner 已在下面拦截，区内 NS
            # 视为非策略数据
            if not _within(owner, apex):
                raise ReviewError(
                    "rpz_owner_out_of_zone",
                    f"zones[{index}] 存在区外 owner: {owner} 不在 {apex} 内",
                    422,
                    [{"index": index, "owner": owner, "zone": apex}],
                )
            ignored.append({"owner": owner, "rtype": "NS",
                            "reason": "non_policy"})
            continue

        if rtype in _ADDRESS_TYPES:
            if not _within(owner, apex):
                raise ReviewError(
                    "rpz_owner_out_of_zone",
                    f"zones[{index}] 存在区外 owner: {owner} 不在 {apex} 内",
                    422,
                    [{"index": index, "owner": owner, "zone": apex}],
                )
            if is_at_apex or owner in ns_targets:
                ignored.append({"owner": owner, "rtype": rtype,
                                "reason": "apex_glue"})
                continue
            # 地址记录落在策略命名空间却不是胶水：非策略数据，忽略
            ignored.append({"owner": owner, "rtype": rtype,
                            "reason": "non_policy"})
            continue

        if rtype != "CNAME":
            if not _within(owner, apex):
                raise ReviewError(
                    "rpz_owner_out_of_zone",
                    f"zones[{index}] 存在区外 owner: {owner} 不在 {apex} 内",
                    422,
                    [{"index": index, "owner": owner, "zone": apex}],
                )
            ignored.append({"owner": owner, "rtype": rtype,
                            "reason": "non_policy"})
            continue

        # CNAME 分支
        if not _within(owner, apex):
            raise ReviewError(
                "rpz_owner_out_of_zone",
                f"zones[{index}] 存在区外 owner: {owner} 不在 {apex} 内",
                422,
                [{"index": index, "owner": owner, "zone": apex}],
            )
        if is_at_apex:
            raise ReviewError(
                "rpz_apex_policy",
                f"zones[{index}] 区顶 {apex} 不允许存在策略 CNAME",
                422,
                [{"index": index, "owner": owner, "zone": apex}],
            )

        # 冲突 RRset：同一 owner 不得与非允许类型共存
        siblings = by_owner.get(owner, {})
        conflicting = sorted(t for t in siblings if t != "CNAME")
        if conflicting:
            raise ReviewError(
                "rpz_conflicting_rrset",
                f"zones[{index}] {owner} 的策略 CNAME 与其它 RRset 冲突: "
                + ", ".join(conflicting),
                422,
                [{"index": index, "owner": owner,
                  "types": sorted(siblings.keys())}],
            )
        targets = rrset.rdata
        if len(set(targets)) > 1:
            raise ReviewError(
                "rpz_conflicting_rrset",
                f"zones[{index}] {owner} 的 CNAME RRset 存在多个不同目标，"
                "策略动作不唯一",
                422,
                [{"index": index, "owner": owner,
                  "targets": sorted(set(targets))}],
            )

        trigger, rel, wild = classify_trigger(owner, apex)
        target = targets[0]
        if trigger in _IP_TRIGGERS:
            try:
                network, plen = decode_ip_prefix(rel, wild)
            except ValueError as exc:
                raise ReviewError(
                    "rpz_invalid_prefix",
                    f"zones[{index}] 触发器 {owner} 的 RPZ 反向前缀编码非法: "
                    f"{exc}",
                    422,
                    [{"index": index, "owner": owner, "trigger": trigger,
                      "message": str(exc)}],
                ) from exc
            rules.append(Rule(
                zone_index=index, zone_origin=apex, trigger=trigger,
                owner=owner, ttl=rrset.ttl, target=target, wildcard=wild,
                network=network, prefix_len=plen,
            ))
        else:
            pattern = "." if not rel else ".".join(rel) + "."
            rules.append(Rule(
                zone_index=index, zone_origin=apex, trigger=trigger,
                owner=owner, ttl=rrset.ttl, target=target, wildcard=wild,
                name_pattern=pattern,
            ))

    return LoadedZone(index=index, origin=apex, rules=rules, ignored=ignored)


# ---------------------------------------------------------------------------
# 查询结果解析
# ---------------------------------------------------------------------------

def _normalize_name(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ReviewError("invalid_request", f"{field} 必须是非空字符串", 400)
    name = value.strip().lower()
    if name != "." and not name.endswith("."):
        name += "."
    try:
        validate_name(name, allow_wildcard=True)
    except ZoneParseError as exc:
        raise ReviewError(
            "invalid_request", f"{field} 非法域名 {value!r}: {exc}", 400
        ) from exc
    return name


def _normalize_addr(value: str, field: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip())).lower()
    except (ValueError, AttributeError) as exc:
        raise ReviewError(
            "invalid_request", f"{field} 非法 IP 地址 {value!r}: {exc}", 400
        ) from exc


def _normalize_section(value, field: str) -> list[dict]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ReviewError(
            "invalid_request", f"{field} 必须是记录数组", 400
        )
    records = []
    for pos, item in enumerate(value):
        if not isinstance(item, dict):
            raise ReviewError(
                "invalid_request", f"{field}[{pos}] 必须是记录对象", 400
            )
        name = _normalize_name(item.get("name"), f"{field}[{pos}].name")
        rtype = item.get("type")
        if not isinstance(rtype, str) or not rtype.strip():
            raise ReviewError(
                "invalid_request", f"{field}[{pos}].type 必须是非空字符串", 400
            )
        rtype = rtype.strip().upper()
        rdata = item.get("rdata")
        if not isinstance(rdata, str) or not rdata.strip():
            raise ReviewError(
                "invalid_request",
                f"{field}[{pos}].rdata 必须是非空字符串",
                400,
            )
        if rtype in _ADDRESS_TYPES:
            norm_rdata = _normalize_addr(
                rdata, f"{field}[{pos}].rdata"
            )
        elif rtype in ("NS", "CNAME", "DNAME"):
            norm_rdata = _normalize_name(
                rdata, f"{field}[{pos}].rdata"
            )
        else:
            norm_rdata = rdata.strip()
        records.append({"name": name, "type": rtype, "rdata": norm_rdata})
    return records


def parse_query(payload: dict) -> dict:
    query = payload.get("query")
    if not isinstance(query, dict):
        raise ReviewError(
            "invalid_request", "query 必须是描述一条 DNS 查询结果的对象", 400
        )
    qname = _normalize_name(query.get("qname"), "query.qname")
    qtype = query.get("qtype", "A")
    if not isinstance(qtype, str) or not qtype.strip().isalnum():
        raise ReviewError(
            "invalid_request",
            f"query.qtype 必须是类型名字符串: {qtype!r}",
            400,
        )
    qtype = qtype.strip().upper()
    protocol = str(query.get("protocol", "udp")).strip().lower()
    if protocol not in ("udp", "tcp"):
        raise ReviewError(
            "invalid_request",
            f"query.protocol 必须是 udp/tcp: {protocol!r}",
            400,
        )
    sections = {
        name: _normalize_section(query.get(name), f"query.{name}")
        for name in _SECTIONS
    }
    return {"qname": qname, "qtype": qtype, "protocol": protocol,
            **sections}


# ---------------------------------------------------------------------------
# 匹配
# ---------------------------------------------------------------------------

def _match_name_rule(qname_labels: list[str], rule: Rule) -> bool:
    pattern = _labels(rule.name_pattern)
    if rule.wildcard:
        # 通配恰好匹配一个标签 + pattern 后缀
        if not pattern:
            return len(qname_labels) == 1
        return (
            len(qname_labels) == len(pattern) + 1
            and qname_labels[-len(pattern):] == pattern
        )
    return qname_labels == pattern


def _name_candidates(
    rules: list[Rule], trigger: str, names: list[str]
) -> list[tuple[Rule, str]]:
    """在指定名称触发器的规则中，为一组待匹配名找出全部命中 (rule, name)。"""
    hits: list[tuple[Rule, str]] = []
    pool = [r for r in rules if r.trigger == trigger]
    for name in names:
        labels = _labels(name)
        for rule in pool:
            if _match_name_rule(labels, rule):
                hits.append((rule, name))
    return hits


def _ip_candidates(
    rules: list[Rule], trigger: str, addresses: list[str]
) -> list[tuple[Rule, str]]:
    """在指定地址触发器的规则中，为一组地址找出全部命中 (rule, address)。"""
    hits: list[tuple[Rule, str]] = []
    pool = [r for r in rules if r.trigger == trigger]
    for value in addresses:
        addr = ipaddress.ip_address(value)
        for rule in pool:
            if addr.version != rule.network.version:
                continue
            if addr in rule.network:
                hits.append((rule, value))
    return hits


def _best_name_hit(
    hits: list[tuple[Rule, str]]
) -> tuple[Rule, str] | None:
    """同区同触发器内取唯一最长匹配；等长时精确优先，再按 owner 定序。"""
    if not hits:
        return None

    def rank(item):
        rule, _ = item
        return (
            len(_labels(rule.name_pattern)),
            0 if rule.wildcard else 1,
            tuple(reversed(_labels(rule.owner))),
        )

    return max(hits, key=rank)


def _best_ip_hit(
    hits: list[tuple[Rule, str]]
) -> tuple[Rule, str] | None:
    """同区同触发器内取最长前缀；并列按 owner 取确定性次序。"""
    if not hits:
        return None

    def rank(item):
        rule, _ = item
        return (
            rule.prefix_len,
            tuple(reversed(_labels(rule.owner))),
        )

    return max(hits, key=rank)


# ---------------------------------------------------------------------------
# 求值编排
# ---------------------------------------------------------------------------

def _response_facts(q: dict) -> dict:
    """从查询结果中提取各触发器所需的事实集合（确定性排序）。"""
    answer_ips: set[str] = set()
    ns_names: set[str] = set()
    for rec in q["answer"]:
        if rec["type"] in _ADDRESS_TYPES:
            answer_ips.add(rec["rdata"])
        elif rec["type"] == "NS":
            ns_names.add(rec["rdata"])
    for rec in q["authority"]:
        if rec["type"] == "NS":
            ns_names.add(rec["rdata"])
    # NSIP：属于任一 NS 目标名的胶水 A/AAAA（additional/authority）
    ns_ips: set[str] = set()
    for section in ("additional", "authority"):
        for rec in q[section]:
            if rec["type"] in _ADDRESS_TYPES and rec["name"] in ns_names:
                ns_ips.add(rec["rdata"])
    return {
        "answer_ips": sorted(answer_ips),
        "ns_names": sorted(ns_names),
        "ns_ips": sorted(ns_ips),
    }


def _candidate_json(
    rule: Rule, matched_value: str, protocol: str
) -> dict:
    # rpz-tcp-only 仅对 UDP 生效（回截断响应促使改用 TCP）；TCP 查询
    # 下该规则视为不存在
    eligible = True
    skip_reason = None
    if rule.action == "tcp-only" and protocol == "tcp":
        eligible = False
        skip_reason = "tcp_only_ignored_on_tcp"
    data = rule.to_dict()
    data.update({
        "matched": matched_value,
        "eligible": eligible,
        "skip_reason": skip_reason,
    })
    return data


def evaluate_rpz(payload: dict) -> dict:
    """执行一次离线 RPZ 求值，返回可直接序列化的结果。"""
    if not isinstance(payload, dict):
        raise ReviewError("invalid_request", "请求体必须是 JSON 对象", 400)

    zones_text = payload.get("zones")
    if not isinstance(zones_text, list) or not zones_text:
        raise ReviewError(
            "invalid_request", "zones 必须是非空的 RPZ 区域文本字符串数组", 400
        )

    loaded: list[LoadedZone] = []
    seen_origins: set[str] = set()
    for position, text in enumerate(zones_text):
        if not isinstance(text, str) or not text.strip():
            raise ReviewError(
                "invalid_request",
                f"zones[{position}] 必须是非空区域文本字符串",
                400,
            )
        lz = load_policy_zone(text, position)
        if lz.origin in seen_origins:
            raise ReviewError(
                "invalid_request",
                f"zones 中策略区源点 {lz.origin} 出现多次",
                400,
            )
        seen_origins.add(lz.origin)
        loaded.append(lz)

    q = parse_query(payload)
    facts = _response_facts(q)

    trace: list[dict] = []
    all_candidates: list[dict] = []
    winner: tuple[Rule, str] | None = None
    winner_trigger: str | None = None

    for lz in loaded:
        zone_event = {
            "type": "zone",
            "zone_index": lz.index,
            "zone_origin": lz.origin,
            "rule_count": len(lz.rules),
        }
        if winner is not None:
            zone_event["evaluated"] = False
            zone_event["reason"] = "previous_zone_terminated"
            trace.append(zone_event)
            continue
        trace.append(zone_event)

        zone_winner: tuple[Rule, str] | None = None
        for trigger in TRIGGER_ORDER:
            if trigger == "qname":
                hits = _name_candidates(lz.rules, "qname", [q["qname"]])
            elif trigger == "response-ip":
                hits = _ip_candidates(lz.rules, "response-ip",
                                      facts["answer_ips"])
            elif trigger == "nsdname":
                hits = _name_candidates(lz.rules, "nsdname",
                                        facts["ns_names"])
            else:  # nsip
                hits = _ip_candidates(lz.rules, "nsip", facts["ns_ips"])

            best = (
                _best_name_hit(hits)
                if trigger not in _IP_TRIGGERS
                else _best_ip_hit(hits)
            )
            cand_event = {
                "type": "trigger",
                "zone_index": lz.index,
                "trigger": trigger,
                "matches": [
                    _candidate_json(rule, value, q["protocol"])
                    for rule, value in sorted(
                        hits,
                        key=lambda hv: (
                            hv[0].prefix_len
                            if trigger in _IP_TRIGGERS
                            else len(_labels(hv[0].name_pattern)),
                            tuple(reversed(_labels(hv[0].owner))),
                            hv[1],
                        ),
                        reverse=False,
                    )
                ],
            }
            if best is not None:
                chosen_rule, chosen_value = best
                cand_event["best"] = chosen_rule.owner
                eligible = not (
                    chosen_rule.action == "tcp-only"
                    and q["protocol"] == "tcp"
                )
                cand_event["eligible"] = eligible
            trace.append(cand_event)
            all_candidates.extend(cand_event["matches"])

            if best is None:
                continue
            chosen_rule, chosen_value = best
            if chosen_rule.action == "tcp-only" and q["protocol"] == "tcp":
                # TCP 查询下 rpz-tcp-only 不生效：本触发器不产出策略，
                # 继续本区内下一触发器
                continue
            zone_winner = best
            winner_trigger = trigger
            break

        if zone_winner is None:
            continue

        rule, matched_value = zone_winner
        winner = zone_winner
        trace.append({
            "type": "selected",
            "zone_index": lz.index,
            "trigger": winner_trigger,
            "owner": rule.owner,
            "action": rule.action,
            "matched": matched_value,
            "terminates": True,
            "passthru": rule.action == "passthru",
        })

    zones_out = [
        {
            "index": lz.index,
            "origin": lz.origin,
            "rule_count": len(lz.rules),
            "ignored": lz.ignored,
        }
        for lz in loaded
    ]

    if winner is None:
        trace.append({"type": "result", "disposition": "unchanged"})
        return {
            "disposition": "unchanged",
            "action": None,
            "matched_rule": None,
            "candidates": _dedupe_candidates(all_candidates),
            "selection_reason": "no_policy_rule_matched",
            "query": q,
            "facts": facts,
            "zones": zones_out,
            "trace": trace,
        }

    rule, matched_value = winner
    disposition, detail = _apply_action(rule, q)
    trace.append({"type": "result", "disposition": disposition,
                  "action": rule.action})
    selection_reason = (
        f"zone_index={rule.zone_index} 为含命中规则的最小序号策略区；"
        f"区内触发器 {winner_trigger} 在固定优先级"
        f"(qname<response-ip<nsdname<nsip) 中最先命中，且其"
        + (
            f"前缀长度 /{rule.prefix_len} 为该触发器最长匹配"
            if winner_trigger in _IP_TRIGGERS
            else "匹配名称为该触发器最长匹配"
        )
    )
    result = {
        "disposition": disposition,
        "action": rule.action,
        "matched_rule": rule.to_dict(),
        "matched_value": matched_value,
        "trigger": winner_trigger,
        "candidates": _dedupe_candidates(all_candidates),
        "selection_reason": selection_reason,
        "query": q,
        "facts": facts,
        "zones": zones_out,
        "trace": trace,
    }
    result.update(detail)
    return result


def _dedupe_candidates(candidates: list[dict]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for cand in candidates:
        key = (cand["zone_index"], cand["owner"], cand["matched"])
        if key not in seen:
            seen[key] = cand
    return sorted(
        seen.values(),
        key=lambda c: (
            c["zone_index"],
            TRIGGER_ORDER.index(c["trigger"]),
            c["owner"],
            c["matched"],
        ),
    )


def _apply_action(rule: Rule, q: dict) -> tuple[str, dict]:
    """把命中规则翻译为对外处置。返回 (disposition, 附加字段)。"""
    action = rule.action
    if action == "nxdomain":
        return "nxdomain", {"rcode": "NXDOMAIN"}
    if action == "nodata":
        return "nodata", {"rcode": "NOERROR", "answer": []}
    if action == "passthru":
        return "passthru", {"passthru": True}
    if action == "drop":
        return "drop", {"dropped": True}
    if action == "tcp-only":
        return "tcp-only", {
            "tcp_only": True,
            "protocol_required": "tcp",
        }
    return "rewrite", {
        "rewrite": {
            "qname": q["qname"],
            "qtype": q["qtype"],
            "cname_target": rule.target,
        }
    }
