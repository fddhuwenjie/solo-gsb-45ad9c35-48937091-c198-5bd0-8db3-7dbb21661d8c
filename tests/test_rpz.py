"""离线 RPZ 求值（app.rpz）单元测试。"""

import copy
import unittest

from app.review import ReviewError
from app.rpz import (
    decode_ip_prefix,
    evaluate_rpz,
    load_policy_zone,
)
import ipaddress


def zone(body: str, origin: str = "rpz.example.") -> str:
    head = (
        f"$ORIGIN {origin}\n$TTL 300\n"
        "@ IN SOA ns1 admin 1 1h 1h 1w 1h\n@ IN NS ns1\n"
        "ns1 IN A 192.0.2.1\n"
    )
    return head + body


def query(**over):
    q = {
        "qname": "www.example.com",
        "qtype": "A",
        "protocol": "udp",
        "answer": [],
        "authority": [],
        "additional": [],
    }
    q.update(over)
    return {"zones": None, "query": q}


def run(body: str, q_over=None, zones=None, origin="rpz.example."):
    payload = query(**(q_over or {}))
    payload["zones"] = zones if zones is not None else [zone(body, origin)]
    return evaluate_rpz(payload)


def expect422(testcase, body, code, origin="rpz.example."):
    payload = query()
    payload["zones"] = [zone(body, origin)]
    with testcase.assertRaises(ReviewError) as cm:
        evaluate_rpz(payload)
    testcase.assertEqual(cm.exception.status, 422)
    testcase.assertEqual(cm.exception.code, code)
    return cm.exception


class IpPrefixDecodeTests(unittest.TestCase):
    def test_ipv4_full_and_short(self):
        net, plen = decode_ip_prefix(["32", "8", "2", "0", "192"], False)
        self.assertEqual(str(net), "192.0.2.8/32")
        self.assertEqual(plen, 32)
        # 短编码：自左向右低位 -> 高位；192.0.2.0/24 写为 24.2.0.192
        net, plen = decode_ip_prefix(["24", "2", "0", "192"], False)
        self.assertEqual(str(net), "192.0.2.0/24")
        net, _ = decode_ip_prefix(["8", "192"], False)
        self.assertEqual(str(net), "192.0.0.0/8")
        net, _ = decode_ip_prefix(["16", "168", "192"], False)
        self.assertEqual(str(net), "192.168.0.0/16")
        net, plen = decode_ip_prefix(["0"], False)
        self.assertEqual(str(net), "0.0.0.0/0")
        self.assertEqual(plen, 0)

    def test_ipv6_full_and_short(self):
        # 2001:db8::/32：自左向右低位 -> 高位的逆序 nibble
        rel = ["32", "8", "b", "d", "0", "1", "0", "0", "2"]
        net, plen = decode_ip_prefix(rel, False)
        self.assertEqual(str(net), "2001:db8::/32")
        self.assertEqual(plen, 32)
        # /128 完整逆序
        addr = "2001:db8::1"
        packed = ipaddress.IPv6Address(addr).packed
        nibs = []
        for byte in packed:
            nibs.extend((byte >> 4, byte & 0xF))
        rel128 = ["128"] + [format(n, "x") for n in reversed(nibs)]
        net, plen = decode_ip_prefix(rel128, False)
        self.assertEqual(str(net), "2001:db8::1/128")
        self.assertEqual(plen, 128)

    def test_invalid_prefix(self):
        for rel in (
            ["33", "1"],                    # 前缀超 32（v4）
            ["129"],                        # 前缀超 128
            ["xx", "1"],                    # 非数字前缀
            ["32", "999", "0", "0", "10"],  # 非法字节
            ["8", "zz"],                    # 非法标签
        ):
            with self.assertRaises(ValueError):
                decode_ip_prefix(rel, False)
        # 通配不允许出现在地址触发器
        with self.assertRaises(ValueError):
            decode_ip_prefix(["32", "1"], True)


class ActionTests(unittest.TestCase):
    def test_nxdomain_action(self):
        r = run("www.example.com CNAME .\n")
        self.assertEqual(r["disposition"], "nxdomain")
        self.assertEqual(r["action"], "nxdomain")
        self.assertEqual(r["matched_rule"]["target"], ".")
        self.assertEqual(r["rcode"], "NXDOMAIN")

    def test_nodata_action(self):
        r = run("www.example.com CNAME *.\n")
        self.assertEqual(r["disposition"], "nodata")
        self.assertEqual(r["action"], "nodata")
        self.assertEqual(r["answer"], [])

    def test_drop_action(self):
        r = run("www.example.com CNAME rpz-drop.\n")
        self.assertEqual(r["disposition"], "drop")
        self.assertTrue(r["dropped"])

    def test_passthru_action_terminates_later_zones(self):
        z0 = zone("www.example.com CNAME rpz-passthru.\n", "a.example.")
        z1 = zone("www.example.com CNAME .\n", "b.example.")
        r = run(None, zones=[z0, z1])
        self.assertEqual(r["disposition"], "passthru")
        self.assertTrue(r["matched_rule"]["zone_index"] == 0)
        later = [e for e in r["trace"]
                 if e["type"] == "zone" and e.get("zone_index") == 1]
        self.assertEqual(later[0]["evaluated"], False)

    def test_rewrite_action(self):
        r = run("www.example.com CNAME cdn.example.net.\n")
        self.assertEqual(r["disposition"], "rewrite")
        self.assertEqual(r["rewrite"]["cname_target"], "cdn.example.net.")
        self.assertEqual(r["rewrite"]["qname"], "www.example.com.")

    def test_tcp_only_fires_udp_skipped_tcp(self):
        body = "www.example.com CNAME rpz-tcp-only.\n"
        r = run(body)
        self.assertEqual(r["disposition"], "tcp-only")
        self.assertEqual(r["protocol_required"], "tcp")
        r = run(body, {"protocol": "tcp"})
        self.assertEqual(r["disposition"], "unchanged")


class TriggerTests(unittest.TestCase):
    def test_qname_exact_and_wildcard(self):
        body = ("www.example.com CNAME .\n"
                "*.example.com CNAME rpz-drop.\n")
        # 精确命中
        r = run(body)
        self.assertEqual(r["matched_rule"]["trigger"], "qname")
        self.assertEqual(r["matched_rule"]["match"], "exact")
        # 通配恰好匹配一个标签
        r = run(body, {"qname": "mail.example.com"})
        self.assertEqual(r["disposition"], "drop")
        self.assertEqual(r["matched_rule"]["match"], "wildcard")
        # 通配不匹配多级子域
        r = run(body, {"qname": "a.b.example.com"})
        self.assertEqual(r["disposition"], "unchanged")

    def test_response_ip_longest_prefix(self):
        # 192.0.0.0/16（短编码）与 192.0.2.0/24，后者更长
        body = ("16.0.192.rpz-response-ip CNAME a.example.\n"
                "24.2.0.192.rpz-response-ip CNAME b.example.\n")
        ans = [{"name": "h", "type": "A", "rdata": "192.0.2.77"}]
        r = run(body, {"answer": ans, "qname": "n.example.org"})
        self.assertEqual(r["matched_rule"]["trigger"], "response-ip")
        self.assertEqual(r["matched_rule"]["prefix_len"], 24)
        self.assertEqual(r["matched_value"], "192.0.2.77")
        # 只落在 /16 时取 /16
        ans = [{"name": "h", "type": "A", "rdata": "192.0.9.9"}]
        r = run(body, {"answer": ans, "qname": "n.example.org"})
        self.assertEqual(r["matched_rule"]["prefix_len"], 16)

    def test_response_ip_ipv6(self):
        body = "32.8.b.d.0.1.0.0.2.rpz-response-ip CNAME .\n"
        ans = [{"name": "h", "type": "AAAA",
                "rdata": "2001:db8:1234::1"}]
        r = run(body, {"answer": ans, "qname": "n.example.org"})
        self.assertEqual(r["disposition"], "nxdomain")
        self.assertEqual(r["matched_rule"]["trigger"], "response-ip")

    def test_nsdname_match(self):
        body = ("ns.evil.example.rpz-nsdname CNAME rpz-drop.\n"
                "*.deleg.example.rpz-nsdname CNAME *.\n")
        auth = [{"name": "example.org", "type": "NS",
                 "rdata": "ns.evil.example"}]
        r = run(body, {"qname": "x.test", "authority": auth})
        self.assertEqual(r["matched_rule"]["trigger"], "nsdname")
        self.assertEqual(r["disposition"], "drop")
        # 通配 NS 名（恰好一个标签）
        auth = [{"name": "example.org", "type": "NS",
                 "rdata": "ns1.deleg.example"}]
        r = run(body, {"qname": "x.test", "authority": auth})
        self.assertEqual(r["disposition"], "nodata")
        # 多级不匹配通配
        auth = [{"name": "example.org", "type": "NS",
                 "rdata": "a.ns1.deleg.example"}]
        r = run(body, {"qname": "x.test", "authority": auth})
        self.assertEqual(r["disposition"], "unchanged")

    def test_nsip_uses_glue_for_authority_ns(self):
        body = "24.2.0.192.rpz-nsip CNAME .\n"
        qover = {
            "qname": "x.test",
            "authority": [{"name": "t", "type": "NS",
                           "rdata": "ns.g.example"}],
            "additional": [{"name": "ns.g.example", "type": "A",
                            "rdata": "192.0.2.5"}],
        }
        r = run(body, qover)
        self.assertEqual(r["matched_rule"]["trigger"], "nsip")
        self.assertEqual(r["disposition"], "nxdomain")

        # additional 中不属于 NS 目标的地址不触发 nsip
        qover["additional"] = [{"name": "other.example", "type": "A",
                                "rdata": "192.0.2.5"}]
        r = run(body, qover)
        self.assertEqual(r["disposition"], "unchanged")

    def test_trigger_order_within_zone(self):
        # 同时构造四类命中；QNAME 必须胜出
        body = (
            "www.example.com CNAME .\n"
            "32.8.2.0.192.rpz-response-ip CNAME a.\n"
            "ns.g.example.rpz-nsdname CNAME b.\n"
            "24.2.0.192.rpz-nsip CNAME c.\n"
        )
        qover = {
            "answer": [{"name": "h", "type": "A", "rdata": "192.0.2.8"}],
            "authority": [{"name": "t", "type": "NS",
                           "rdata": "ns.g.example"}],
            "additional": [{"name": "ns.g.example", "type": "A",
                            "rdata": "192.0.2.8"}],
        }
        r = run(body, qover)
        self.assertEqual(r["trigger"], "qname")
        # 去掉 QNAME：response-ip 优先
        body2 = body.replace("www.example.com CNAME .\n", "")
        r = run(body2, qover)
        self.assertEqual(r["trigger"], "response-ip")
        # 再去掉 response-ip：nsdname 优先
        body3 = body2.replace("32.8.2.0.192.rpz-response-ip CNAME a.\n", "")
        r = run(body3, qover)
        self.assertEqual(r["trigger"], "nsdname")
        # 只剩 nsip
        body4 = body3.replace("ns.g.example.rpz-nsdname CNAME b.\n", "")
        r = run(body4, qover)
        self.assertEqual(r["trigger"], "nsip")

    def test_only_a_aaaa_in_answer_count_for_response_ip(self):
        body = "32.8.2.0.192.rpz-response-ip CNAME .\n"
        # CNAME RDATA 不是地址，不应触发
        ans = [{"name": "h", "type": "CNAME", "rdata": "192.0.2.8"}]
        r = run(body, {"answer": ans, "qname": "n.test"})
        self.assertEqual(r["disposition"], "unchanged")


class ZoneOrderAndSelectionTests(unittest.TestCase):
    def test_lowest_zone_index_selected(self):
        z0 = zone("www.example.com CNAME rpz-drop.\n", "z0.example.")
        z1 = zone("www.example.com CNAME .\n", "z1.example.")
        r = run(None, zones=[z0, z1])
        self.assertEqual(r["disposition"], "drop")
        self.assertEqual(r["matched_rule"]["zone_index"], 0)
        # 反过来顺序：z1 在前，结论随之改变
        r = run(None, zones=[z1, z0])
        self.assertEqual(r["disposition"], "nxdomain")
        self.assertEqual(r["matched_rule"]["zone_index"], 0)

    def test_later_zone_used_when_earlier_has_no_match(self):
        z0 = zone("other.example.com CNAME .\n", "z0.example.")
        z1 = zone("www.example.com CNAME rpz-drop.\n", "z1.example.")
        r = run(None, zones=[z0, z1])
        self.assertEqual(r["disposition"], "drop")
        self.assertEqual(r["matched_rule"]["zone_index"], 1)

    def test_unchanged_has_candidates_and_reason(self):
        # 其它触发器有候选但不针对本查询，candidates 仅含实际命中项
        body = "other.example.com CNAME .\n"
        r = run(body)
        self.assertEqual(r["disposition"], "unchanged")
        self.assertIsNone(r["matched_rule"])
        self.assertEqual(r["selection_reason"], "no_policy_rule_matched")
        self.assertEqual(r["candidates"], [])

    def test_candidates_listed_when_multiple_match(self):
        body = ("16.0.192.rpz-response-ip CNAME a.\n"
                "24.2.0.192.rpz-response-ip CNAME b.\n")
        ans = [{"name": "h", "type": "A", "rdata": "192.0.2.7"}]
        r = run(body, {"answer": ans, "qname": "n.test"})
        owners = sorted(c["owner"] for c in r["candidates"])
        self.assertEqual(len(owners), 2)
        # 选中最长
        self.assertEqual(r["matched_rule"]["prefix_len"], 24)


class ReorderStabilityTests(unittest.TestCase):
    def test_record_reorder_does_not_change_result(self):
        body = (
            "www.example.com CNAME .\n"
            "*.example.com CNAME rpz-drop.\n"
            "32.2.0.192.1.rpz-response-ip CNAME block.net.\n"
            "ns.evil.example.rpz-nsdname CNAME *.\n"
            "24.2.0.192.rpz-nsip CNAME rpz-tcp-only.\n"
        )
        lines = [ln + "\n" for ln in body.strip().splitlines()]
        import itertools
        qover = {
            "qname": "www.example.com",
            "answer": [{"name": "h", "type": "A", "rdata": "1.192.0.2"}],
            "authority": [{"name": "t", "type": "NS",
                           "rdata": "ns.evil.example"}],
            "additional": [{"name": "ns.evil.example", "type": "A",
                            "rdata": "192.0.2.9"}],
        }
        baseline = run(body, qover)
        for perm in itertools.islice(itertools.permutations(lines), 20):
            r = run("".join(perm), qover)
            self.assertEqual(r["disposition"], baseline["disposition"])
            self.assertEqual(
                r["matched_rule"]["owner"],
                baseline["matched_rule"]["owner"],
            )


class ZoneLoadErrorTests(unittest.TestCase):
    def test_invalid_prefix(self):
        expect422(self, "33.1.2.3.4.rpz-response-ip CNAME .\n",
                  "rpz_invalid_prefix")
        expect422(self, "xx.1.rpz-nsip CNAME .\n", "rpz_invalid_prefix")
        expect422(self, "32.300.0.0.10.rpz-response-ip CNAME .\n",
                  "rpz_invalid_prefix")
        expect422(self, "129.0.0.0.0.0.0.0.0.0.rpz-nsip CNAME .\n",
                  "rpz_invalid_prefix")
        expect422(self, "*.8.192.rpz-response-ip CNAME .\n",
                  "rpz_invalid_prefix")

    def test_out_of_zone_owner(self):
        text = zone("")
        text += "evil.other.net. CNAME .\n"
        payload = query()
        payload["zones"] = [text]
        with self.assertRaises(ReviewError) as cm:
            evaluate_rpz(payload)
        self.assertEqual(cm.exception.code, "rpz_owner_out_of_zone")

    def test_apex_policy_cname(self):
        expect422(self, "@ CNAME .\n", "rpz_apex_policy")

    def test_conflicting_rrset(self):
        expect422(self,
                  "foo.example CNAME .\nfoo.example A 1.2.3.4\n",
                  "rpz_conflicting_rrset")
        expect422(self,
                  "foo.example CNAME a.\nfoo.example CNAME b.\n",
                  "rpz_conflicting_rrset")

    def test_zone_parse_error_422(self):
        expect422(self, 'bad CNAME unclosed"\n', "rpz_zone_parse_error")

    def test_non_policy_data_ignored(self):
        # 区顶 NS / 其 in-bailiwick 胶水与普通 A 不产生规则也不报错
        body = "host.example A 1.2.3.4\n"
        lz = load_policy_zone(zone(body), 0)
        self.assertEqual(lz.rules, [])
        self.assertTrue(any(i["reason"] == "non_policy"
                            for i in lz.ignored))


class RequestValidationTests(unittest.TestCase):
    def test_bad_request(self):
        with self.assertRaises(ReviewError) as cm:
            evaluate_rpz({"zones": [], "query": {"qname": "a."}})
        self.assertEqual(cm.exception.status, 400)

        payload = query()
        payload["zones"] = [zone("www.example.com CNAME .\n")]
        payload["query"]["qname"] = ""
        with self.assertRaises(ReviewError):
            evaluate_rpz(payload)

        payload = query()
        payload["zones"] = [zone("www.example.com CNAME .\n")]
        payload["query"]["answer"] = [{"name": "h", "type": "A",
                                       "rdata": "not-an-ip"}]
        with self.assertRaises(ReviewError) as cm:
            evaluate_rpz(payload)
        self.assertEqual(cm.exception.status, 400)

    def test_duplicate_zone_origin_400(self):
        payload = query()
        payload["zones"] = [zone(""), zone("x CNAME .\n")]
        with self.assertRaises(ReviewError) as cm:
            evaluate_rpz(payload)
        self.assertEqual(cm.exception.status, 400)


class DeterminismTests(unittest.TestCase):
    def test_same_input_same_output(self):
        body = ("24.2.0.192.rpz-nsip CNAME .\n"
                "www.example.com CNAME .\n")
        qover = {
            "authority": [{"name": "t", "type": "NS",
                           "rdata": "ns.g.example"}],
            "additional": [{"name": "ns.g.example", "type": "A",
                            "rdata": "192.0.2.9"}],
        }
        import json
        a = json.dumps(run(body, qover), sort_keys=True)
        b = json.dumps(run(body, qover), sort_keys=True)
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
