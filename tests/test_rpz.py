"""离线 RPZ 求值单元测试（直接调用 evaluate_rpz，不起 HTTP）。"""

import ipaddress
import json
import unittest

from app.review import ReviewError
from app.rpz import _decode_ip_prefix, evaluate_rpz

HEADER = (
    "$ORIGIN example.com.\n$TTL 300\n"
    "@ IN SOA ns1.example.com. admin.example.com. 1 1h 1h 1w 1h\n"
    "@ IN NS ns1.example.com.\nns1 IN A 192.0.2.1\n"
)

ZONE = (
    HEADER
    + "evil CNAME .\n"
    + "*.wild CNAME *.\n"
    + "good CNAME rpz-passthru.\n"
    + "drop CNAME rpz-drop.\n"
    + "tcp CNAME rpz-tcp-only.\n"
    + "www CNAME target.example.net.\n"
    # 192.0.2.2/32 与 192.168.0.0/24
    + "32.2.2.0.192.rpz-ip CNAME blocked-host.example.net.\n"
    + "24.0.168.192.rpz-ip CNAME blocked-net.example.net.\n"
    # NS 名位于 ns.evil.example.com. 之下即命中
    + "ns.evil.rpz-nsdname CNAME .\n"
    + "*.ns-cn.rpz-nsdname CNAME .\n"
    # 名称服务器地址 203.0.2.99/32
    + "32.99.2.0.203.rpz-nsip CNAME .\n"
)

# 序号更大的第二个策略区：good 在 zone1 是 passthru，这里改成 nxdomain
ZONE2 = (
    "$ORIGIN block.example.\n$TTL 300\n"
    "@ IN SOA ns1.example.com. admin.example.com. 1 1h 1h 1w 1h\n"
    "@ IN NS ns1.example.com.\n"
    "good.example.com CNAME .\n"
)


def eval_rpz(qname, response=None, zones=(ZONE, ZONE2), qtype="A"):
    payload = {"zones": list(zones), "qname": qname, "qtype": qtype}
    if response is not None:
        payload["response"] = response
    return evaluate_rpz(payload)


def a_response(address, name="host.example."):
    return {"answer": [{"name": name, "type": "A", "ttl": 60,
                        "rdata": address}]}


def ns_response(ns_name, glue=None):
    authority = [{"name": "q.example.", "type": "NS", "ttl": 60,
                  "rdata": ns_name}]
    additional = []
    if glue is not None:
        additional.append({"name": ns_name, "type": "A", "ttl": 60,
                           "rdata": glue})
    return {"answer": [], "authority": authority, "additional": additional}


class PrefixDecodeTests(unittest.TestCase):
    def test_ipv4_prefixes(self):
        net, length = _decode_ip_prefix("0")
        self.assertEqual((str(net), length), ("0.0.0.0/0", 0))
        net, length = _decode_ip_prefix("24.0.168.192")
        self.assertEqual((str(net), length), ("192.168.0.0/24", 24))
        net, length = _decode_ip_prefix("32.2.2.0.192")
        self.assertEqual((str(net), length), ("192.0.2.2/32", 32))

    def test_ipv6_prefix(self):
        # 2001:db8::/64 反向半字节：64 后面 16 个 nibble
        net, length = _decode_ip_prefix(
            "64.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2")
        self.assertEqual(str(net), "2001:db8::/64")
        self.assertEqual(length, 64)
        self.assertIn(ipaddress.IPv6Address("2001:db8::abcd"), net)
        self.assertNotIn(ipaddress.IPv6Address("2001:db9::1"), net)

    def test_bad_label_count(self):
        # /24 必须恰好 3 个字节标签
        with self.assertRaises(ValueError):
            _decode_ip_prefix("24.168.192")
        # /32 必须恰好 4 个字节标签
        with self.assertRaises(ValueError):
            _decode_ip_prefix("32.0.2.192")

    def test_bad_host_bits(self):
        # 192.0.2.0/24 的主机位非零（字节标签是 2.2.0.192）
        with self.assertRaises(ValueError):
            _decode_ip_prefix("24.2.2.0.192")

    def test_bad_values(self):
        with self.assertRaises(ValueError):
            _decode_ip_prefix("32.256.0.2.192")  # 字节超出 255
        with self.assertRaises(ValueError):
            _decode_ip_prefix("40.0.0.0.0")  # IPv4 长度超出 32
        with self.assertRaises(ValueError):
            _decode_ip_prefix("16.0.168.192.10")  # 5 标签但前缀太短
        with self.assertRaises(ValueError):
            _decode_ip_prefix("64.z.0.0.0.0.0.0.8.b.d.0.1.0.0.2")


class QnameTriggerTests(unittest.TestCase):
    def test_special_actions(self):
        self.assertEqual(eval_rpz("evil.example.com.")["result"],
                         "nxdomain")
        self.assertEqual(eval_rpz("drop.example.com.")["result"], "drop")
        self.assertEqual(eval_rpz("tcp.example.com.")["result"], "tcp-only")
        nodata = eval_rpz("host.wild.example.com.")
        self.assertEqual(nodata["result"], "nodata")

    def test_wildcard_single_label_only(self):
        # *.wild 只匹配恰好一个标签
        self.assertEqual(
            eval_rpz("x.wild.example.com.")["result"], "nodata")
        self.assertEqual(
            eval_rpz("a.b.wild.example.com.")["result"], "unchanged")
        # 通配不匹配触发名自身
        self.assertEqual(
            eval_rpz("wild.example.com.")["result"], "unchanged")

    def test_rewrite_target(self):
        result = eval_rpz("www.example.com.")
        self.assertEqual(result["result"], "rewrite")
        self.assertEqual(result["rewrite_target"], "target.example.net.")

    def test_relative_qname_is_qualified(self):
        result = eval_rpz("evil.example.com")  # 无根点也补全
        self.assertEqual(result["result"], "nxdomain")


class PassthruTests(unittest.TestCase):
    def test_passthru_stops_later_zones(self):
        result = eval_rpz("good.example.com.")
        self.assertEqual(result["result"], "passthru")
        # zone2 中 good -> NXDOMAIN，但不应被求值
        self.assertEqual(len(result["trace"]), 1)
        self.assertEqual(
            result["selection_reason"],
            "passthru_terminates_further_policy_zones")

    def test_later_zone_used_when_earlier_has_no_match(self):
        # zone1 不含 only.block.example.，zone2 也没有 -> unchanged；
        # 再验证 zone2 的规则确实能独立命中
        z2_only = (
            "$ORIGIN block.example.\n$TTL 300\n"
            "@ IN SOA ns1 h 1 1 1 1 1\n@ IN NS ns1\n"
            "name CNAME .\n"
        )
        result = eval_rpz("name.block.example.", zones=(HEADER, z2_only))
        self.assertEqual(result["matched_rule"]["zone_index"], 1)
        self.assertEqual(result["result"], "nxdomain")


class AddressTriggerTests(unittest.TestCase):
    def test_response_ip_exact_prefix(self):
        result = eval_rpz("host.example.", a_response("192.0.2.2"))
        self.assertEqual(result["matched_rule"]["trigger"], "response-ip")
        self.assertEqual(
            result["matched_rule"]["owner"],
            "32.2.2.0.192.rpz-ip.example.com.")
        self.assertEqual(result["matched_value"], "192.0.2.2")

    def test_response_ip_shorter_prefix(self):
        result = eval_rpz("host.example.", a_response("192.168.0.9"))
        self.assertEqual(
            result["matched_rule"]["owner"],
            "24.0.168.192.rpz-ip.example.com.")

    def test_longest_prefix_wins(self):
        zone = HEADER + (
            "24.0.168.192.rpz-ip CNAME a.\n"
            "32.9.0.168.192.rpz-ip CNAME b.\n"
        )
        result = eval_rpz("h.", a_response("192.168.0.9"), zones=(zone,))
        self.assertEqual(result["matched_rule"]["prefix_len"], 32)

    def test_response_ip_no_match(self):
        result = eval_rpz("host.example.", a_response("8.8.8.8"))
        self.assertEqual(result["result"], "unchanged")

    def test_response_ip_ipv6(self):
        zone = (
            "$ORIGIN v6.example.\n$TTL 300\n"
            "@ IN SOA ns h 1 1 1 1 1\n@ IN NS ns\n"
            "64.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.rpz-ip CNAME .\n"
        )
        response = {"answer": [{"name": "h.", "type": "AAAA", "ttl": 60,
                                "rdata": "2001:db8::1"}]}
        result = eval_rpz("h.", response, zones=(zone,))
        self.assertEqual(result["result"], "nxdomain")
        response["answer"][0]["rdata"] = "2001:db9::1"
        result = eval_rpz("h.", response, zones=(zone,))
        self.assertEqual(result["result"], "unchanged")

    def test_catch_all_prefix_zero(self):
        zone = (
            "$ORIGIN all.example.\n$TTL 300\n"
            "@ IN SOA ns h 1 1 1 1 1\n@ IN NS ns\n"
            "0.rpz-ip CNAME .\n"
        )
        self.assertEqual(
            eval_rpz("h.", a_response("8.8.8.8"), zones=(zone,))["result"],
            "nxdomain")


class NsTriggerTests(unittest.TestCase):
    def test_nsdname_suffix_match(self):
        result = eval_rpz(
            "q.example.", ns_response("ns1.ns.evil.example.com."))
        self.assertEqual(result["matched_rule"]["trigger"], "nsdname")
        self.assertEqual(result["result"], "nxdomain")

    def test_nsdname_exact(self):
        result = eval_rpz("q.example.", ns_response("ns.evil.example.com."))
        self.assertEqual(result["matched_rule"]["trigger"], "nsdname")

    def test_nsdname_wildcard_single_label(self):
        hit = eval_rpz(
            "q.example.", ns_response("bj.ns-cn.example.com."))
        self.assertEqual(hit["matched_rule"]["trigger"], "nsdname")
        miss = eval_rpz(
            "q.example.", ns_response("a.b.ns-cn.example.com."))
        self.assertEqual(miss["result"], "unchanged")

    def test_nsdname_exact_beats_wildcard_across_ns_names(self):
        # 两个 NS 目标分别被精确规则与通配规则命中 -> 精确规则胜
        response = {
            "answer": [],
            "authority": [
                {"name": "q.", "type": "NS", "ttl": 1,
                 "rdata": "ns.exact.example.com."},
                {"name": "q.", "type": "NS", "ttl": 1,
                 "rdata": "bj.wildns.example.com."},
            ],
            "additional": [],
        }
        zone = HEADER + (
            "ns.exact.rpz-nsdname CNAME .\n"
            "*.wildns.rpz-nsdname CNAME *.\n"
        )
        result = eval_rpz("q.", response, zones=(zone,))
        self.assertEqual(result["matched_rule"]["trigger"], "nsdname")
        self.assertEqual(result["result"], "nxdomain")
        self.assertEqual(result["matched_value"],
                         "ns.exact.example.com.")

    def test_nsip_glue(self):
        result = eval_rpz(
            "q.example.", ns_response("ns.other.net.", "203.0.2.99"))
        self.assertEqual(result["matched_rule"]["trigger"], "nsip")
        self.assertEqual(result["matched_value"], "203.0.2.99")

    def test_nsip_answer_glue_also_works(self):
        # 胶水出现在 answer 区（CNAME 链场景）同样可用
        response = {
            "answer": [
                {"name": "ns.other.net.", "type": "A", "ttl": 60,
                 "rdata": "203.0.2.99"},
            ],
            "authority": [
                {"name": "q.", "type": "NS", "ttl": 60,
                 "rdata": "ns.other.net."},
            ],
            "additional": [],
        }
        result = eval_rpz("q.", response)
        self.assertEqual(result["matched_rule"]["trigger"], "nsip")

    def test_nsip_no_glue_no_match(self):
        # 有 NS 名但响应没有提供任何地址 -> NSIP 无法命中
        result = eval_rpz("q.example.", ns_response("ns.other.net."))
        self.assertEqual(result["result"], "unchanged")


class SelectionTests(unittest.TestCase):
    def test_trigger_order_within_zone(self):
        # qname 与 response-ip 同时命中 -> qname 胜
        response = a_response("192.0.2.2")
        result = eval_rpz("evil.example.com.", response)
        self.assertEqual(result["matched_rule"]["trigger"], "qname")
        # response-ip 与 nsdname 同时命中 -> response-ip 胜
        response = {
            "answer": [{"name": "h.", "type": "A", "ttl": 1,
                        "rdata": "192.0.2.2"}],
            "authority": [{"name": "h.", "type": "NS", "ttl": 1,
                           "rdata": "x.ns.evil.example.com."}],
        }
        result = eval_rpz("unknown.example.com.", response)
        self.assertEqual(result["matched_rule"]["trigger"], "response-ip")

    def test_lowest_zone_index_wins(self):
        z0 = (
            "$ORIGIN z0.example.\n$TTL 300\n"
            "@ IN SOA ns h 1 1 1 1 1\n@ IN NS ns\n"
            "32.2.2.0.192.rpz-ip CNAME .\n"
        )
        response = {
            "answer": [{"name": "a.", "type": "A", "ttl": 1,
                        "rdata": "192.0.2.2"}],
            "authority": [{"name": "a.", "type": "NS", "ttl": 1,
                           "rdata": "ns1.ns.evil.example.com."}],
        }
        result = eval_rpz("anything.", response, zones=(z0, ZONE))
        self.assertEqual(result["matched_rule"]["zone_index"], 0)
        self.assertEqual(
            result["matched_rule"]["trigger"], "response-ip")

    def test_multiple_addresses_produce_multiple_candidates(self):
        zone = HEADER + (
            "32.8.8.8.8.rpz-ip CNAME a.\n"
            "32.9.8.8.8.rpz-ip CNAME b.\n"
        )
        response = {"answer": [
            {"name": "h.", "type": "A", "ttl": 1, "rdata": "8.8.8.8"},
            {"name": "h.", "type": "A", "ttl": 1, "rdata": "8.8.8.9"},
        ]}
        result = eval_rpz("h.", response, zones=(zone,))
        owners = [c["owner"] for c in result["candidates"]]
        self.assertEqual(len(owners), 2)
        # 8.8.8.8 打包字节更小，其规则确定性地胜出
        self.assertEqual(result["matched_value"], "8.8.8.8")

    def test_multiple_nsdnames_produce_multiple_candidates(self):
        zone = HEADER + (
            "ns.a.rpz-nsdname CNAME .\n"
            "ns.b.rpz-nsdname CNAME .\n"
        )
        response = {"authority": [
            {"name": "q.", "type": "NS", "ttl": 1,
             "rdata": "x.ns.a.example.com."},
            {"name": "q.", "type": "NS", "ttl": 1,
             "rdata": "y.ns.b.example.com."},
        ]}
        result = eval_rpz("q.", response, zones=(zone,))
        self.assertEqual(len(result["candidates"]), 2)

    def test_candidates_list_all_matches_sorted(self):
        response = {
            "answer": [{"name": "h.", "type": "A", "ttl": 1,
                        "rdata": "192.0.2.2"}],
            "authority": [{"name": "h.", "type": "NS", "ttl": 1,
                           "rdata": "x.ns.evil.example.com."}],
        }
        result = eval_rpz("unknown.example.com.", response)
        triggers = [c["trigger"] for c in result["candidates"]]
        self.assertEqual(triggers, ["response-ip", "nsdname"])

    def test_no_match_is_unchanged(self):
        result = eval_rpz("nothing.here.example.")
        self.assertEqual(result["result"], "unchanged")
        self.assertEqual(result["action"], "unchanged")
        self.assertIsNone(result["matched_rule"])
        self.assertEqual(result["candidates"], [])
        self.assertEqual(result["selection_reason"], "no_trigger_matched")

    def test_duplicate_rule_is_deduplicated(self):
        duplicate_zone = ZONE + "evil CNAME .\n"
        result = eval_rpz("evil.example.com.", zones=(duplicate_zone,))
        owners = [c["owner"] for c in result["candidates"]]
        self.assertEqual(owners.count("evil.example.com."), 1)

    def test_record_reorder_does_not_change_result(self):
        lines = [line for line in ZONE.splitlines(keepends=True)
                 if line.strip()]
        shuffled = "".join(lines[:3]) + "".join(reversed(lines[3:]))
        payload_response = a_response("192.0.2.2")
        one = eval_rpz("evil.example.com.", payload_response)
        two = eval_rpz("evil.example.com.", payload_response,
                       zones=(shuffled, ZONE2))
        self.assertEqual(
            json.dumps(one, sort_keys=True),
            json.dumps(two, sort_keys=True))

    def test_output_is_deterministic(self):
        one = eval_rpz("unknown.example.com.", {
            "answer": [{"name": "h.", "type": "A", "ttl": 1,
                        "rdata": "192.0.2.2"}],
            "authority": [{"name": "h.", "type": "NS", "ttl": 1,
                           "rdata": "x.ns.evil.example.com."}],
        })
        two = eval_rpz("unknown.example.com.", {
            "answer": [{"name": "h.", "type": "A", "ttl": 1,
                        "rdata": "192.0.2.2"}],
            "authority": [{"name": "h.", "type": "NS", "ttl": 1,
                           "rdata": "x.ns.evil.example.com."}],
        })
        self.assertEqual(
            json.dumps(one, sort_keys=True),
            json.dumps(two, sort_keys=True))


class ParseErrorTests(unittest.TestCase):
    def _expect_422(self, zone_text, code):
        with self.assertRaises(ReviewError) as ctx:
            evaluate_rpz({"zones": [zone_text], "qname": "h."})
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.code, code)

    def test_invalid_prefix_bad_label_count(self):
        self._expect_422(
            HEADER + "24.168.192.rpz-ip CNAME .\n", "invalid_prefix")

    def test_invalid_prefix_bad_host_bits(self):
        # 192.168.0.0/24 的规范编码是 24.0.168.192；多写一个非零主机字节
        self._expect_422(
            HEADER + "24.9.0.168.192.rpz-ip CNAME .\n", "invalid_prefix")

    def test_invalid_prefix_wildcard_on_ip_branch(self):
        self._expect_422(
            HEADER + "*.rpz-ip CNAME .\n", "invalid_prefix")

    def test_nsdname_branch_root_invalid(self):
        # nsdname 分支的根不是合法触发器
        zone = (
            "$ORIGIN b.example.\n$TTL 300\n"
            "@ IN SOA ns h 1 1 1 1 1\n@ IN NS ns\n"
            "rpz-nsdname CNAME .\n"
        )
        self._expect_422(zone, "invalid_prefix")

    def test_owner_out_of_zone(self):
        self._expect_422(
            HEADER + "evil.other.example. CNAME .\n",
            "owner_out_of_zone")

    def test_conflicting_cname_and_address(self):
        for body in (
            "x CNAME .\nx IN A 192.0.2.9\n",
            "x IN A 192.0.2.9\nx CNAME .\n",
        ):
            self._expect_422(HEADER + body, "conflict_rrset")

    def test_multiple_cname_targets(self):
        self._expect_422(
            HEADER + "x CNAME .\nx CNAME other.\n", "conflict_rrset")

    def test_non_apex_ns(self):
        self._expect_422(
            HEADER + "sub NS ns.other.\n", "conflict_rrset")

    def test_apex_cname(self):
        self._expect_422(HEADER + "@ CNAME .\n", "conflict_rrset")

    def test_unsupported_rr_type(self):
        self._expect_422(HEADER + "x MX 10 mail.\n", "conflict_rrset")
        self._expect_422(
            "$ORIGIN broken.example.\n$TTL 300\n"
            "@ SOA ns h 1 1 1 1 1\n@ NS ns\nx TXT \"v=hi\"\n",
            "conflict_rrset")

    def test_multiple_soa(self):
        self._expect_422(HEADER + "@ SOA ns h 2 1 1 1 1\n",
                         "conflict_rrset")

    def test_structural_error_is_zone_parse_error(self):
        # 括号未闭合是纯结构错误
        self._expect_422(
            "$ORIGIN broken.example.\n$TTL 300\n"
            "@ SOA ns h 1 1 1 1 1\n@ IN NS (\n",
            "zone_parse_error")

    def test_missing_origin(self):
        self._expect_422(
            "$TTL 300\n@ IN CNAME .\n", "zone_parse_error")

    def test_bad_response_record_is_422(self):
        payload = {
            "zones": [ZONE],
            "qname": "h.",
            "response": {"answer": [{"name": "h.", "type": "A",
                                     "rdata": "not-an-ip"}]},
        }
        with self.assertRaises(ReviewError) as ctx:
            evaluate_rpz(payload)
        self.assertEqual(ctx.exception.status, 422)
        self.assertEqual(ctx.exception.code, "invalid_record")


class RequestValidationTests(unittest.TestCase):
    def test_zones_required(self):
        with self.assertRaises(ReviewError) as ctx:
            evaluate_rpz({"qname": "h."})
        self.assertEqual(ctx.exception.status, 400)

    def test_qname_required(self):
        with self.assertRaises(ReviewError) as ctx:
            evaluate_rpz({"zones": [ZONE]})
        self.assertEqual(ctx.exception.status, 400)

    def test_bad_rcode(self):
        with self.assertRaises(ReviewError) as ctx:
            evaluate_rpz({"zones": [ZONE], "qname": "h.",
                          "response": {"rcode": "WHAT"}})
        self.assertEqual(ctx.exception.status, 400)

    def test_empty_response_is_allowed(self):
        result = evaluate_rpz(
            {"zones": [ZONE], "qname": "evil.example.com.",
             "response": {}})
        self.assertEqual(result["result"], "nxdomain")


if __name__ == "__main__":
    unittest.main()
