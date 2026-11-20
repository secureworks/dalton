import json

import pytest

from tests.rule2pcap_scripts import load

rf = load("rule_facts")


def facts(text):
    return rf.facts_for_text(text)


def codes(notes):
    return {n["code"] for n in notes}


def test_decode_content_mixes_text_hex_and_escapes():
    assert rf.decode_content('"GET |20 2f|a\\;b\\"c"') == b'GET  /a;b"c'


def test_printable_round_trips_through_rule_syntax():
    data = b'ab;"|\r\n'
    assert rf.printable(data) == "ab|3b 22 7c 0d 0a|"
    assert rf.decode_content(rf.printable(data)) == data


def test_split_options_keeps_escaped_and_quoted_semicolons():
    opts = rf.split_options(
        'msg:"a; b"; content:"x\\;y"; nocase; pcre:"/a;b/i"; sid:5;'
    )
    assert opts == [
        ("msg", '"a; b"'),
        ("content", '"x\\;y"'),
        ("nocase", None),
        ("pcre", '"/a;b/i"'),
        ("sid", "5"),
    ]


def test_header_with_spaced_address_list():
    rule = rf.parse_rule(
        "alert tcp [10.0.0.1, 10.0.0.2] any -> $EXTERNAL_NET [80, 8080] "
        '(msg:"x"; sid:1;)'
    )
    assert rule["src"] == "[10.0.0.1, 10.0.0.2]"
    assert rule["dport"] == "[80, 8080]"


def test_not_a_rule():
    assert rf.parse_rule("include foo.rules") is None
    assert facts("# just a comment\n")["notes"][0]["code"] == "no-rules"


def test_sticky_buffers_and_legacy_modifiers():
    result = facts(
        'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"t"; '
        'flow:established,to_server; http.method; content:"POST"; '
        'http.uri; content:"/gate.php"; startswith; nocase; '
        'content:"ua"; http_user_agent; sid:10; rev:2;)'
    )
    rule = result["rules"][0]
    assert rule["sid"] == 10 and rule["rev"] == 2
    assert [(c["buffer"], c["printable"]) for c in rule["contents"]] == [
        ("http.method", "POST"),
        ("http.uri", "/gate.php"),
        ("http.user_agent", "ua"),
    ]
    assert rule["contents"][1]["modifiers"] == {"startswith": True, "nocase": True}
    assert rule["roles"]["client"] == "$HOME_NET any"
    assert rule["roles"]["server"] == "$EXTERNAL_NET any"


def test_negated_content_and_hex_bytes():
    rule = facts('alert tcp any any -> any any (content:!"|00 01|ab"; sid:3;)')[
        "rules"
    ][0]
    content = rule["contents"][0]
    assert content["negated"] is True
    assert content["bytes_hex"] == "00016162"


def test_flowbit_without_setter_is_flagged():
    result = facts(
        "alert http any any -> any any (flow:to_client; "
        'flowbits:isset,a.b; content:"x"; sid:2;)'
    )
    assert "no-setter" in codes(result["notes"])


def test_flowbit_setter_in_file_satisfies_isset():
    result = facts(
        "alert http any any -> any any (flow:to_server; "
        "flowbits:set,a.b; flowbits:noalert; sid:1;)\n"
        "alert http any any -> any any (flow:to_client; "
        "flowbits:isset,a.b|c.d; sid:2;)\n"
        "alert http any any -> any any (flowbits:set,c.d; sid:3;)\n"
    )
    assert "no-setter" not in codes(result["notes"])
    assert "noalert" in codes(result["rules"][0]["notes"])


def test_threshold_and_ips_only_notes():
    rule = facts(
        "alert tls $HOME_NET any -> $EXTERNAL_NET any (flow:established,to_client; "
        'ssl_state:server_hello; content:"|04|"; offset:2; depth:1; '
        "threshold:type both,track by_dst,count 100,seconds 2; sid:4;)"
    )["rules"][0]
    assert rule["threshold"] == {
        "type": "both",
        "track": "by_dst",
        "count": "100",
        "seconds": "2",
    }
    assert {"threshold", "ips-only"} <= codes(rule["notes"])
    assert rule["roles"]["server"] == "$HOME_NET any"


def test_header_fields_external_deps_drop_and_no_sid():
    rule = facts(
        'drop icmp any any -> any any (itype:0; dataset:isset,x; content:"a";)'
    )["rules"][0]
    assert {"header-fields", "external-dependency", "drop-action", "no-sid"} <= codes(
        rule["notes"]
    )


def test_non_ascii_rule_is_an_error():
    result = facts('alert tcp any any -> any any (content:"café"; sid:9;)')
    assert "non-ascii" in codes(result["rules"][0]["notes"])


def test_leads_from_references_metadata_and_msg():
    rule = facts(
        'alert http any any -> any any (msg:"Exploit CVE-2021-44228 attempt"; '
        "reference:cve,2014-6271; reference:url,example.com/a; "
        "reference:md5,d41d8cd98f00b204e9800998ecf8427e; "
        "metadata:cve 2016-0800, malware_family Foo; sid:7;)"
    )["rules"][0]
    leads = rule["leads"]
    assert leads["cves"] == ["CVE-2014-6271", "CVE-2016-0800", "CVE-2021-44228"]
    assert leads["cve_urls"][0] == "https://nvd.nist.gov/vuln/detail/CVE-2014-6271"
    assert leads["urls"] == ["https://example.com/a"]
    assert leads["hashes"] == ["d41d8cd98f00b204e9800998ecf8427e"]
    assert leads["families"] == ["Foo"]


def test_port_vars_and_disabled_rules_and_continuations():
    result = facts(
        "# alert tcp any any -> any any (sid:1;)\n"
        "alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS \\\n"
        '  (msg:"x"; sid:2;)\n'
    )
    assert len(result["rules"]) == 1
    assert result["rules"][0]["port_vars"] == {"HTTP_PORTS": "80"}
    assert result["rules"][0]["address_vars"] == ["EXTERNAL_NET", "HOME_NET"]
    assert "disabled" in codes(result["notes"])


@pytest.mark.parametrize(
    "text, exit_code",
    [
        ('alert tcp any any -> any any (content:"a"; sid:1;)', 0),
        ("not a rule", 1),
    ],
)
def test_main_exit_codes(tmp_path, capsys, text, exit_code):
    path = tmp_path / "x.rules"
    path.write_text(text)
    assert rf.main([str(path)]) == exit_code
    json.loads(capsys.readouterr().out)


def test_main_help_and_usage(capsys):
    assert rf.main(["--help"]) == 0
    assert "Usage:" in capsys.readouterr().out
    assert rf.main([]) == 2
    assert "Usage:" in capsys.readouterr().err


def test_content_value_is_unquoted_and_suggested_dir():
    rule = facts(
        'alert tcp any any -> any any (msg:"Big Bad: Thing!"; content:"ab"; sid:42;)'
    )["rules"][0]
    assert rule["contents"][0]["value"] == "ab"
    assert rule["suggested_dir"] == "42-big-bad-thing"


def test_min_version_no_content_and_byte_notes():
    rule = facts(
        "alert smtp any any -> any any (flow:to_server; smtp.mail_from; "
        'content:"x"; sid:1;)'
    )["rules"][0]
    assert "min-version" in codes(rule["notes"])
    rule = facts(
        "alert tcp any any -> any any (flow:to_server; byte_test:2,>,40000,4; sid:2;)"
    )["rules"][0]
    notes = {n["code"]: n["message"] for n in rule["notes"]}
    assert "no-content" in notes
    assert "reads 2 bytes (big-endian) at offset 4" in notes["byte_test"]
    rule = facts(
        'alert http any any -> any any (file.data; content:"MZ"; startswith; '
        "byte_jump:4,58,relative,little; sid:3;)"
    )["rules"][0]
    notes = {n["code"]: n["message"] for n in rule["notes"]}
    assert (
        "little-endian" in notes["byte_jump"]
        and "after the previous" in notes["byte_jump"]
    )


def test_roles_basis_echoes_the_rules_keyword():
    rule = facts(
        'alert tls any any -> any any (flow:established,from_server; content:"x"; sid:4;)'
    )["rules"][0]
    assert rule["roles"]["basis"] == "flow from_server"


def one_rule(text):
    return facts(text)["rules"][0]


@pytest.mark.parametrize(
    "option, buffer",
    [
        ("http_request_line", "http_request_line"),
        ("http.request_line", "http.request_line"),
        ("http_accept", "http_accept"),
        ("http_header_names", "http_header_names"),
    ],
)
def test_underscore_sticky_buffers(option, buffer):
    rule = one_rule(
        f'alert http any any -> any any (msg:"x"; flow:established,to_server; '
        f'{option}; content:"GET /x"; sid:1;)'
    )
    assert rule["contents"][0]["buffer"] == buffer


def test_header_buffer_gets_header_fields_note():
    rule = one_rule(
        'alert tcp any any -> any any (msg:"x"; tcp.hdr; content:"|50 18|"; sid:1;)'
    )
    assert rule["contents"][0]["buffer"] == "tcp.hdr"
    assert "header-fields" in codes(rule["notes"])


def test_tls_store_is_not_a_buffer():
    rule = one_rule(
        'alert tls any any -> any any (msg:"x"; flow:established,to_client; '
        'tls.cert_subject; content:"CN=x"; tls.store; sid:1;)'
    )
    assert rule["buffers"] == ["tls.cert_subject"]


def test_non_numeric_sid():
    rule = one_rule(
        'alert tcp any any -> any any (msg:"x"; content:"a"; sid:../../tmp/x;)'
    )
    assert "sid" in codes(rule["notes"])
    assert rule["suggested_dir"].startswith("nosid-")


def test_standalone_noalert_note():
    rule = one_rule(
        'alert tcp any any -> any any (msg:"x"; content:"a"; noalert; sid:1;)'
    )
    assert "noalert" in codes(rule["notes"])


@pytest.mark.parametrize(
    "option, wanted",
    [
        ("threshold:type threshold,track by_src,count 5,seconds 60", "every 5 matches"),
        (
            "threshold:type both,track by_src,count 5,seconds 60",
            "one alert, at match 5",
        ),
        ("threshold:type limit,track by_src,count 5,seconds 60", "one matching event"),
        ("detection_filter:track by_src,count 5,seconds 60", "from match 6"),
    ],
)
def test_threshold_note_per_type(option, wanted):
    rule = one_rule(
        f'alert tcp any any -> any any (msg:"x"; content:"a"; {option}; sid:1;)'
    )
    message = " ".join(n["message"] for n in rule["notes"])
    assert wanted in message and "runmode=single" in message


def test_tcp_header_keywords_get_header_fields_note():
    rule = one_rule('alert tcp any any -> any any (msg:"x"; tcp.seq:0; sid:1;)')
    assert "header-fields" in codes(rule["notes"])


def test_bare_count_does_not_crash():
    rule = one_rule(
        'alert tcp any any -> any any (msg:"x"; content:"a"; '
        "detection_filter:track by_src, count, seconds 60; sid:1;)"
    )
    assert "detection_filter" in codes(rule["notes"])


def test_continuation_with_trailing_whitespace_is_parsed():
    result = facts('alert tcp any any -> any any (msg:"x"; \\  \n  sid:7;)\n')
    assert result["rules"][0]["sid"] == 7


def test_requires_note():
    rule = one_rule(
        'alert tcp any any -> any any (msg:"x"; requires: version >= 8; '
        'content:"a"; sid:1;)'
    )
    assert "requires" in codes(rule["notes"])


def test_matches_per_event_caveat_only_where_counting_is_unclear():
    def note_for(options, proto="tcp"):
        rule = one_rule(
            f'alert {proto} any any -> any any (msg:"x"; {options} '
            "threshold:type threshold,track by_src,count 5,seconds 60; sid:4;)"
        )
        return next(n["message"] for n in rule["notes"] if n["code"] == "threshold")

    caveat = "Measure with a copy at count 1"
    assert caveat in note_for('content:"a";')
    assert caveat in note_for("flow:established,to_server;")
    assert caveat in note_for("flow:established,to_server;", proto="ip")
    assert caveat in note_for("byte_test:1,=,82,0;")
    assert caveat not in note_for('http.uri; content:"/a";', proto="http")
    assert caveat not in note_for('content:"a";', proto="udp")


def test_tls_certificate_note():
    rule = one_rule(
        'alert tls any any -> any any (msg:"x"; tls.cert_issuer; content:"Z"; sid:1;)'
    )
    assert "tls-certificate" in codes(rule["notes"])


def test_body_limit_note():
    def limits(options, proto="http"):
        rule = one_rule(f'alert {proto} any any -> any any (msg:"x"; {options} sid:1;)')
        found = [n["message"] for n in rule["notes"] if n["code"] == "body-limit"]
        return sorted(m.split("libhtp's ")[1].split(":")[0] for m in found)

    request, response = ["request-body-limit"], ["response-body-limit"]
    assert limits('http.request_body; content:"a";') == request
    assert limits('content:"a"; http_client_body;') == request
    assert limits('pcre:"/a/P";') == request
    assert limits('http.response_body; content:"a";') == response
    # file.data follows the direction; with none it could be either body
    assert limits('flow:to_server; file.data; content:"a";') == request
    assert limits('flow:established,to_client; file.data; content:"a";') == response
    assert limits('file.data; content:"a";') == request + response
    # other protocols, and HTTP/2, aren't bounded by libhtp's limits
    assert limits('file.data; content:"a";', proto="smtp") == []
    assert limits('file.data; content:"a";', proto="http2") == []
    assert limits('http.uri; content:"/a";') == []
    # file.data on a generic proto is bounded only if the traffic is HTTP
    tcp = 'flow:established,to_client; file_data; content:"a";'
    assert limits(tcp, proto="tcp") == response
    rule = one_rule(f'alert tcp any any -> any any (msg:"x"; {tcp} sid:1;)')
    (message,) = [n["message"] for n in rule["notes"] if n["code"] == "body-limit"]
    assert message.startswith("if the traffic is HTTP")
    assert limits('content:"a";', proto="tcp") == []


def test_valueless_pcre_does_not_crash():
    rule = one_rule('alert tcp any any -> any any (msg:"x"; pcre; sid:20;)')
    assert rule["sid"] == 20


def test_byte_jump_note_follows_where_it_jumps_from():
    def jump(args):
        rule = one_rule(
            f'alert udp any any -> any any (msg:"x"; content:"a"; byte_jump:{args}; '
            'content:"b"; within:1; sid:1;)'
        )
        return next(n["message"] for n in rule["notes"] if n["code"] == "byte_jump")

    assert "past the end of the field" in jump("2,0")
    assert "from the start of the buffer" in jump("2,0,from_beginning")
    assert "from the end of the buffer" in jump("2,0,from_end")
    assert jump("2,0,multiplier 2,post_offset 1").index("multiplier") < jump(
        "2,0,multiplier 2,post_offset 1"
    ).index("post_offset")


def test_dsize_rule_is_packet_only_and_may_be_a_range():
    rule = one_rule('alert tcp any any -> any any (msg:"x"; dsize:>100; sid:1;)')
    notes = {n["code"]: n["message"] for n in rule["notes"]}
    assert "no-content" not in notes
    assert "exactly" not in notes["dsize"]


def test_malformed_header_is_a_note_not_a_crash():
    rule = one_rule(
        'alert http any any any any (msg:"x"; file.data; content:"a"; sid:1;)'
    )
    assert "header" in codes(rule["notes"])


def test_pkt_data_resets_to_payload():
    rule = one_rule(
        'alert http any any -> any any (msg:"x"; http.uri; content:"/a"; '
        'pkt_data; content:"raw"; sid:1;)'
    )
    assert [c["buffer"] for c in rule["contents"]] == ["http.uri", "payload"]


def test_suggested_dir_for_a_file_is_the_rule_that_alerts():
    setter = (
        'alert http any any -> any any (msg:"Setter"; flow:established,to_server; '
        'http.uri; content:"/x"; flowbits:set,b; flowbits:noalert; sid:1;)'
    )
    target = (
        'alert http any any -> any any (msg:"Target"; flow:established,to_client; '
        'file_data; content:"MZ"; flowbits:isset,b; sid:2;)'
    )
    result = facts(setter + "\n" + target)
    assert result["suggested_dir"] == "2-target"
    assert "several-targets" not in {n["code"] for n in result["notes"]}
    both = facts(target + "\n" + target.replace("sid:2", "sid:3"))
    assert both["suggested_dir"] == "2-target"
    assert "several-targets" in {n["code"] for n in both["notes"]}
    # a pass rule doesn't alert either
    allow = target.replace("alert http", "pass http").replace("sid:2", "sid:4")
    result = facts(allow + "\n" + target)
    assert result["suggested_dir"] == "2-target"
    assert "several-targets" not in {n["code"] for n in result["notes"]}
