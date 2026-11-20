#!/usr/bin/env python3
"""Summarise Suricata rules as JSON for building a pcap that fires them.

Usage:
    rule_facts.py RULES_FILE        (or "-" for stdin)

For each rule this prints the header, the key options, every content match
decoded to bytes with its buffer and modifiers, and "notes": things in the
rule that change how the pcap has to be built or tested (a flowbit with no
setter, a threshold, an external file the engine needs, and so on).

This is not a validator. Suricata decides whether a rule is well-formed;
this only reads the options so the traffic can be planned. Standard
library only, so it runs before any venv exists.
"""

import json
import re
import sys

ACTIONS = (
    "alert",
    "drop",
    "reject",
    "rejectsrc",
    "rejectdst",
    "rejectboth",
    "pass",
    "log",
    "sdrop",
    "accept",
)
DIRECTIONS = ("->", "<>", "<-", "=>")

# Value-less options that switch the inspection buffer for what follows.
# Any value-less option with a dot in its name (http.uri, tls.sni, ...) is
# treated the same way.
LEGACY_STICKY = {
    "file_data",
    "pkt_data",
    "base64_data",
    "dns_query",
    "tls_sni",
    "tls_cert_subject",
    "tls_cert_issuer",
    "tls_cert_serial",
    "tls_cert_fingerprint",
    "ja3_hash",
    "ja3_string",
    "ja3s_hash",
    "ja3s_string",
    "ssh_proto",
    "ssh_software",
    "krb5_cname",
    "krb5_sname",
    "sip_method",
    "sip_uri",
    # HTTP sticky buffers with legacy underscore names
    "http_request_line",
    "http_response_line",
    "http_accept",
    "http_accept_enc",
    "http_accept_lang",
    "http_referer",
    "http_content_type",
    "http_content_len",
    "http_header_names",
    "http_connection",
    "http_start",
    "http_protocol",
}
# Value-less options with a dot in their name that aren't buffers.
NOT_BUFFERS = {"tls.store", "tls.cert_expired", "tls.cert_valid"}
# Old-style modifiers that move the preceding content into a buffer.
LEGACY_MODIFIERS = {
    "http_uri": "http.uri",
    "http_raw_uri": "http.uri.raw",
    "http_header": "http.header",
    "http_raw_header": "http.header.raw",
    "http_cookie": "http.cookie",
    "http_method": "http.method",
    "http_stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg",
    "http_client_body": "http.request_body",
    "http_server_body": "http.response_body",
    "http_user_agent": "http.user_agent",
    "http_host": "http.host",
    "http_raw_host": "http.host.raw",
}
CONTENT_MODIFIERS = {
    "nocase",
    "depth",
    "offset",
    "distance",
    "within",
    "startswith",
    "endswith",
    "fast_pattern",
    "rawbytes",
    "bsize",
}
# Keywords that test packet or header fields rather than payload. Flowsynth
# picks most header values itself, so these usually mean building with scapy.
HEADER_KEYWORDS = {
    "ipopts",
    "fragbits",
    "fragoffset",
    "ttl",
    "tos",
    "id",
    "ip_proto",
    "sameip",
    "icmp_id",
    "icmp_seq",
    "itype",
    "icode",
    "flags",
    "tcp.flags",
    "window",
    "seq",
    "ack",
    "tcp.seq",
    "tcp.ack",
    "tcp.window",
    "tcp.wscale",
    "tcp.mss",
    "ipv4.hdr",
    "ipv6.hdr",
    "tcp.hdr",
    "udp.hdr",
    "icmpv4.hdr",
    "icmpv6.hdr",
}
# Keywords that need something besides the rule and the pcap.
EXTERNAL_KEYWORDS = {
    "dataset": "a dataset file (or an inline dataset definition)",
    "datarep": "a dataset reputation file",
    "iprep": "an IP reputation file and category config",
    "lua": "a Lua script",
    "luajit": "a Lua script",
    "filemd5": "a list file of MD5 hashes",
    "filesha1": "a list file of SHA-1 hashes",
    "filesha256": "a list file of SHA-256 hashes",
}
APP_STATE_KEYWORDS = {"ssl_state", "ssl_version"}
# Transforms rewrite the current buffer before the next content is matched.
TRANSFORMS = {
    "from_base64",
    "to_lowercase",
    "to_uppercase",
    "strip_whitespace",
    "compress_whitespace",
    "dotprefix",
    "url_decode",
    "xor",
    "pcrexform",
    "to_md5",
    "to_sha1",
    "to_sha256",
    "header_lowercase",
    "strip_pseudo_headers",
    "luaxform",
    "domain",
    "tld",
    "gunzip",
    "zlib_deflate",
}
# Keywords Suricata 8.0.6 has and 7.0.17 lacks, from each engine's
# --list-keywords. A rule using one won't load on Suricata 7.
SURICATA8_KEYWORDS = set(
    """
    absent app-layer-state dns.additionals.rrname dns.answer.name
    dns.answers.rrname dns.authorities.rrname dns.queries.rrname dns.query.name
    dns.rcode dns.response.rrname dns.rrtype domain email.cc email.date
    email.from email.message_id email.received email.subject email.to email.url
    email.x_mailer enip.capabilities enip.cip_attribute enip.cip_class
    enip.cip_extendedstatus enip.cip_instance enip.cip_status enip.device_type
    enip.identity_status enip.product_code enip.product_name
    enip.protocol_version enip.revision enip.serial enip.service_name enip.state
    enip.status enip.vendor_id entropy flow.bytes flow.bytes_toclient
    flow.bytes_toserver flow.pkts flow.pkts_toclient flow.pkts_toserver
    from_base64 ftp.command ftp.command_data ftp.completion_code
    ftp.dynamic_port ftp.mode ftp.reply ftp.reply_received gunzip
    ldap.request.attribute_type ldap.request.dn ldap.request.operation
    ldap.responses.attribute_type ldap.responses.count ldap.responses.dn
    ldap.responses.message ldap.responses.operation ldap.responses.result_code
    luaxform mdns.additionals.rrname mdns.answers.rrname
    mdns.authorities.rrname mdns.queries.rrname mdns.response.rrname
    mqtt.connect.protocol_string ntp.mode ntp.reference_id ntp.stratum
    ntp.version pgsql.query sdp.attribute sdp.bandwidth sdp.connection_data
    sdp.email sdp.encryption_key sdp.media.connection_data
    sdp.media.encryption_key sdp.media.media sdp.media.media_info sdp.origin
    sdp.phone_number sdp.repeat_time sdp.session_info sdp.session_name sdp.time
    sdp.timezone sdp.uri sip.content_length sip.content_type sip.from sip.to
    sip.user_agent sip.via smb.version smtp.helo smtp.mail_from smtp.rcpt_to
    snmp.trap_type tcp.wscale tld tls.alpn tls.subjectaltname vlan.id
    vlan.layers websocket.flags websocket.mask websocket.opcode
    websocket.payload zlib_deflate
    """.split()
)
TO_CLIENT = {"to_client", "from_server"}
GENERIC_PROTOS = {"tcp", "ip", "any", "pkthdr"}  # may carry HTTP or not
TO_SERVER = {"to_server", "from_client"}
# Defaults from Suricata's suricata.yaml; a job's own config may differ.
DEFAULT_PORT_VARS = {
    "HTTP_PORTS": "80",
    "SHELLCODE_PORTS": "!80",
    "ORACLE_PORTS": "1521",
    "SSH_PORTS": "22",
    "DNP3_PORTS": "20000",
    "MODBUS_PORTS": "502",
    "FILE_DATA_PORTS": "[$HTTP_PORTS,110,143]",
    "FTP_PORTS": "21",
    "GENEVE_PORTS": "6081",
    "VXLAN_PORTS": "4789",
    "TEREDO_PORTS": "3544",
}
REFERENCE_URLS = {
    "cve": "https://nvd.nist.gov/vuln/detail/CVE-{}",
    "url": "https://{}",
    "bugtraq": "https://www.securityfocus.com/bid/{}",
    "md5": None,
    "sha256": None,
}


def join_continuations(text):
    """Join lines ending in a backslash, as Suricata does."""
    return re.sub(r"\\[ \t]*\r?\n", "", text)


def split_header(header):
    """Split a rule header on whitespace, keeping [ ... ] groups whole."""
    tokens, depth, cur = [], 0, ""
    for ch in header:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch.isspace() and depth == 0:
            if cur:
                tokens.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        tokens.append(cur)
    return tokens


def split_options(body):
    """Split the option text into (name, value) pairs.

    Values run to the next unescaped semicolon outside double quotes. The
    value keeps its escapes and quotes; callers unquote as needed.
    """
    options = []
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i] in " \t;":
            i += 1
        if i >= n:
            break
        start = i
        while i < n and body[i] not in ":;":
            i += 1
        name = body[start:i].strip()
        value = None
        if i < n and body[i] == ":":
            i += 1
            vstart, in_quote = i, False
            while i < n:
                ch = body[i]
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_quote = not in_quote
                elif ch == ";" and not in_quote:
                    break
                i += 1
            value = body[vstart:i].strip()
        options.append((name, value))
        i += 1
    return options


def unquote(value):
    if value is None:
        return None
    value = value.strip()
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1]
    return value


def decode_content(value):
    """Decode a content string ("abc|0d 0a|") into bytes."""
    raw = unquote(value)
    out, i, n = bytearray(), 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch == "|":
            end = raw.index("|", i + 1)
            hexpart = re.sub(r"\s+", "", raw[i + 1 : end])
            out += bytes.fromhex(hexpart)
            i = end + 1
        elif ch == "\\" and i + 1 < n:
            out += raw[i + 1].encode("latin-1")
            i += 2
        else:
            out += ch.encode("latin-1")
            i += 1
    return bytes(out)


def printable(data):
    """Render bytes the way Suricata rules do: text plus |hex| runs."""
    out, hexrun = [], []
    for b in data:
        if 0x20 <= b < 0x7F and b not in (0x22, 0x3B, 0x5C, 0x7C):
            if hexrun:
                out.append("|" + " ".join(hexrun) + "|")
                hexrun = []
            out.append(chr(b))
        else:
            hexrun.append(f"{b:02x}")
    if hexrun:
        out.append("|" + " ".join(hexrun) + "|")
    return "".join(out)


def parse_kv_list(value):
    """Parse "type both, track by_src, count 5, seconds 60" into a dict."""
    result = {}
    for part in (value or "").split(","):
        bits = part.strip().split(None, 1)
        if bits:
            result[bits[0]] = bits[1] if len(bits) > 1 else True
    return result


def parse_flowbits(value):
    """Return (command, [names]) for a flowbits/xbits value."""
    parts = [p.strip() for p in (value or "").split(",")]
    cmd = parts[0] if parts else ""
    names = []
    if len(parts) > 1:
        names = [x for x in re.split(r"[|&]", parts[1]) if x]
    return cmd, names


def parse_rule(line):
    """Parse one rule line into a dict, or None if it isn't a rule."""
    line = line.strip()
    m = re.match(r"^(\S+)\s+(.*?)\s*\((.*)\)\s*$", line, re.S)
    if not m or m.group(1) not in ACTIONS:
        return None
    action, header, body = m.groups()
    tokens = split_header(header)
    rule = {"action": action, "raw": line}
    if len(tokens) == 6 and tokens[3] in DIRECTIONS:
        keys = ("proto", "src", "sport", "direction", "dst", "dport")
        rule.update(dict(zip(keys, tokens, strict=True)))
    else:
        rule["header_error"] = f"unexpected header: {header!r}"
    rule["options"] = [{"name": n, "value": v} for n, v in split_options(body) if n]
    return rule


def analyse(rule):
    """Pull the facts a pcap builder needs out of a parsed rule."""
    facts = {
        k: rule.get(k)
        for k in ("action", "proto", "src", "sport", "direction", "dst", "dport")
    }
    facts.update(
        _options=rule["options"],
        raw=rule["raw"],
        sid=None,
        rev=None,
        gid=None,
        msg=None,
        classtype=None,
        references=[],
        metadata={},
        flow=[],
        flowbits=[],
        xbits=[],
        threshold=None,
        detection_filter=None,
        contents=[],
        pcre=[],
        buffers=[],
        transforms=[],
        other_keywords={},
        notes=[],
    )
    if rule.get("header_error"):
        facts["notes"].append(note("error", "header", rule["header_error"]))
    buffer = "payload"
    last_content = None
    for opt in rule["options"]:
        name, value = opt["name"], opt["value"]
        if name in ("sid", "rev", "gid", "priority"):
            try:
                facts[name] = int(value)
            except (TypeError, ValueError):
                facts[name] = value
                facts["notes"].append(
                    note("error", name, f"{name} must be a number, not {value!r}")
                )
        elif name == "msg":
            facts["msg"] = unquote(value)
        elif name == "classtype":
            facts["classtype"] = value
        elif name == "reference":
            facts["references"].append(parse_reference(value))
        elif name == "metadata":
            for part in (value or "").split(","):
                bits = part.strip().split(None, 1)
                if bits:
                    facts["metadata"].setdefault(bits[0], []).append(
                        bits[1] if len(bits) > 1 else ""
                    )
        elif name == "flow":
            facts["flow"] = [x.strip() for x in (value or "").split(",") if x.strip()]
        elif name in ("flowbits", "xbits"):
            cmd, names = parse_flowbits(value)
            facts[name].append({"command": cmd, "names": names, "raw": value})
        elif name in ("threshold", "detection_filter"):
            facts[name] = parse_kv_list(value)
        elif name in ("content", "uricontent"):
            negated = (value or "").lstrip().startswith("!")
            text = (value or "").lstrip().lstrip("!")
            try:
                data = decode_content(text)
                entry = {"buffer": buffer, "negated": negated, "value": unquote(text)}
                entry["bytes_hex"] = data.hex()
                entry["printable"] = printable(data)
            except (ValueError, IndexError) as exc:
                entry = {"buffer": buffer, "negated": negated, "value": unquote(text)}
                facts["notes"].append(
                    note("error", "content", f"cannot decode {text}: {exc}")
                )
            if name == "uricontent":
                entry["buffer"] = "http.uri"
            entry["modifiers"] = {}
            facts["contents"].append(entry)
            last_content = entry
        elif name in CONTENT_MODIFIERS and last_content is not None:
            last_content["modifiers"][name] = True if value is None else value
        elif name in LEGACY_MODIFIERS and last_content is not None:
            last_content["buffer"] = LEGACY_MODIFIERS[name]
            add_unique(facts["buffers"], LEGACY_MODIFIERS[name])
        elif value is None and (
            name in LEGACY_STICKY or ("." in name and name not in NOT_BUFFERS)
        ):
            # pkt_data resets to the raw payload
            buffer = "payload" if name == "pkt_data" else name
            last_content = None
            add_unique(facts["buffers"], name)
            if name in HEADER_KEYWORDS:  # tcp.hdr etc.: a buffer of header bytes
                facts["other_keywords"].setdefault(name, []).append(value)
        elif name in TRANSFORMS:
            facts["transforms"].append(
                {"buffer": buffer, "transform": name, "value": value}
            )
        elif name == "pcre":
            facts["pcre"].append({"buffer": buffer, "value": value})
        else:
            facts["other_keywords"].setdefault(name, []).append(value)
    add_notes(facts)
    return facts


def parse_reference(value):
    kind, _, ref = (value or "").partition(",")
    kind, ref = kind.strip(), ref.strip()
    template = REFERENCE_URLS.get(kind.lower())
    url = None
    if kind.lower() == "url":
        url = ref if re.match(r"^https?://", ref) else template.format(ref)
    elif template:
        url = template.format(re.sub(r"^CVE-", "", ref, flags=re.I))
    return {"type": kind, "value": ref, "url": url}


def note(level, code, message):
    return {"level": level, "code": code, "message": message}


def add_unique(items, item):
    if item not in items:
        items.append(item)


def body_limits(facts):
    """(side, libhtp setting, sure) for each HTTP body the rule inspects.

    sure is False for file.data on a generic proto (tcp, ip, any): it is
    bounded by libhtp only if the traffic turns out to be HTTP.
    """
    proto = facts["proto"] or ""
    if proto == "http2":
        return []  # libhtp's limits are for HTTP/1
    buffers = set(facts["buffers"])
    for p in facts["pcre"]:
        # legacy pcre modifiers: P is the request body, Q the response body
        flags = (p["value"] or "").strip('"').rsplit("/", 1)[-1]
        if "P" in flags:
            buffers.add("http.request_body")
        if "Q" in flags:
            buffers.add("http.response_body")
    http = proto.startswith("http") or any(b.startswith("http") for b in buffers)
    sure = True
    request = "http.request_body" in buffers
    response = "http.response_body" in buffers
    if buffers & {"file.data", "file_data"} and (http or proto in GENERIC_PROTOS):
        # file.data follows the rule's direction; with none, either body
        flow = set(facts["flow"])
        sure = http
        request = request or not flow & TO_CLIENT
        response = response or not flow & TO_SERVER
    return [("request", "request-body-limit", sure)] * request + [
        ("response", "response-body-limit", sure)
    ] * response


def per_event(facts):
    """Warn when matches per event on TCP or IP can't be read off the rule."""
    if facts["proto"] not in ("tcp", "ip"):
        return ""  # app-layer buffers count per transaction, UDP per packet
    if facts["buffers"] and not any(
        c["buffer"] == "payload" for c in facts["contents"]
    ):
        return ""
    return (
        "; on raw TCP one event can make several matches or none of its own. "
        "Measure with a copy at count 1 (gotchas.md: Matches per event vary)"
    )


def add_notes(facts):
    """Flag things in the rule that change how the pcap is built or tested."""
    notes = facts["notes"]
    flow = set(facts["flow"])
    others = facts["other_keywords"]

    if facts["sid"] is None:
        notes.append(
            note(
                "warning",
                "no-sid",
                "rule has no sid; Dalton will assign one (806421601 and up), "
                "but add one so the alert can be matched to the rule",
            )
        )
    if not re.match(r"^[\x00-\x7f]*$", facts["raw"]):
        notes.append(note("error", "non-ascii", "Dalton rejects non-ASCII rules"))
    if facts["action"] in ("drop", "reject", "sdrop") or facts["action"].startswith(
        "reject"
    ):
        notes.append(
            note(
                "info",
                "drop-action",
                f"'{facts['action']}' alerts in IDS mode but stops inspection of "
                "the rest of the flow; later rules on the same flow may not fire. "
                "Test with 'alert' if that matters",
            )
        )
    if is_noalert(facts):
        notes.append(
            note(
                "info",
                "noalert",
                "rule never alerts: it only sets state for other rules. Check "
                "the eve event's metadata (e.g. flowbits), or test a copy with "
                "noalert removed",
            )
        )
    for kind in ("threshold", "detection_filter"):
        spec = facts[kind]
        if spec:
            count = spec.get("count")
            count = count if isinstance(count, str) else "?"  # a bare count is True
            if kind == "detection_filter":
                # alerts start once the count is exceeded
                need = f"{int(count) + 1}" if count.isdigit() else f"{count} + 1"
                what = f"more than {count} matching events (alerts from match {need})"
            elif spec.get("type") == "limit":
                what = f"one matching event (it limits alerts to {count})"
            elif spec.get("type") == "both":
                what = (
                    f"{count} matching events (one alert, at match {count}, per window)"
                )
            else:
                what = f"{count} matching events (an alert every {count} matches)"
            caveat = per_event(facts)
            notes.append(
                note(
                    "info",
                    kind,
                    f"needs {what} in {spec.get('seconds', '?')}s tracked "
                    f"{spec.get('track', '?')}{caveat}. Test with --set "
                    "runmode=single so the alert lands on the same packet every run",
                )
            )
    if any(b.startswith(("tls.cert", "tls_cert")) for b in facts["buffers"]):
        notes.append(
            note(
                "info",
                "tls-certificate",
                "the certificate is only visible in TLS 1.2 or older; TLS 1.3 "
                "encrypts it. pcapkit.tls_flights() defaults to TLS 1.2",
            )
        )
    for side, limit, sure in body_limits(facts):
        notes.append(
            note(
                "info",
                "body-limit",
                ("" if sure else "if the traffic is HTTP, file.data ")
                + f"inspects the HTTP {side} body, which Suricata reads only up to "
                f"libhtp's {limit}: 100 KiB in the stock suricata.yaml and "
                "Dalton's default configs, 4 KiB if the key is unset, and "
                "server-config blocks can override it per address. "
                "Production sensors may differ: bytes past their limit never "
                "match, and padding ahead of the payload evades the rule. Tell "
                "the user, and keep the matched bytes well inside the limit",
            )
        )
    for name, purpose in EXTERNAL_KEYWORDS.items():
        if name in others:
            notes.append(
                note(
                    "warning",
                    "external-dependency",
                    f"'{name}' needs {purpose}; the job must supply it",
                )
            )
    header_kw = sorted(k for k in others if k in HEADER_KEYWORDS)
    if header_kw:
        notes.append(
            note(
                "info",
                "header-fields",
                f"tests packet header fields ({', '.join(header_kw)}); "
                "build these packets with scapy",
            )
        )
    payload_content = any(
        c["buffer"] == "payload" and not c["negated"] for c in facts["contents"]
    )
    if flow & TO_CLIENT and payload_content:
        if APP_STATE_KEYWORDS & set(others):
            notes.append(
                note(
                    "warning",
                    "ips-only",
                    "to_client rule mixes raw content with app-layer state "
                    f"({', '.join(sorted(APP_STATE_KEYWORDS & set(others)))}); "
                    "in IDS mode these can land on different packets and never "
                    "match together. Test with stream.inline=true",
                )
            )
        elif any(c["buffer"] != "payload" for c in facts["contents"]):
            notes.append(
                note(
                    "info",
                    "mixed-buffers",
                    "to_client rule mixes raw content with app-layer buffers; "
                    "if it won't fire in IDS mode, try stream.inline=true",
                )
            )
    if facts["proto"] == "tcp" and payload_content and not flow:
        notes.append(
            note(
                "info",
                "no-flow",
                "tcp rule with payload content but no flow keyword: any "
                "direction and stream state will do",
            )
        )
    if "dsize" in others:
        notes.append(
            note(
                "info",
                "dsize",
                f"dsize {others['dsize'][0]}: compares the matching packet's own "
                "payload size, so the data has to arrive in one segment of a "
                "size that satisfies it",
            )
        )
    if "stream_size" in others:
        notes.append(
            note(
                "info",
                "stream_size",
                f"stream_size {others['stream_size'][0]}: counts bytes sent so far "
                "on that side of the stream, including the SYN (an empty side "
                "has size 1)",
            )
        )
    for t in facts["transforms"]:
        notes.append(
            note(
                "info",
                "transform",
                f"{t['transform']} rewrites {t['buffer']} before matching: the "
                "content matches the transformed bytes, not what is on the wire",
            )
        )
    used = {o["name"] for o in facts["_options"]}
    newer = sorted(used & SURICATA8_KEYWORDS)
    if newer:
        notes.append(
            note(
                "info",
                "min-version",
                f"needs Suricata 8 or later ({', '.join(newer)}); Suricata 7 "
                "won't load it, and test lists such engines in not_loaded",
            )
        )
    for spec in facts["other_keywords"].get("requires", []):
        notes.append(
            note(
                "info",
                "requires",
                f"requires: {spec}. An engine that doesn't meet it skips the "
                "rule, and test lists it in not_loaded",
            )
        )
    if "dsize" not in others and not any(
        o["name"] in ("content", "uricontent", "pcre") for o in facts["_options"]
    ):
        notes.append(
            note(
                "info",
                "no-content",
                "no content or pcre: there is no fast pattern, and on a TCP "
                "stream the alert may land on a flush or flow-timeout "
                "pseudo-packet (pcap_cnt null) rather than the data packet",
            )
        )
    for name in ("byte_test", "byte_jump", "byte_extract", "byte_math"):
        for value in others.get(name, []):
            notes.append(note("info", name, explain_byte(name, value)))
    facts["roles"] = roles(facts)
    facts["leads"] = leads(facts)
    facts["suggested_dir"] = suggested_dir(facts)
    port_vars = sorted(
        {
            v
            for p in (facts["sport"] or "", facts["dport"] or "")
            for v in re.findall(r"\$(\w+)", p)
        }
    )
    facts["port_vars"] = {v: DEFAULT_PORT_VARS.get(v) for v in port_vars}
    facts["address_vars"] = sorted(
        {
            v
            for a in (facts["src"] or "", facts["dst"] or "")
            for v in re.findall(r"\$(\w+)", a)
        }
    )


def leads(facts):
    """Collect research leads: CVEs, URLs, hashes and named families."""
    cves, urls, hashes, families = [], [], [], []
    texts = [facts["msg"] or ""]
    for ref in facts["references"]:
        kind = ref["type"].lower()
        if kind == "cve":
            add_unique(cves, "CVE-" + re.sub(r"^CVE-", "", ref["value"], flags=re.I))
        elif kind in ("md5", "sha1", "sha256"):
            add_unique(hashes, ref["value"])
        elif ref["url"]:
            add_unique(urls, ref["url"])
        texts.append(ref["value"])
    for key, values in facts["metadata"].items():
        for value in values:
            if key.lower() == "cve":
                add_unique(cves, "CVE-" + re.sub(r"^CVE[-_]", "", value, flags=re.I))
            elif key.lower() in ("malware_family", "family", "tag"):
                add_unique(families, value)
            texts.append(value)
    for text in texts:
        for cve in re.findall(r"CVE[-_](\d{4})[-_](\d{4,})", text, flags=re.I):
            add_unique(cves, f"CVE-{cve[0]}-{cve[1]}")
        for h in re.findall(r"\b(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})\b", text):
            add_unique(hashes, h)
    return {
        "cves": cves,
        "cve_urls": [REFERENCE_URLS["cve"].format(c[4:]) for c in cves],
        "urls": urls,
        "hashes": hashes,
        "families": families,
    }


def explain_byte(name, value):
    """Spell out what a byte_* keyword reads, in plain words."""
    parts = [p.strip() for p in (value or "").split(",")]
    flags = set(parts[2:]) if name != "byte_test" else set(parts[4:])
    endian = "little-endian" if "little" in flags else "big-endian"
    if "string" in flags:
        base = "hex" if "hex" in flags else "oct" if "oct" in flags else "dec"
        endian = f"ASCII {base} digits"
    rel = "after the previous match" if "relative" in flags else "from the buffer start"
    try:
        if name == "byte_test":
            nbytes, op, val, offset = parts[:4]
            return (
                f"byte_test: reads {nbytes} bytes ({endian}) at offset {offset} "
                f"{rel}, and the value must be {op} {val}"
            )
        if name == "byte_jump":
            nbytes, offset = parts[:2]
            extra = "".join(
                f"; {f}"
                for f in parts[2:]
                if f.startswith(("multiplier", "post_offset"))
            )
            if "from_beginning" in flags:
                to = "to that many bytes from the start of the buffer"
            elif "from_end" in flags:
                to = "from the end of the buffer by that value"
            else:
                to = "that many bytes past the end of the field"
            return (
                f"byte_jump: reads {nbytes} bytes ({endian}) at offset {offset} "
                f"{rel}, then moves the cursor {to}{extra}. Later relative "
                "matches (distance, within) count from there, so a negative "
                "distance reaches back"
            )
        if name == "byte_extract":
            nbytes, offset, var = parts[:3]
            return (
                f"byte_extract: reads {nbytes} bytes ({endian}) at offset {offset} "
                f"{rel} into variable {var}, used by later keywords"
            )
    except ValueError:
        pass
    return f"{name}: {value}"


def suggested_dir(facts):
    """<sid>-<slug>: msg lowercased, non-alphanumerics to '-', 40 chars max."""
    slug = re.sub(r"[^a-z0-9]+", "-", (facts["msg"] or "rule").lower()).strip("-")
    slug = slug[:40].rstrip("-") or "rule"
    sid = facts["sid"] if isinstance(facts["sid"], int) else "nosid"
    return f"{sid}-{slug}"


def roles(facts):
    """Say which side of the header is the client, from the flow keyword."""
    flow = set(facts["flow"])
    src = f"{facts['src']} {facts['sport']}"
    dst = f"{facts['dst']} {facts['dport']}"
    if facts["direction"] == "<-":
        src, dst = dst, src
    if flow & TO_SERVER:
        word = sorted(flow & TO_SERVER)[0]
        return {"client": src, "server": dst, "basis": f"flow {word}"}
    if flow & TO_CLIENT:
        word = sorted(flow & TO_CLIENT)[0]
        return {"client": dst, "server": src, "basis": f"flow {word}"}
    return {"client": None, "server": None, "basis": "no flow direction"}


def cross_rule_notes(rules):
    """Notes that need every rule in the file, such as flowbit setters."""
    setters = set()
    for r in rules:
        for kind in ("flowbits", "xbits"):
            for fb in r[kind]:
                if fb["command"] in ("set", "toggle", "setx"):
                    setters.update(fb["names"])
    notes = []
    for r in rules:
        for kind in ("flowbits", "xbits"):
            for fb in r[kind]:
                if fb["command"] == "isset":
                    missing = [n for n in fb["names"] if n not in setters]
                    if missing:
                        notes.append(
                            note(
                                "warning",
                                "no-setter",
                                f"sid {r['sid']}: {kind} isset "
                                f"{', '.join(missing)} but no rule here sets it. "
                                "Find the real setter or write a stand-in "
                                "setter rule, and say so in the write-up",
                            )
                        )
    return notes


def is_noalert(facts):
    return "noalert" in facts["other_keywords"] or any(
        fb["command"] == "noalert" for fb in facts["flowbits"]
    )


def facts_for_text(text):
    rules, disabled = [], 0
    for line in join_continuations(text).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if parse_rule(stripped.lstrip("#").strip()):
                disabled += 1
            continue
        parsed = parse_rule(stripped)
        if parsed is None:
            continue
        facts = analyse(parsed)
        facts.pop("_options", None)
        rules.append(facts)
    result = {"rules": rules, "notes": cross_rule_notes(rules)}
    # the file's output directory is named for the rule the pcap must fire:
    # a setter marked noalert, or a pass rule, only supports it
    alerting = [
        r for r in rules if not is_noalert(r) and r["action"] != "pass"
    ] or rules
    if alerting:
        result["suggested_dir"] = alerting[0]["suggested_dir"]
    if len(alerting) > 1:
        result["notes"].append(
            note(
                "info",
                "several-targets",
                f"{len(alerting)} rules can alert; the top-level suggested_dir "
                f"uses the first (sid {alerting[0]['sid']}). If another is the "
                "target, use its suggested_dir",
            )
        )
    if disabled:
        result["notes"].append(
            note("info", "disabled", f"skipped {disabled} commented-out rule(s)")
        )
    if not rules:
        result["notes"].append(note("error", "no-rules", "no rules found"))
    return result


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    if len(argv) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    if argv[0] == "-":
        text = sys.stdin.read()
    else:
        with open(argv[0], encoding="utf-8", errors="surrogateescape") as fh:
            text = fh.read()
    result = facts_for_text(text)
    print(json.dumps(result, indent=2))
    notes = result["notes"] + [n for r in result["rules"] for n in r["notes"]]
    return 1 if any(n["level"] == "error" for n in notes) else 0


if __name__ == "__main__":
    sys.exit(main())
