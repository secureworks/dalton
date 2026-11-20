"""The skill's build templates must run, rebuild byte-for-byte, and lint clean."""

import hashlib
import importlib.util
import shutil
import subprocess
import sys

import pytest

from tests.rule2pcap_scripts import SCRIPTS, load

pl = load("pcap_lint")
TEMPLATES = SCRIPTS.parent / "templates"


def build(tmp_path, template):
    shutil.copy(TEMPLATES / template, tmp_path / "build.py")
    shutil.copy(TEMPLATES / "pcapkit.py", tmp_path / "pcapkit.py")
    out = subprocess.run(
        [sys.executable, "-I", "build.py"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().splitlines()[-1]


@pytest.mark.parametrize(
    "template",
    [
        "build_flowsynth.py",
        "build_scapy.py",
        pytest.param(
            "build_tls.py",
            marks=pytest.mark.skipif(
                importlib.util.find_spec("cryptography") is None,
                reason="cryptography not installed",
            ),
        ),
    ],
)
def test_template_builds_reproducibly_and_lints_clean(tmp_path, template):
    pcap = build(tmp_path, template)
    first = hashlib.sha256(open(pcap, "rb").read()).hexdigest()
    pcap = build(tmp_path, template)
    assert hashlib.sha256(open(pcap, "rb").read()).hexdigest() == first
    result = pl.lint(pcap)
    assert [f for f in result["findings"] if f["level"] != "info"] == []
    tcp_flows = [f for f in result["summary"]["flows"] if f["proto"] == "tcp"]
    assert tcp_flows and all(f["handshake"] and f["teardown"] for f in tcp_flows)
    assert not (tmp_path / "__pycache__").exists()


def test_every_demo_rule_parses():
    rf = load("rule_facts")
    result = rf.facts_for_text((TEMPLATES / "demo.rules").read_text())
    assert len(result["rules"]) == 5
    assert all(n["level"] != "error" for r in result["rules"] for n in r["notes"])


def test_eval_rules_parse_cleanly():
    import json
    import re

    rf = load("rule_facts")
    evals = json.loads((SCRIPTS.parent / "evals" / "evals.json").read_text())
    sids = []
    for case in evals["evals"]:
        rules = re.findall(r"alert .*?rev:1;\)", case["prompt"])
        assert rules, case["id"]
        result = rf.facts_for_text("\n".join(rules))
        assert not [n for n in result["notes"] if n["level"] != "info"], case["id"]
        sids += [r["sid"] for r in result["rules"]]
    assert len(sids) == len(set(sids))


def pcapkit():
    sys.path.insert(0, str(TEMPLATES))
    try:
        import pcapkit as pk
    finally:
        sys.path.pop(0)
    return pk


def test_inert_pe_looks_like_a_linker_built_pe():
    import base64
    import random
    import struct

    pk = pcapkit()
    pe = pk.inert_pe(4096, rng=random.Random(1), dll=True)
    assert base64.b64encode(pe).startswith(b"TVqQAAMAAAAEAAAA//8AALgA")
    e_lfanew = struct.unpack("<I", pe[60:64])[0]
    assert pe[e_lfanew : e_lfanew + 4] == b"PE\0\0"
    (sections,) = struct.unpack("<H", pe[e_lfanew + 6 : e_lfanew + 8])
    (characteristics,) = struct.unpack("<H", pe[e_lfanew + 22 : e_lfanew + 24])
    assert sections == 1 and characteristics & 0x2000
    (optional_size,) = struct.unpack("<H", pe[e_lfanew + 20 : e_lfanew + 22])
    optional = e_lfanew + 24
    assert optional_size == 224 and pe[optional : optional + 2] == b"\x0b\x01"
    (subsystem,) = struct.unpack("<H", pe[optional + 68 : optional + 70])
    assert subsystem == 2  # Windows GUI
    text = optional + optional_size
    assert pe[text : text + 5] == b".text"
    # the section has no bytes in the file: nothing for the entry point to run
    raw_size, raw_pointer = struct.unpack("<II", pe[text + 16 : text + 24])
    assert raw_size == 0 and raw_pointer == 0
    assert len(pe) == 4096


def test_dns_messages_aaaa_and_nxdomain():
    from scapy.layers.dns import DNS

    pk = pcapkit()
    _, reply = pk.dns_messages(7, "a.example", "2001:db8::5", qtype="AAAA")
    dns = DNS(reply)
    assert dns.ancount == 1 and dns.an[0].rdata == "2001:db8::5"
    with pytest.raises(ValueError):
        pk.dns_messages(7, "a.example", "192.0.2.1", qtype="AAAA")
    _, reply = pk.dns_messages(7, "nope.example", rcode=3)
    dns = DNS(reply)
    assert dns.rcode == 3 and dns.ancount == 0


def test_set_ip_fields_and_reply_gap():
    import random

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pk = pcapkit()
    rng = random.Random(3)
    pkts = [
        Ether() / IP(src="10.0.0.1", dst="203.0.113.9", id=1) / TCP(),
        Ether() / IP(src="203.0.113.9", dst="10.0.0.1", id=1) / TCP(),
        Ether() / IP(src="10.0.0.1", dst="203.0.113.9", id=1) / TCP(),
    ]
    for i, p in enumerate(pkts):
        p.time = 100 + i
    out = pk.set_ip_fields(pkts, rng, ttl={"10.0.0.1": 128, "203.0.113.9": 52})
    assert [p[IP].ttl for p in out] == [128, 52, 128]
    assert out[2][IP].id == out[0][IP].id + 1
    for p in out:
        clone = p[IP].copy()
        clone.chksum = None
        assert IP(bytes(clone)).chksum == p[IP].chksum
    remote = {"203.0.113.9"}
    assert pk.reply_gap(out[1], out[:1], remote, rng) >= 0.035  # remote answers local
    assert pk.reply_gap(out[2], out[:2], remote, rng) < 0.001  # local is fast


def test_reply_gap_keeps_a_flight_together_across_local_acks():
    import random

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether
    from scapy.packet import Raw

    pk = pcapkit()
    rng = random.Random(3)

    def pkt(src, dst, flags, data=b""):
        sport, dport = (49152, 80) if src == "10.0.0.1" else (80, 49152)
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        return p / Raw(data) if data else p

    lan, wan = "10.0.0.1", "203.0.113.9"
    synack, ack = pkt(wan, lan, "SA"), pkt(lan, wan, "A")
    seg1, seg2 = pkt(wan, lan, "PA", b"a" * 1460), pkt(wan, lan, "PA", b"b")
    remote = {wan}
    # a server-first banner after the handshake ACK answers it: an RTT
    assert pk.reply_gap(seg1, [synack, ack], remote, rng) >= 0.035
    # the next segment of the same flight doesn't wait for the local ACK
    assert pk.reply_gap(seg2, [synack, ack, seg1, ack], remote, rng) < 0.001


@pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography not installed",
)
def test_mint_chain_writes_leaf_then_intermediate(tmp_path):
    import datetime

    from cryptography import x509

    pk = pcapkit()
    when = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    pk.mint_chain(
        [("C", "AT"), ("O", "ZeroSSL"), ("CN", "ZeroSSL RSA Domain Secure Site CA")],
        [("C", "US"), ("O", "The USERTRUST Network"), ("CN", "USERTrust RSA")],
        when,
        3650,
        [("CN", "portal.example.net")],
        ["portal.example.net"],
        when,
        90,
        (11, 22),
        str(tmp_path / "chain.pem"),
        str(tmp_path / "leaf.key"),
    )
    leaf, ca = x509.load_pem_x509_certificates((tmp_path / "chain.pem").read_bytes())
    assert leaf.issuer == ca.subject
    assert "ZeroSSL" in leaf.issuer.rfc4514_string()
    assert leaf.serial_number == 22 and ca.serial_number == 11


@pytest.mark.parametrize("tls", ["TLSv1_2", "TLSv1_3"])
@pytest.mark.parametrize(
    "exchanges", [[(b"beacon", b"")], [(b"", b"hello")], [(b"a", b"b"), (b"", b"c")]]
)
def test_tls_flights_with_an_empty_side(tmp_path, tls, exchanges):
    import datetime

    pk = pcapkit()
    when = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert, key = str(tmp_path / "c.pem"), str(tmp_path / "k.pem")
    pk.mint_cert([("CN", "a.example")], when, 30, 1, cert, key)
    flights = pk.tls_flights(
        cert, key, exchanges, str(tmp_path / "keys.log"), max_version=tls
    )
    assert flights and {d for d, _ in flights} == {">", "<"}


@pytest.mark.parametrize("capture", ["client", "server"])
def test_teardown_rtt_follows_the_capture_point(capture):
    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pk = pcapkit()
    syn = (
        Ether()
        / IP(src="10.0.0.5", dst="203.0.113.9")
        / TCP(sport=49152, dport=80, flags="S", seq=100)
    )
    synack = (
        Ether()
        / IP(src="203.0.113.9", dst="10.0.0.5")
        / TCP(sport=80, dport=49152, flags="SA", seq=500, ack=101)
    )
    # serialise, so lengths and checksums are filled in as in a real capture
    syn, synack = Ether(bytes(syn)), Ether(bytes(synack))
    syn.time, synack.time = 1000.0, 1000.05
    pkts = pk.teardown([syn, synack], closer="server", rtt=0.045, capture=capture)
    fin, ack, fin2, last = pkts[2:]
    gap_ack, gap_last = float(ack.time - fin.time), float(last.time - fin2.time)
    # near the client: the client's ACK of the server's FIN is local, and the
    # server's ACK of the client's FIN arrives an RTT later; the reverse near
    # the server
    if capture == "client":
        assert gap_ack < 0.01 and gap_last > 0.04
    else:
        assert gap_ack > 0.04 and gap_last < 0.01


def test_tcp_session_keeps_big_messages_inside_the_window(tmp_path):
    import random

    from scapy.utils import wrpcap

    pk = pcapkit()
    client = pk.Host("10.0.0.5", "02:00:00:00:00:01")
    server = pk.Host("203.0.113.9", "02:00:00:00:00:02", ttl=52)
    big = b"x" * 200_000
    pkts, _ = pk.tcp_session(
        1000.0, client, server, 49152, 80, [(">", big), ("<", big)], random.Random(1)
    )
    path = tmp_path / "big.pcap"
    wrpcap(str(path), pkts)
    lint = load("pcap_lint").lint(str(path))
    assert "beyond-window" not in {f["code"] for f in lint["findings"]}
    # after the handshake the window field is scaled, offering about 64 KB
    from scapy.layers.inet import TCP

    data = [p for p in pkts if TCP in p and "S" not in p[TCP].flags]
    assert all(p[TCP].window < 1024 for p in data)


def test_ipv6_flowsynth_segments_fit_the_mtu(tmp_path):
    pk = pcapkit()
    synth = tmp_path / "v6.synth"
    macs = ("02:00:00:00:00:01", "02:00:00:00:00:02")
    synth.write_text(
        pk.flow_line("f", "tcp", "[2001:db8::5]", 49152, "[2001:db8:1::9]", 80, *macs)
        + pk.event_line("f", ">", b"x" * 5000)
        + pk.event_line("f", "<", b"y" * 5000)
    )
    pk.compile_synth(str(synth), str(tmp_path / "v6.pcap"))
    lint = load("pcap_lint").lint(str(tmp_path / "v6.pcap"))
    codes = {f["code"] for f in lint["findings"]}
    assert not codes & {"jumbo-frame", "over-mss"}, codes


@pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography not installed",
)
def test_tls_template_rebuilds_its_cache_when_an_input_changes(tmp_path):
    build(tmp_path, "build_tls.py")
    script = tmp_path / "build.py"
    text = script.read_text()
    assert "SNI = None" in text
    script.write_text(text.replace("SNI = None", 'SNI = "edited.example.org"'))
    out = subprocess.run(
        [sys.executable, "-I", "build.py"], cwd=tmp_path, capture_output=True, text=True
    )
    assert out.returncode == 0, out.stderr
    pcap = out.stdout.strip().splitlines()[-1]
    assert b"edited.example.org" in open(pcap, "rb").read()


@pytest.mark.parametrize("window", [1000, 262144])
def test_tcp_session_handles_small_and_large_windows(tmp_path, window):
    import random

    from scapy.utils import wrpcap

    pk = pcapkit()
    client = pk.Host("10.0.0.5", "02:00:00:00:00:01", window=window)
    server = pk.Host("203.0.113.9", "02:00:00:00:00:02", ttl=52, window=window)
    msgs = [(">", b"x" * 20_000), ("<", b"y" * 20_000)]
    pkts, _ = pk.tcp_session(1000.0, client, server, 49152, 80, msgs, random.Random(1))
    path = tmp_path / "w.pcap"
    wrpcap(str(path), pkts)
    lint = load("pcap_lint").lint(str(path))
    assert "beyond-window" not in {f["code"] for f in lint["findings"]}


def flowsynth_flow(tmp_path, pk, mss=None, size=5000):
    synth = tmp_path / "f.synth"
    macs = ("02:00:00:00:00:01", "02:00:00:00:00:02")
    synth.write_text(
        pk.flow_line("f", "tcp", "10.0.0.5", 49152, "203.0.113.9", 80, *macs, mss)
        + pk.event_line("f", ">", b"x" * size)
        + pk.event_line("f", "<", b"y" * size)
    )
    pk.compile_synth(str(synth), str(tmp_path / "f.pcap"))
    from scapy.utils import rdpcap

    return list(rdpcap(str(tmp_path / "f.pcap")))


def test_set_tcp_stack_gives_flowsynth_real_options(tmp_path):
    import random

    from scapy.layers.inet import TCP
    from scapy.utils import wrpcap

    pk = pcapkit()
    stacks = {"10.0.0.5": "linux", "203.0.113.9": "linux"}
    assert pk.both_timestamp("linux", "linux")
    # full 1460-byte segments leave no room for the timestamp option
    with pytest.raises(ValueError, match="mss=1448"):
        pk.set_tcp_stack(flowsynth_flow(tmp_path, pk), stacks, random.Random(1))
    pkts = flowsynth_flow(tmp_path, pk, mss=1448)
    pkts = pk.teardown(pkts, closer="client")
    pkts = pk.set_tcp_stack(pkts, stacks, random.Random(1))
    syn, synack = pkts[0][TCP], pkts[1][TCP]
    assert [o[0] for o in syn.options] == [
        "MSS",
        "SAckOK",
        "Timestamp",
        "NOP",
        "WScale",
    ]
    assert dict(syn.options)["MSS"] == 1460 and syn.window == 64240
    assert synack.window == 65160
    # the SYN/ACK echoes the SYN's timestamp; later packets echo the peer's
    assert dict(synack.options)["Timestamp"][1] == dict(syn.options)["Timestamp"][0]
    rest = [p[TCP] for p in pkts[2:]]
    assert all(t.window == 502 and dict(t.options).get("Timestamp") for t in rest)
    path = tmp_path / "out.pcap"
    wrpcap(str(path), pkts)
    codes = {f["code"] for f in load("pcap_lint").lint(str(path))["findings"]}
    assert not codes & {"bare-syn", "jumbo-frame", "over-mss", "beyond-window"}, codes


def test_set_tcp_stack_without_timestamps_on_one_side(tmp_path):
    import random

    from scapy.layers.inet import TCP

    pk = pcapkit()
    pkts = flowsynth_flow(tmp_path, pk)
    stacks = {"10.0.0.5": "windows", "203.0.113.9": "linux"}
    pkts = pk.set_tcp_stack(pkts, stacks, random.Random(1))
    syn, synack = pkts[0][TCP], pkts[1][TCP]
    assert [o[0] for o in syn.options] == [
        "MSS",
        "NOP",
        "WScale",
        "NOP",
        "NOP",
        "SAckOK",
    ]
    # Linux answers a SYN without timestamps in its other option order
    assert [o[0] for o in synack.options] == pk.STACKS["linux"]["options_nots"]
    # and offers a window that is a multiple of the full 1460-byte MSS
    assert synack.window == 64240
    later = [p[TCP] for p in pkts[2:]]
    assert all(not t.options for t in later)
    assert {t.window for t in later if t.sport == 49152} == {513}


def test_tcp_session_with_stacks_fits_timestamps_in_the_mtu(tmp_path):
    import random

    from scapy.utils import wrpcap

    pk = pcapkit()
    client = pk.Host("10.0.0.5", "02:00:00:00:00:01", stack="macos")
    server = pk.Host("203.0.113.9", "02:00:00:00:00:02", ttl=52, stack="linux")
    msgs = [(">", b"x" * 100_000), ("<", b"y" * 300_000)]
    t = 1_700_000_000.0
    pkts, _ = pk.tcp_session(t, client, server, 49152, 80, msgs, random.Random(1))
    path = tmp_path / "s.pcap"
    wrpcap(str(path), pkts)
    codes = {f["code"] for f in load("pcap_lint").lint(str(path))["findings"]}
    assert not codes, codes


def test_teardown_with_remote_hosts_and_an_rtt_range():
    import random

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pk = pcapkit()

    def flow(server):
        syn = (
            Ether()
            / IP(src="10.0.0.5", dst=server)
            / TCP(sport=49152, dport=80, flags="S", seq=1)
        )
        ack = (
            Ether()
            / IP(src=server, dst="10.0.0.5")
            / TCP(sport=80, dport=49152, flags="SA", ack=2)
        )
        syn, ack = Ether(bytes(syn)), Ether(bytes(ack))
        syn.time, ack.time = 1000.0, 1000.05
        return [syn, ack]

    # a flow with no remote end closes at LAN speed
    lan = pk.teardown(flow("10.0.0.9"), remote={"203.0.113.9"})
    assert float(lan[-1].time - lan[2].time) < 0.002
    with pytest.raises(ValueError):
        pk.teardown(flow("203.0.113.9"), rtt=(0.03, 0.05))
    wan = pk.teardown(
        flow("203.0.113.9"),
        closer="client",
        remote={"203.0.113.9"},
        rtt=(0.03, 0.05),
        rng=random.Random(1),
    )
    fin, ack = wan[2], wan[3]
    assert 0.03 <= float(ack.time - fin.time) <= 0.05


def test_set_tcp_stack_synack_offers_only_what_the_syn_did(tmp_path):
    import random

    from scapy.layers.inet import TCP

    pk = pcapkit()
    pkts = flowsynth_flow(tmp_path, pk)  # Flowsynth's SYN has no options
    pkts = pk.set_tcp_stack(pkts, {"203.0.113.9": "linux"}, random.Random(1))
    assert [o[0] for o in pkts[1][TCP].options] == ["MSS"]
    pkts = pk.set_tcp_stack(
        flowsynth_flow(tmp_path, pk), {"203.0.113.9": "macos"}, random.Random(1)
    )
    assert [o[0] for o in pkts[1][TCP].options] == ["MSS", "EOL"]


def test_stack_with_timestamps_off_uses_its_other_option_order(tmp_path):
    import random

    from scapy.layers.inet import TCP

    pk = pcapkit()
    off = {"base": "linux", "ts": False}
    stacks = {"10.0.0.5": off, "203.0.113.9": off}
    pkts = pk.set_tcp_stack(flowsynth_flow(tmp_path, pk), stacks, random.Random(1))
    for p in pkts[:2]:
        assert [o[0] for o in p[TCP].options] == pk.STACKS["linux"]["options_nots"]
    assert pkts[1][TCP].window == 64240


def test_remote_host_echoes_timestamps_it_has_received(tmp_path):
    import random

    from scapy.layers.inet import TCP

    pk = pcapkit()
    rng = random.Random(3)
    remote = {"203.0.113.9"}
    pkts = flowsynth_flow(tmp_path, pk, mss=1448)
    pk.restamp(
        pkts,
        1.7e9,
        lambda p, new, earlier: pk.reply_gap(p, earlier, remote, rng),
    )
    stacks = {"10.0.0.5": "linux", "203.0.113.9": "linux"}
    pkts = pk.set_tcp_stack(pkts, stacks, rng)
    sent = {}  # client TSval -> capture time
    for p in pkts:
        ts = dict(p[TCP].options).get("Timestamp")
        if p[TCP].sport == 49152:
            sent.setdefault(ts[0], float(p.time))
        elif ts and ts[1]:
            # the echoed value left the client at least ~an RTT earlier
            assert float(p.time) - sent[ts[1]] > 0.03


def test_scapy_helpers_take_an_rtt_range():
    import random

    pk = pcapkit()
    rng = random.Random(5)
    a = pk.Host("192.168.1.5", "02:00:00:00:00:01", stack="windows")
    b = pk.Host("203.0.113.9", "02:00:00:00:00:02", ttl=52, stack="linux")
    pkts, _ = pk.tcp_session(
        1.7e9, a, b, 50000, 80, [(">", b"hi"), ("<", b"yo")], rng, rtt=(0.03, 0.05)
    )
    gaps = [
        float(q.time) - float(p.time)
        for p, q in zip(pkts, pkts[1:], strict=False)
        if q["IP"].src == b.ip and p["IP"].src == a.ip
    ]
    assert gaps and all(0.03 <= g <= 0.05 for g in gaps) and len(set(gaps)) > 1
    (q, r), _ = pk.udp_exchange(
        1.7e9, a, b, 5353, 53, b"q", b"r", rng, rtt=(0.03, 0.05)
    )
    assert 0.03 <= float(r.time) - float(q.time) <= 0.05
    with pytest.raises(ValueError, match="needs rng"):
        pk.icmp_echo(1.7e9, a, b, 1, 1, b"x", None, rtt=(0.03, 0.05))


def test_tcp_session_first_flight_fits_a_synack_without_timestamps(tmp_path):
    import random

    from scapy.layers.inet import TCP
    from scapy.utils import wrpcap

    pk = pcapkit()
    a = pk.Host("192.168.1.5", "02:00:00:00:00:01", ttl=128, stack="windows")
    b = pk.Host("203.0.113.9", "02:00:00:00:00:02", ttl=52, stack="linux")
    pkts, _ = pk.tcp_session(
        1.7e9, a, b, 50000, 80, [(">", bytes(200000)), ("<", b"ok")], random.Random(2)
    )
    assert pkts[1][TCP].window == 64240  # Linux, no timestamps agreed
    wrpcap(str(tmp_path / "w.pcap"), pkts)
    codes = {f["code"] for f in pl.lint(str(tmp_path / "w.pcap"))["findings"]}
    assert "beyond-window" not in codes


def test_far_end_echoes_what_it_acks(tmp_path):
    import random

    from scapy.layers.inet import TCP

    pk = pcapkit()
    rng = random.Random(4)
    a = pk.Host("192.168.1.5", "02:00:00:00:00:01", stack="linux")
    b = pk.Host("203.0.113.9", "02:00:00:00:00:02", ttl=52, stack="linux")
    msgs = [(">", b"GET / HTTP/1.1\r\n\r\n"), ("<", bytes(20000))] * 3
    for n in range(6):
        pkts, _ = pk.tcp_session(
            1.7e9, a, b, 50000 + n, 80, msgs, rng, rtt=(0.038, 0.055)
        )
        sent = []  # (seq end, TSval) of the client's packets so far
        for p in pkts:
            tcp = p[TCP]
            ts = dict(tcp.options)["Timestamp"]
            if p["IP"].src == a.ip:
                end = (
                    tcp.seq + len(bytes(tcp.payload)) + bool(tcp.flags.S or tcp.flags.F)
                )
                sent.append((end % 2**32, ts[0]))
            elif tcp.flags.A:
                acked = [v for end, v in sent if (tcp.ack - end) % 2**32 < 2**31]
                # never older than the newest segment it acknowledges
                assert ts[1] >= max(acked)


def test_resent_syn_is_the_one_echoed():
    import random

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pk = pcapkit()

    def pkt(t, src, dst, sport, dport, flags, seq, ack=0, load=b""):
        p = (
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
        )
        if load:
            p = p / load
        p.time = t
        return p

    c, s = "10.0.0.5", "203.0.113.9"
    pkts = [
        pkt(1.7e9, c, s, 40000, 80, "S", 100),
        pkt(1.7e9 + 1, c, s, 40000, 80, "S", 100),
        pkt(1.7e9 + 1.045, s, c, 80, 40000, "SA", 500, 101),
        pkt(1.7e9 + 1.0453, c, s, 40000, 80, "A", 101, 501),
    ]
    stacks = {c: "linux", s: "linux"}
    out = pk.set_tcp_stack(pkts, stacks, random.Random(1))
    second = dict(out[1][TCP].options)["Timestamp"][0]
    assert dict(out[2][TCP].options)["Timestamp"][1] == second


def test_host_outside_stacks_gets_its_timestamps_echoed():
    import random

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pk = pcapkit()
    c, s = "10.0.0.5", "203.0.113.9"
    syn = (
        Ether()
        / IP(src=c, dst=s)
        / TCP(
            sport=40000,
            dport=80,
            flags="S",
            seq=100,
            options=[("MSS", 1460), ("Timestamp", (777, 0))],
        )
    )
    synack = (
        Ether()
        / IP(src=s, dst=c)
        / TCP(sport=80, dport=40000, flags="SA", seq=500, ack=101)
    )
    syn.time, synack.time = 1.7e9, 1.7e9 + 0.04
    out = pk.set_tcp_stack([syn, synack], {s: "linux"}, random.Random(1))
    opts = out[1][TCP].options
    assert dict(opts)["Timestamp"][1] == 777
    # no SACK to sit beside, so the timestamp gets its own NOP padding
    assert [o[0] for o in opts] == ["MSS", "NOP", "NOP", "Timestamp"]


def test_stack_profile_keeps_a_whole_profile_as_it_is():
    pk = pcapkit()
    win = pk.stack_profile("windows")
    assert pk.stack_profile(win) == win  # not merged onto linux
    assert "synack_window_nots" not in win
    assert pk.stack_profile({"window": 29200})["wscale"] == 7  # linux base
    # an options override alone is still merged onto linux
    opts = ["MSS", "NOP", "WScale", "SAckOK", "Timestamp"]
    assert pk.stack_profile({"options": opts})["ts"] is True
    assert pk.Host("10.0.0.1", "02:00:00:00:00:01", stack={"options": opts}).window


def test_reused_ports_raise(tmp_path):
    pk = pcapkit()
    pkts = flowsynth_flow(tmp_path, pk, size=100)
    import random

    with pytest.raises(ValueError, match="own source port"):
        pk.randomize_isns(pkts + pkts, random.Random(1))
    with pytest.raises(ValueError, match="own source port"):
        pk.teardown(pkts + pkts)


@pytest.mark.parametrize("server", ["windows", "linux", "macos"])
@pytest.mark.parametrize("client", ["windows", "linux", "macos"])
def test_tcp_session_big_first_message_stays_in_window(tmp_path, client, server):
    import random

    from scapy.utils import wrpcap

    pk = pcapkit()
    a = pk.Host("192.168.1.5", "02:00:00:00:00:01", stack=client)
    b = pk.Host("203.0.113.9", "02:00:00:00:00:02", ttl=52, stack=server)
    pkts, _ = pk.tcp_session(
        1.7e9, a, b, 50000, 80, [(">", bytes(100000)), ("<", b"ok")], random.Random(2)
    )
    wrpcap(str(tmp_path / "w.pcap"), pkts)
    codes = {f["code"] for f in pl.lint(str(tmp_path / "w.pcap"))["findings"]}
    assert "beyond-window" not in codes


def test_host_outside_stacks_echoes_the_rewritten_timestamps():
    import random

    from scapy.layers.inet import IP, TCP
    from scapy.layers.l2 import Ether

    pk = pcapkit()
    c, s = "10.0.0.5", "203.0.113.9"

    def pkt(t, src, dst, flags, seq, ack, ts):
        sport, dport = (40000, 80) if src == c else (80, 40000)
        opts = (
            [("MSS", 1460), ("Timestamp", ts)]
            if "S" in flags
            else [("NOP", None), ("NOP", None), ("Timestamp", ts)]
        )
        p = (
            Ether()
            / IP(src=src, dst=dst)
            / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, options=opts)
        )
        p.time = t
        return p

    pkts = [
        pkt(1.7e9, c, s, "S", 100, 0, (7000, 0)),
        pkt(1.7e9 + 0.04, s, c, "SA", 500, 101, (9000, 7000)),
        pkt(1.7e9 + 0.0403, c, s, "A", 101, 501, (7040, 9000)),
    ]
    out = pk.set_tcp_stack(pkts, {s: "linux"}, random.Random(1))
    server_ts = dict(out[1][TCP].options)["Timestamp"][0]
    assert server_ts != 9000
    client = dict(out[2][TCP].options)["Timestamp"]
    assert client == (7040, server_ts)  # own clock, the peer's new value


def test_http_message_frames_a_bodiless_response():
    pk = pcapkit()
    redirect = pk.http_message("HTTP/1.1 302 Found", [("Location", "/b")])
    assert b"Content-Length: 0\r\n" in redirect
    for line in ("HTTP/1.1 204 No Content", "HTTP/1.1 304 Not Modified"):
        assert b"Content-Length" not in pk.http_message(line, [])
    assert b"Content-Length" not in pk.http_message("GET / HTTP/1.1", [("Host", "a")])
    chunked = pk.http_message("HTTP/1.1 200 OK", [("Transfer-Encoding", "chunked")])
    assert b"Content-Length" not in chunked


def test_dns_name_with_a_trailing_dot():
    pk = pcapkit()
    assert pk.dns_messages(1, "a.example.") == pk.dns_messages(1, "a.example")
    with pytest.raises(ValueError, match="empty label"):
        pk.dns_messages(1, "a..example")


def test_compile_synth_raises_instead_of_keeping_a_stale_pcap(tmp_path):
    pk = pcapkit()
    pcap = tmp_path / "f.pcap"
    flowsynth_flow(tmp_path, pk, size=10)  # leaves a good f.pcap behind
    assert pcap.exists()
    bad = tmp_path / "bad.synth"
    # mixed IPv4 and IPv6 ends: Flowsynth prints CRITICAL and exits 0
    bad.write_text("flow f tcp 10.0.0.5:1000 > [2001:db8::1]:80 ( tcp.initialize; );\n")
    with pytest.raises(RuntimeError, match="Flowsynth failed"):
        pk.compile_synth(str(bad), str(pcap))
    assert not pcap.exists()


def test_flow_line_brackets_a_bare_ipv6_address():
    pk = pcapkit()
    macs = ("02:00:00:00:00:01", "02:00:00:00:00:02")
    line = pk.flow_line("f", "tcp", "2001:db8::5", 50000, "2001:db8::9", 80, *macs)
    assert "[2001:db8::5]:50000 > [2001:db8::9]:80" in line and "mss:1440" in line
    already = pk.flow_line("f", "tcp", "[2001:db8::5]", 1, "[2001:db8::9]", 2, *macs)
    assert "[[" not in already
