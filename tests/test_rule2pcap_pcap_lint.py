import itertools
import json

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from tests.rule2pcap_scripts import load

pl = load("pcap_lint")

CLIENT, SERVER = "10.1.2.3", "203.0.113.9"
CMAC, SMAC = "02:00:00:00:00:01", "02:00:00:00:00:02"
T0 = 1_700_000_000.0
IP_IDS = itertools.count(1000)


def pkt(src, dst, flags, seq, ack, data=b"", sport=49152, dport=80):
    smac, dmac = (CMAC, SMAC) if src == CLIENT else (SMAC, CMAC)
    if src != CLIENT:
        sport, dport = dport, sport
    p = (
        Ether(src=smac, dst=dmac)
        / IP(src=src, dst=dst, id=next(IP_IDS), ttl=128 if src == CLIENT else 52)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    )
    if "S" in flags:
        p[TCP].options = [("MSS", 1460)]
    if data:
        p = p / Raw(data)
    return p


def session(
    request=b"GET / HTTP/1.1\r\nHost: a\r\n\r\n", response=b"HTTP/1.1 200 OK\r\n\r\n"
):
    c, s = 1000, 5000
    pkts = [
        pkt(CLIENT, SERVER, "S", c, 0),
        pkt(SERVER, CLIENT, "SA", s, c + 1),
        pkt(CLIENT, SERVER, "A", c + 1, s + 1),
        pkt(CLIENT, SERVER, "PA", c + 1, s + 1, request),
        pkt(SERVER, CLIENT, "PA", s + 1, c + 1 + len(request), response),
        pkt(CLIENT, SERVER, "FA", c + 1 + len(request), s + 1 + len(response)),
        pkt(SERVER, CLIENT, "FA", s + 1 + len(response), c + 2 + len(request)),
        pkt(CLIENT, SERVER, "A", c + 2 + len(request), s + 2 + len(response)),
    ]
    return pkts


def write(tmp_path, pkts, name="x.pcap"):
    for i, p in enumerate(pkts):
        if p.time is None or float(p.time) < 1_000_000:
            p.time = T0 + i * 0.01
    path = tmp_path / name
    wrpcap(str(path), pkts)
    return str(path)


def stamp(pkts):
    for i, p in enumerate(pkts):
        p.time = T0 + i * 0.01
    return pkts


def codes(result):
    return {f["code"] for f in result["findings"]}


def test_clean_session_has_no_findings(tmp_path):
    result = pl.lint(write(tmp_path, stamp(session())))
    assert result["findings"] == []
    (flow,) = result["summary"]["flows"]
    assert flow["client"] == f"{CLIENT}:49152"
    assert flow["handshake"] is True and flow["teardown"] == "fin"
    assert result["summary"]["addresses"] == {
        "documentation": [SERVER],
        "private": [CLIENT],
    }


def test_group_bit_mac_is_an_error(tmp_path):
    pkts = stamp(session())
    pkts[0][Ether].src = "01:00:5e:00:00:01"
    assert "group-mac" in codes(pl.lint(write(tmp_path, pkts)))


def test_bad_checksum_is_an_error(tmp_path):
    pkts = stamp(session())
    pkts[3][TCP].chksum = 0x1234
    pkts[4][IP].chksum = 0x1234
    found = codes(pl.lint(write(tmp_path, pkts)))
    assert {"bad-tcp-checksum", "bad-ip-checksum"} <= found


def test_udp_zero_checksum_is_allowed(tmp_path):
    p = (
        Ether(src=CMAC, dst=SMAC)
        / IP(src=CLIENT, dst=SERVER)
        / UDP(sport=5353, dport=53, chksum=0)
        / Raw(b"x")
    )
    p.time = T0
    assert "bad-udp-checksum" not in codes(pl.lint(write(tmp_path, [p])))


def test_time_backwards_and_same_time(tmp_path):
    pkts = stamp(session())
    pkts[5].time = T0 - 5
    assert "time-backwards" in codes(pl.lint(write(tmp_path, pkts, "a.pcap")))
    for p in pkts:
        p.time = T0
    assert "same-time" in codes(pl.lint(write(tmp_path, pkts, "b.pcap")))


def test_midstream_and_no_teardown(tmp_path):
    pkts = stamp(session()[3:5])
    found = codes(pl.lint(write(tmp_path, pkts)))
    assert {"no-handshake", "no-teardown"} <= found


def test_sequence_gap(tmp_path):
    pkts = session()
    pkts[4][TCP].seq += 100
    found = codes(pl.lint(write(tmp_path, stamp(pkts))))
    assert "seq-gap" in found and "ack-unsent" not in found


def test_ack_of_unsent_data(tmp_path):
    pkts = session()
    pkts[5][TCP].ack += 100
    found = codes(pl.lint(write(tmp_path, stamp(pkts))))
    assert "ack-unsent" in found and "seq-gap" not in found


def test_segment_over_mss(tmp_path):
    pkts = stamp(session(response=b"A" * 1600))
    assert "over-mss" in codes(pl.lint(write(tmp_path, pkts)))


def test_public_address_is_info(tmp_path):
    p = (
        Ether(src=CMAC, dst=SMAC)
        / IP(src=CLIENT, dst="8.8.8.8")
        / UDP(sport=5353, dport=53)
        / Raw(b"x")
    )
    p.time = T0
    result = pl.lint(write(tmp_path, [p]))
    (finding,) = [f for f in result["findings"] if f["code"] == "public-address"]
    assert finding["level"] == "info" and "8.8.8.8" in finding["message"]


def test_main_exit_codes(tmp_path, capsys):
    clean = write(tmp_path, stamp(session()), "clean.pcap")
    assert pl.main([clean]) == 0
    json.loads(capsys.readouterr().out)
    midstream = write(tmp_path, stamp(session()[3:5]), "mid.pcap")
    assert pl.main([midstream]) == 0
    assert pl.main([midstream, "--strict"]) == 1
    capsys.readouterr()
    assert pl.main([str(tmp_path / "missing.pcap")]) == 2


def test_constant_ip_id_and_ttl_64(tmp_path):
    pkts = stamp(session())
    for p in pkts:
        p[IP].id, p[IP].ttl = 1, 64
    found = codes(pl.lint(write(tmp_path, pkts)))
    assert {"constant-ip-id", "ttl-64"} <= found


def test_frames_listing(tmp_path, capsys):
    path = write(tmp_path, stamp(session()))
    rows = pl.frames(path)
    assert [r["flags"] for r in rows[:3]] == ["S", "SA", "A"]
    assert rows[3]["payload"].startswith("GET / HTTP/1.1..Host")
    assert rows[3]["src"] == f"{CLIENT}:49152"
    assert pl.main([path, "--frames"]) == 0
    listing = json.loads(capsys.readouterr().out)  # one JSON document
    assert listing["frames"] == rows and listing["frames"][0]["frame"] == 1


def test_mixed_ipv4_and_ipv6_addresses(tmp_path):
    # public addresses of both versions used to crash the sort
    def dns(ip):
        return Ether(src=CMAC, dst=SMAC) / ip / UDP(sport=5353, dport=53) / Raw(b"x")

    pkts = [
        dns(IP(src="198.18.0.1", dst="9.9.9.9")),
        dns(IPv6(src="2001:4860::1", dst="2606:4700::1")),
    ]
    result = pl.lint(write(tmp_path, stamp(pkts)))
    assert "public-address" in codes(result)
    assert result["summary"]["addresses"]["public"][-1] == "2606:4700::1"


def test_data_past_the_receive_window(tmp_path):
    pkts = session(request=b"A" * 1200)
    pkts[1][TCP].window = 1000  # the SYN/ACK offers 1000 bytes, unscaled
    assert "beyond-window" in codes(pl.lint(write(tmp_path, stamp(pkts))))
    pkts[1][TCP].window = 1200
    assert "beyond-window" not in codes(pl.lint(write(tmp_path, stamp(pkts), "y.pcap")))


def test_syn_without_options_is_flagged(tmp_path):
    pkts = stamp(session())
    pkts[0][TCP].options = []
    result = pl.lint(write(tmp_path, pkts))
    (bare,) = [f for f in result["findings"] if f["code"] == "bare-syn"]
    assert bare["level"] == "warning" and bare["frames"] == [1]


def test_second_connection_on_the_same_ports_is_flagged(tmp_path):
    still_open = session()[:5]  # no FINs yet
    pkts = stamp(still_open + session())
    assert "reused-tuple" in codes(pl.lint(write(tmp_path, pkts)))
    # a resent SYN before the SYN/ACK is not a new connection
    again = session()
    pkts = stamp(again[:1] + again)
    assert "reused-tuple" not in codes(pl.lint(write(tmp_path, pkts, "y.pcap")))
    # nor is a new connection after the old one closed
    closed = session()[:-1]  # FINs both ways, the last ACK lost
    pkts = stamp(closed + session())
    assert "reused-tuple" not in codes(pl.lint(write(tmp_path, pkts, "z.pcap")))
