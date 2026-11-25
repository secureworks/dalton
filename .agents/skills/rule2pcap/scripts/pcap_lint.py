#!/usr/bin/env python3
"""Check a generated pcap for the mistakes that make it unrealistic.

Usage:
    pcap_lint.py PCAP [--strict]

Prints JSON: a summary (packets, duration, flows, addresses) and a list of
findings, each with a level (error, warning, info), a code, a message and
the frame numbers involved (1-based, as Wireshark numbers them).

Errors are things a real capture can't contain or that break analysis:
group-bit source MACs, bad checksums, time running backwards. Warnings are
things real traffic rarely does: no TCP handshake, sequence gaps, segments
over the MSS. Info is context: public addresses, no teardown.

Exit code 1 if there are errors (or warnings, with --strict).
Needs scapy (see requirements.txt).
"""

import argparse
import datetime
import ipaddress
import json
import logging
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

DOC_NETS = [
    ipaddress.ip_network(n)
    for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
]
MAX_FRAME = 1514
DEFAULT_MSS = {4: 1460, 6: 1440}
EPOCH_2000 = 946684800
SEQ_MOD = 2**32


def address_key(address):
    """Sort key for a mix of IPv4 and IPv6 addresses (which don't compare)."""
    ip = ipaddress.ip_address(address)
    return (ip.version, ip)


def seq_after(a, b):
    """True if sequence number a is after b, allowing for wraparound."""
    return a != b and (a - b) % SEQ_MOD < 2**31


class Lint:
    def __init__(self):
        self.findings = {}

    def add(self, level, code, message, frame=None):
        key = (level, code, message)
        entry = self.findings.setdefault(
            key, {"level": level, "code": code, "message": message, "frames": []}
        )
        if frame is not None and len(entry["frames"]) < 20:
            entry["frames"].append(frame)

    def results(self):
        order = {"error": 0, "warning": 1, "info": 2}
        return sorted(self.findings.values(), key=lambda f: order[f["level"]])


def classify(addr):
    ip = ipaddress.ip_address(addr)
    if any(ip in net for net in DOC_NETS):
        return "documentation"
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return "special"
    if ip.is_private:
        return "private"
    if ip.version == 4 and ip == ipaddress.ip_address("255.255.255.255"):
        return "special"
    return "public"


def mac_is_group(mac):
    return int(mac.split(":")[0], 16) & 1 == 1


def l3(pkt):
    if IP in pkt:
        return pkt[IP]
    if IPv6 in pkt:
        return pkt[IPv6]
    return None


def checksum_ok(layer_pkt, layer):
    """Rebuild the packet from its IP layer and compare one checksum."""
    original = layer_pkt[layer].chksum
    clone = layer_pkt.copy()
    clone[layer].chksum = None
    rebuilt = clone.__class__(bytes(clone))
    return layer in rebuilt and rebuilt[layer].chksum == original


def tcp_payload_len(ip, tcp):
    if ip.version == 4:
        return ip.len - ip.ihl * 4 - tcp.dataofs * 4
    return ip.plen - tcp.dataofs * 4


def lint(path, now=None):
    now = now or datetime.datetime.now(datetime.timezone.utc).timestamp()
    out = Lint()
    flows = {}
    addresses = {}
    ip_macs = {}
    ip_ids = {}
    ip_ttls = {}
    times = []
    frame = 0
    linktypes = set()

    with PcapReader(path) as reader:
        linktype = getattr(reader, "linktype", None)
        for pkt in reader:
            frame += 1
            ts = float(pkt.time)
            if times and ts < times[-1]:
                out.add("error", "time-backwards", "timestamp goes backwards", frame)
            times.append(ts)
            linktypes.add(linktype)

            if len(bytes(pkt)) > MAX_FRAME + (4 if pkt.haslayer("Dot1Q") else 0):
                out.add(
                    "warning",
                    "jumbo-frame",
                    f"frame larger than {MAX_FRAME} bytes; a real NIC with a "
                    "1500 MTU would not capture this",
                    frame,
                )
            ip = l3(pkt)
            if Ether in pkt:
                src, dst = pkt[Ether].src.lower(), pkt[Ether].dst.lower()
                if mac_is_group(src):
                    out.add(
                        "error",
                        "group-mac",
                        f"source MAC {src} has the group (multicast) bit set",
                        frame,
                    )
                if src == "00:00:00:00:00:00":
                    out.add("error", "zero-mac", "source MAC is all zeros", frame)
                if ip is not None and mac_is_group(dst):
                    kind = classify(ip.dst)
                    if kind != "special" and ip.dst != "255.255.255.255":
                        out.add(
                            "warning",
                            "group-dst-mac",
                            f"unicast IP {ip.dst} sent to group MAC {dst}",
                            frame,
                        )
                if ip is not None:
                    ip_macs.setdefault(ip.src, set()).add(src)
            if ip is None:
                continue
            for addr in (ip.src, ip.dst):
                addresses.setdefault(classify(addr), set()).add(addr)
            if ip.version == 4:
                ip_ids.setdefault(ip.src, []).append(ip.id)
                ip_ttls.setdefault(ip.src, set()).add(ip.ttl)

            truncated = pkt.wirelen is not None and pkt.wirelen > len(bytes(pkt))
            fragment = ip.version == 4 and (ip.flags.MF or ip.frag > 0)
            if ip.version == 4 and not truncated and not checksum_ok(ip, IP):
                out.add("error", "bad-ip-checksum", "bad IPv4 header checksum", frame)
            for layer in (TCP, UDP, ICMP):
                if layer in ip and not truncated and not fragment:
                    if layer is UDP and ip[UDP].chksum == 0 and ip.version == 4:
                        continue
                    if not checksum_ok(ip, layer):
                        name = layer.__name__
                        out.add(
                            "error",
                            f"bad-{name.lower()}-checksum",
                            f"bad {name} checksum",
                            frame,
                        )
            if TCP in ip and not fragment:
                track_tcp(out, flows, frame, ts, ip, ip[TCP])
            elif UDP in ip and not fragment:
                track_udp(flows, ts, ip, ip[UDP])

    finish_flows(out, flows)
    if not times:
        out.add("error", "empty", "pcap has no packets")
    else:
        if len(times) > 1 and times[0] == times[-1]:
            out.add("warning", "same-time", "every packet has the same timestamp")
        if times[0] < EPOCH_2000:
            out.add("info", "old-time", "timestamps are before 2000")
        if times[-1] > now + 86400:
            out.add("warning", "future-time", "timestamps are in the future")
    for addr, macs in sorted(ip_macs.items()):
        if len(macs) > 1:
            out.add(
                "info",
                "ip-many-macs",
                f"{addr} is sent from {len(macs)} MACs ({', '.join(sorted(macs))})",
            )
    for addr, ids in sorted(ip_ids.items()):
        if len(ids) > 2 and len(set(ids)) == 1:
            out.add(
                "warning",
                "constant-ip-id",
                f"every packet from {addr} has IP ID {ids[0]}; real stacks vary "
                "it (pcapkit.set_ip_fields)",
            )
    remote = {
        a for kind in ("public", "documentation") for a in addresses.get(kind, set())
    }
    ttls = {t for v in ip_ttls.values() for t in v}
    if remote and ttls == {64} and len(ip_ttls) > 1:
        out.add(
            "info",
            "ttl-64",
            "every host sends with TTL 64, including remote ones that should "
            "arrive a few hops lower (Flowsynth's default; pcapkit.set_ip_fields)",
        )
    public = sorted(addresses.get("public", set()), key=address_key)
    if public:
        out.add(
            "info",
            "public-address",
            "public addresses outside the documentation ranges: "
            f"{', '.join(public)}. Fine for well-known services; otherwise use "
            "192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 or 2001:db8::/32",
        )
    summary = {
        "pcap": path,
        "packets": len(times),
        "duration": round(times[-1] - times[0], 6) if times else 0,
        "start": iso(times[0]) if times else None,
        "end": iso(times[-1]) if times else None,
        "flows": [flow_summary(f) for f in flows.values()],
        "addresses": {
            k: sorted(v, key=address_key) for k, v in sorted(addresses.items())
        },
    }
    if linktypes - {1, None}:
        summary["linktypes"] = sorted(x for x in linktypes if x is not None)
    return {"summary": summary, "findings": out.results()}


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).isoformat()


def flow_key(proto, ip, sport, dport):
    a, b = (ip.src, sport), (ip.dst, dport)
    return (proto,) + (a + b if a <= b else b + a)


def track_udp(flows, ts, ip, udp):
    key = flow_key("udp", ip, udp.sport, udp.dport)
    flow = flows.get(key)
    if flow is None:
        flow = flows[key] = new_flow("udp", (ip.src, udp.sport), (ip.dst, udp.dport))
    side = "c" if (ip.src, udp.sport) == flow["client"] else "s"
    flow["packets"] += 1
    flow["bytes"][side] += len(bytes(udp.payload))


def new_flow(proto, client, server):
    return {
        "proto": proto,
        "client": client,
        "server": server,
        "packets": 0,
        "bytes": {"c": 0, "s": 0},
        "syn": False,
        "synack": False,
        "fin": False,
        "rst": False,
        "next": {"c": None, "s": None},
        "mss": {"c": None, "s": None},
        "wscale": {"c": None, "s": None},
        # right edge of the receive window each side last offered
        "edge": {"c": None, "s": None},
        "data_before_handshake": None,
        "bare_syn": False,
        "reused": False,
        "first_frame": None,
    }


def track_tcp(out, flows, frame, ts, ip, tcp):
    key = flow_key("tcp", ip, tcp.sport, tcp.dport)
    flags = tcp.flags
    flow = flows.get(key)
    if flow is None:
        client, server = (ip.src, tcp.sport), (ip.dst, tcp.dport)
        if flags.S and flags.A:
            client, server = server, client
        flow = flows[key] = new_flow("tcp", client, server)
        flow["first_frame"] = frame
    side = "c" if (ip.src, tcp.sport) == flow["client"] else "s"
    other = "s" if side == "c" else "c"
    flow["packets"] += 1
    plen = max(tcp_payload_len(ip, tcp), 0)
    flow["bytes"][side] += plen

    if flags.S:
        if flags.A:
            flow["synack"] = True
        else:
            # a new SYN while the old connection is still open
            if (
                flow["synack"]
                and not (flow["fin"] or flow["rst"])
                and not flow["reused"]
            ):
                flow["reused"] = True
                out.add(
                    "warning",
                    "reused-tuple",
                    "a new SYN on a connection already open on the same "
                    "addresses and ports: Suricata treats it as part of the "
                    "old one and may never inspect the new data. Give each "
                    "connection its own source port",
                    frame,
                )
            flow["syn"] = True
        if not tcp.options:
            flow["bare_syn"] = True
        for opt in tcp.options or []:
            if opt[0] == "MSS":
                flow["mss"][side] = opt[1]
            if opt[0] == "WScale":
                flow["wscale"][side] = opt[1]
    if flags.F:
        flow["fin"] = True
    if flags.R:
        flow["rst"] = True

    mss = flow["mss"][other] or DEFAULT_MSS[ip.version]
    if plen > mss:
        out.add(
            "warning",
            "over-mss",
            f"TCP segment of {plen} bytes is over the {mss}-byte MSS",
            frame,
        )
    if plen and not (flow["syn"] and flow["synack"]):
        if flow["data_before_handshake"] is None:
            flow["data_before_handshake"] = frame

    seg_len = plen + (1 if flags.S else 0) + (1 if flags.F else 0)
    expected = flow["next"][side]
    if expected is None or flags.S:
        flow["next"][side] = (tcp.seq + seg_len) % SEQ_MOD
    else:
        if seq_after(tcp.seq, expected):
            gap = (tcp.seq - expected) % SEQ_MOD
            out.add(
                "warning",
                "seq-gap",
                f"{gap} bytes missing before this segment (sequence gap)",
                frame,
            )
        elif seq_after(expected, tcp.seq) and plen:
            out.add(
                "info",
                "retransmission",
                "segment repeats data already sent (retransmission or overlap)",
                frame,
            )
        end = (tcp.seq + seg_len) % SEQ_MOD
        if seq_after(end, expected):
            flow["next"][side] = end
    edge = flow["edge"][other]
    if plen and edge is not None:
        over = (tcp.seq + plen - edge) % SEQ_MOD
        if 0 < over < 2**31:
            out.add(
                "warning",
                "beyond-window",
                "segment runs past the receive window the other side offered; "
                "Suricata may drop the excess without logging an anomaly, "
                "truncating the stream. ACK the data in window-sized flights",
                frame,
            )
    if flags.A:
        # a SYN's window is never scaled; later ones are, if both sides
        # offered window scaling
        both = None not in flow["wscale"].values()
        shift = flow["wscale"][side] if both and not flags.S else 0
        flow["edge"][side] = (tcp.ack + (tcp.window << shift)) % SEQ_MOD
    peer_next = flow["next"][other]
    if flags.A and peer_next is not None and seq_after(tcp.ack, peer_next):
        out.add(
            "warning",
            "ack-unsent",
            "ACK acknowledges data the other side never sent",
            frame,
        )


def finish_flows(out, flows):
    for flow in flows.values():
        if flow["proto"] == "tcp" and flow["bare_syn"]:
            out.add(
                "warning",
                "bare-syn",
                "TCP flow opens with a SYN or SYN/ACK that has no options; "
                "every real stack sends at least MSS (Flowsynth's default). "
                "Use pcapkit.set_tcp_stack()",
                flow["first_frame"],
            )
    for flow in flows.values():
        if flow["proto"] != "tcp":
            continue
        name = endpoint_pair(flow)
        frame = flow["first_frame"]
        if not flow["syn"] or not flow["synack"]:
            missing = "SYN" if not flow["syn"] else "SYN/ACK"
            out.add(
                "warning",
                "no-handshake",
                f"{name}: no {missing}; with stream.midstream off (the "
                "default) Suricata won't track the session, so stream and "
                "app-layer detection don't run",
                frame,
            )
        elif flow["data_before_handshake"]:
            out.add(
                "warning",
                "data-before-handshake",
                f"{name}: data sent before the handshake finished",
                flow["data_before_handshake"],
            )
        if not flow["fin"] and not flow["rst"]:
            out.add(
                "info",
                "no-teardown",
                f"{name}: no FIN or RST. The last data may only be inspected "
                "when the flow times out or the pcap ends, which can reorder "
                "alerts against rules that inspect earlier",
                frame,
            )


def endpoint_pair(flow):
    (ca, cp), (sa, sp) = flow["client"], flow["server"]
    return f"{ca}:{cp} -> {sa}:{sp}"


def flow_summary(flow):
    summary = {
        "proto": flow["proto"],
        "client": f"{flow['client'][0]}:{flow['client'][1]}",
        "server": f"{flow['server'][0]}:{flow['server'][1]}",
        "packets": flow["packets"],
        "bytes_to_server": flow["bytes"]["c"],
        "bytes_to_client": flow["bytes"]["s"],
    }
    if flow["proto"] == "tcp":
        summary["handshake"] = flow["syn"] and flow["synack"]
        summary["teardown"] = "fin" if flow["fin"] else "rst" if flow["rst"] else None
    return summary


def frames(path, width=48):
    """One line per frame: number, time offset, endpoints, flags, payload."""
    rows, t0 = [], None
    with PcapReader(path) as reader:
        for n, pkt in enumerate(reader, 1):
            ts = float(pkt.time)
            t0 = ts if t0 is None else t0
            ip = l3(pkt)
            row = {"frame": n, "t": round(ts - t0, 6)}
            if ip is None:
                row["summary"] = pkt.summary()
                rows.append(row)
                continue
            proto, sport, dport, flags, data = "ip", "", "", "", b""
            for layer in (TCP, UDP, ICMP):
                if layer in ip:
                    proto = layer.__name__.lower()
                    l4 = ip[layer]
                    if layer is ICMP:
                        flags = f"type {l4.type} code {l4.code}"
                        data = bytes(l4.payload)
                    else:
                        sport, dport = l4.sport, l4.dport
                        data = bytes(l4.payload)
                    if layer is TCP:
                        flags = str(l4.flags)
                        data = data[: max(tcp_payload_len(ip, l4), 0)]
                    break
            row.update(
                src=f"{ip.src}:{sport}" if sport != "" else ip.src,
                dst=f"{ip.dst}:{dport}" if dport != "" else ip.dst,
                proto=proto,
                flags=flags,
                len=len(data),
                payload=data[:width].decode("latin-1").translate(PRINTABLE),
            )
            rows.append(row)
    return rows


PRINTABLE = {i: "." for i in range(256) if not 0x20 <= i < 0x7F}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("pcap")
    parser.add_argument(
        "--strict", action="store_true", help="fail on warnings as well as errors"
    )
    parser.add_argument(
        "--frames",
        action="store_true",
        help="list every frame (number, time, endpoints, flags, payload start) "
        "instead of linting; for the README's frame table",
    )
    args = parser.parse_args(argv)
    if args.frames:
        try:
            rows = frames(args.pcap)
        except (OSError, ValueError) as exc:
            print(json.dumps({"error": f"cannot read {args.pcap}: {exc}"}))
            return 2
        print(json.dumps({"pcap": args.pcap, "frames": rows}, indent=1))
        return 0
    try:
        result = lint(args.pcap)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": f"cannot read {args.pcap}: {exc}"}))
        return 2
    print(json.dumps(result, indent=2))
    levels = {f["level"] for f in result["findings"]}
    if "error" in levels or (args.strict and "warning" in levels):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
