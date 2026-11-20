"""Helpers for rule2pcap build scripts.

Copy this file next to build.py in the output directory, so the build stays
standalone. build.py adds its own directory to sys.path, because the build
runs with python -I, which leaves the script's directory off the path.

Sections:
  payloads     esc, dns_messages, http_date, http_message, inert_pe
  flowsynth    flow_line, event_line, compile_synth
  post-process restamp, reply_gap, randomize_isns, teardown, set_tcp_stack,
               set_ip_fields, rebuild (for Flowsynth output; in that order)
  scapy        Host, frame, tcp_session, udp_exchange, icmp_echo
  tls          mint_cert, mint_chain, tls_flights
"""

import datetime
import os
import struct
import subprocess
import sys

from scapy.all import ICMP, IP, TCP, UDP, Ether, IPv6, Raw

SEQ_MOD = 2**32
# Ephemeral (client) port ranges: Windows, and Linux's default.
WINDOWS_PORTS = (49152, 65535)
LINUX_PORTS = (32768, 60999)


# ---------------------------------------------------------------- payloads


def esc(data: bytes) -> str:
    """Escape bytes for a Flowsynth content string.

    Flowsynth tokenises with shlex and only understands \\xHH escapes, so
    anything outside plain ASCII text becomes \\xHH.
    """
    ok = set(
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /.:,=-_()*&?%"
    )
    return "".join(chr(c) if c in ok else f"\\x{c:02x}" for c in data)


QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28}


def dns_messages(txid, name, addr=None, ttl=300, qtype="A", rcode=0):
    """A DNS query and its response, as UDP payloads.

    qtype "A" with an IPv4 addr, or "AAAA" with an IPv6 one, gives one
    answer record. addr=None gives an empty answer: NODATA with rcode=0, or
    NXDOMAIN with rcode=3. Other answer types aren't built here.
    """
    import ipaddress

    if addr is not None:
        version = ipaddress.ip_address(addr).version
        if (qtype, version) not in (("A", 4), ("AAAA", 6)):
            raise ValueError(f"qtype {qtype} can't answer with {addr}")

    labels = name.rstrip(".").split(".")  # a trailing dot is the root
    if not all(labels):
        raise ValueError(f"empty label in DNS name {name!r}")
    qname = b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\0"
    question = qname + struct.pack(">HH", QTYPES[qtype], 1)
    query = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + question
    answers = b""
    if addr is not None:
        rdata = ipaddress.ip_address(addr).packed
        answers = (
            struct.pack(">HHHIH", 0xC00C, QTYPES[qtype], 1, ttl, len(rdata)) + rdata
        )
    flags = 0x8180 | (rcode & 0xF)
    reply = (
        struct.pack(">HHHHHH", txid, flags, 1, 1 if answers else 0, 0, 0)
        + question
        + answers
    )
    return query, reply


def http_date(dt):
    return dt.strftime("%a, %d %b %Y %H:%M:%S GMT")


def http_message(start_line, headers, body=b""):
    """An HTTP/1.x message from a start line and (name, value) pairs.

    Content-Length is added when there's no length header and either
    there's a body or it's a response that could carry one: without it, a
    keep-alive parser reads the next response as this one's body. For a
    response to HEAD, pass the length the GET's body would have.
    """
    lines = [start_line] + [f"{k}: {v}" for k, v in headers]
    framed = any(
        k.lower() in ("content-length", "transfer-encoding") for k, _ in headers
    )
    status = start_line.split()[1] if start_line.startswith("HTTP/") else None
    bodiless = status is not None and (status[:1] == "1" or status in ("204", "304"))
    if not framed and (body or (status is not None and not bodiless)):
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def inert_pe(size=4096, e_lfanew=0x80, rng=None, dll=False):
    """Bytes shaped like a Windows PE file that can't run.

    A standard DOS header (the usual MZ field values and stub, so it looks
    like a linker's output and base64 of it starts "TVqQAAMAAAAEAAAA//8AALgA"),
    the PE signature at e_lfanew, an i386 COFF header, a PE32 optional
    header (Windows GUI subsystem; libmagic and Suricata's filemagic call it
    "PE32 executable" or "PE32 executable (DLL)"), one .text section header,
    then filler. The .text section has no bytes in the file, so the entry
    point lands on zero-filled memory: there's no code to run. Filler is
    seeded random bytes when rng is given, zeros otherwise.
    """
    dos = struct.pack(
        "<2s13H8s2H20sI",
        b"MZ",
        0x0090,  # e_cblp
        0x0003,  # e_cp
        0,  # e_crlc
        0x0004,  # e_cparhdr
        0,  # e_minalloc
        0xFFFF,  # e_maxalloc
        0,  # e_ss
        0x00B8,  # e_sp
        0,  # e_csum
        0,  # e_ip
        0,  # e_cs
        0x0040,  # e_lfarlc
        0,  # e_ovno
        bytes(8),  # e_res
        0,  # e_oemid
        0,  # e_oeminfo
        bytes(20),  # e_res2
        e_lfanew,
    )
    dos += b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos += b"This program cannot be run in DOS mode.\r\r\n$"
    dos = dos[:e_lfanew].ljust(e_lfanew, b"\0")
    characteristics = 0x0102 | (0x2000 if dll else 0)  # executable, 32-bit (+DLL)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,  # PE32
        14,  # linker version 14.0 (Visual Studio 2015+)
        0,
        0,  # size of code: none in the file
        0,
        0,
        0x1000,  # entry point: the start of an empty .text
        0x1000,  # base of code
        0x2000,  # base of data
        0x10000000 if dll else 0x00400000,  # image base
        0x1000,  # section alignment
        0x200,  # file alignment
        6,  # OS version 6.0
        0,
        0,
        0,
        6,  # subsystem version 6.0
        0,
        0,
        0x2000,  # size of image
        0x400,  # size of headers
        0,  # checksum
        2,  # subsystem: Windows GUI
        0x8140,  # DYNAMIC_BASE, NX_COMPAT, TERMINAL_SERVER_AWARE
        0x100000,  # stack reserve
        0x1000,
        0x100000,  # heap reserve
        0x1000,
        0,
        16,  # data directories, all empty
    ) + bytes(16 * 8)
    coff = struct.pack(
        "<4sHHIIIHH",
        b"PE\0\0",
        0x014C,
        1,
        0x5E2A1C00,
        0,
        0,
        len(optional),
        characteristics,
    )
    text = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        0x1000,  # virtual size
        0x1000,  # virtual address
        0,  # raw size: no bytes in the file
        0,  # raw pointer
        0,
        0,
        0,
        0,
        0x60000020,  # code, execute, read
    )
    body = dos + coff + optional + text
    filler = size - len(body)
    if filler > 0:
        body += (
            bytes(rng.randrange(256) for _ in range(filler)) if rng else bytes(filler)
        )
    return body


# --------------------------------------------------------------- flowsynth


def flow_line(name, proto, src, sport, dst, dport, src_mac, dst_mac, mss=None):
    """A Flowsynth flow declaration with fixed MACs (never Flowsynth's own).

    TCP data is cut into mss-byte segments: 1460 over IPv4 and 1440 over
    IPv6 (Flowsynth's own 1460 makes oversized IPv6 frames) unless given.
    Pass 12 less (1448, 1428) when set_tcp_stack() will give both ends
    timestamps (pk.both_timestamp()); the option takes 12 bytes per segment.
    A bare IPv6 address is put in the brackets Flowsynth needs, so the same
    variable can key the IP maps (STACKS, ttl, WAN_HOSTS).
    """
    src, dst = (
        f"[{a}]" if ":" in a and not a.startswith("[") else a for a in (src, dst)
    )
    init = ""
    if proto == "tcp":
        mss = mss or (1440 if ":" in src.strip("[]") else 1460)
        init = f"tcp.initialize; mss:{mss}; "
    return f"flow {name} {proto} {src}:{sport} > {dst}:{dport} ( {init}src_mac:{src_mac}; dst_mac:{dst_mac}; );\n"


def event_line(name, direction, data):
    """A Flowsynth event: direction ">" (to server) or "<" (to client)."""
    return f'{name} {direction} ( content:"{esc(data)}"; );\n'


def compile_synth(synth, pcap):
    """Compile a .synth file to pcap. Flowsynth reports a syntax error and
    still exits 0, so the old pcap is removed first and any CRITICAL line
    raises RuntimeError: a failed build never reuses the last one."""
    if os.path.exists(pcap):
        os.remove(pcap)
    run = subprocess.run(
        [sys.executable, "-m", "flowsynth", "-f", "pcap", "-w", pcap, synth],
        capture_output=True,
        text=True,
    )
    output = run.stdout + run.stderr
    critical = [x for x in output.splitlines() if "CRITICAL" in x]
    if run.returncode or critical or not os.path.exists(pcap):
        detail = "; ".join(critical) or output.strip()[-500:] or "no pcap written"
        raise RuntimeError(f"Flowsynth failed on {synth}: {detail}")


# ------------------------------------------------------------ post-process


def l3(p):
    return p[IP] if IP in p else p[IPv6]


def payload_len(p):
    """Application payload length of a TCP or UDP packet."""
    ip = l3(p)
    if TCP in p:
        if IP in p:
            return ip.len - ip.ihl * 4 - p[TCP].dataofs * 4
        return ip.plen - p[TCP].dataofs * 4
    if UDP in p:
        return p[UDP].len - 8
    return len(bytes(ip.payload))


tcp_payload_len = payload_len


def endpoints(p):
    """((src ip, src port), (dst ip, dst port)); ports are None for ICMP."""
    for proto in (TCP, UDP):
        if proto in p:
            return (l3(p).src, p[proto].sport), (l3(p).dst, p[proto].dport)
    return (l3(p).src, None), (l3(p).dst, None)


def rebuild(q, when=None):
    """Recompute lengths and checksums after editing a packet."""
    when = q.time if when is None else when
    if IP in q:
        del q[IP].len, q[IP].chksum
    else:
        del q[IPv6].plen
    for proto in (TCP, UDP, ICMP):
        if proto in q:
            del q[proto].chksum
    q = q.__class__(bytes(q))
    q.time = when
    return q


def reply_gap(p, earlier, remote, rng, rtt=(0.035, 0.060), local=(0.0002, 0.0008)):
    """A plausible gap before packet p, seen from a capture point.

    earlier: the packets before p, oldest first (restamp passes them).
    remote: the set of IPs on the far side of the WAN from the capture
    point. A packet from a remote host that answers a local one arrives an
    RTT later; everything else (back-to-back segments of one flight, local
    replies) is sub-millisecond. Flowsynth ACKs every segment, so a local
    pure ACK between two remote data segments doesn't count as something
    answered. The reverse can't be fixed by timing alone: each remote ACK
    of a local multi-segment send still costs an RTT, so a big upload from
    the near side is slow. Build those with tcp_session instead. If the capture point is near the server (an inbound attack),
    the remote set is the outside client.
    """
    src = l3(p).src
    if (
        earlier
        and src in remote
        and l3(earlier[-1]).src not in remote
        and not continues_flight(p, earlier)
    ):
        return rng.uniform(*rtt)
    return rng.uniform(*local)


def continues_flight(p, earlier):
    """True if TCP data p follows its sender's own data with only pure ACKs
    from the other end in between: the same flight, not an answer."""
    if TCP not in p or not bytes(p[TCP].payload):
        return False
    key, src = frozenset(endpoints(p)), l3(p).src
    for q in reversed(earlier):
        if TCP not in q or frozenset(endpoints(q)) != key:
            return False
        if l3(q).src == src:
            return bool(bytes(q[TCP].payload)) and not q[TCP].flags.F
        if bytes(q[TCP].payload) or q[TCP].flags != "A":
            return False
    return False


def restamp(pkts, start, gap):
    """Replace Flowsynth's wall-clock stamps.

    gap(packet, new_flow, earlier) returns the seconds since the previous
    packet; new_flow is True for the first packet of a flow and earlier is
    the list of packets before it in the capture, oldest first
    (earlier[-1] is the previous one). The first packet is stamped exactly
    at start.
    """
    seen, earlier = set(), []
    t = start.timestamp() if isinstance(start, datetime.datetime) else start
    for p in pkts:
        key = frozenset(endpoints(p))
        if earlier:
            t += gap(p, key not in seen, earlier)
        seen.add(key)
        p.time = t
        earlier.append(p)


def check_one_connection_per_tuple(pkts):
    """Raise ValueError if a SYN opens a second connection on addresses and
    ports an earlier connection used: the helpers here, and Suricata,
    would treat both as one flow. A resent SYN before the SYN/ACK is fine."""
    answered = set()
    for p in pkts:
        if TCP not in p or not p[TCP].flags.S:
            continue
        src, dst = endpoints(p)
        if p[TCP].flags.A:
            answered.add(frozenset((src, dst)))
        elif frozenset((src, dst)) in answered:
            raise ValueError(
                f"two TCP connections on {src[0]}:{src[1]} -> {dst[0]}:{dst[1]}; "
                "give each connection its own source port"
            )


def randomize_isns(pkts, rng):
    """Give each TCP flow seeded random ISNs.

    Flowsynth 1.4's tcp.initialize starts every flow at ISN 10 (client) and
    100 (server), which no real stack does. Raises ValueError if two
    connections share addresses and ports.
    """
    check_one_connection_per_tuple(pkts)
    offsets, out = {}, []
    for p in pkts:
        if TCP not in p:
            out.append(p)
            continue
        src, dst = endpoints(p)
        key = frozenset((src, dst))
        for side in (src, dst):
            offsets.setdefault((key, side), rng.randrange(SEQ_MOD))
        q = p.copy()
        q[TCP].seq = (q[TCP].seq + offsets[(key, src)]) % SEQ_MOD
        if q[TCP].flags.A:
            q[TCP].ack = (q[TCP].ack + offsets[(key, dst)]) % SEQ_MOD
        out.append(rebuild(q, p.time))
    return out


def draw_rtt(rtt, rng):
    """One round trip: rtt as is if it's a number, else drawn from its
    (low, high) range."""
    if isinstance(rtt, (int, float)):
        return rtt
    if rng is None:
        raise ValueError("an rtt range needs rng")
    return rng.uniform(*rtt)


def teardown(
    pkts, closer="server", idle=0.2, rtt=0.045, capture="client", remote=None, rng=None
):
    """Add a FIN, ACK, FIN, ACK close to every TCP flow that has none.

    Flowsynth 1.4 emits no teardown. Without one, data at the end of a flow
    is inspected only when the flow times out, after rules that ran earlier.

    closer is "server" or "client". The first FIN comes `idle` seconds after
    the flow's last packet: about 0.2 s for a client that closes when it's
    done, the server's keep-alive timeout (often 5 s or more) for a server
    that closes an idle connection, and under a millisecond for a server
    closing right after a `Connection: close` response. Inspection of the
    last data in the flow can wait for this close, so the idle also sets
    when such an alert is logged.

    A packet from the far side that answers one from the near side shows up
    `rtt` later; everything else is sub-millisecond. rtt is seconds, or a
    (low, high) range drawn from rng: use the range the rest of the build
    uses. Which side is far: pass `remote`, the set of IPs across the WAN
    (the template's WAN_HOSTS), and a flow with no remote end is all local.
    Without it, `capture` says where the capture point is: "client" (the
    default, an inside host calling out) or "server" (an inbound attack
    seen on the server's LAN).

    The new packets copy their IP header from earlier ones: run
    set_ip_fields() afterwards so IP IDs stay unique.
    """
    draw_rtt(rtt, rng)  # fail early on a range without rng
    check_one_connection_per_tuple(pkts)
    flows = {}
    for p in pkts:
        if TCP in p:
            flows.setdefault(frozenset(endpoints(p)), []).append(p)
    added = []
    for flow in flows.values():
        if any(p[TCP].flags.F or p[TCP].flags.R for p in flow):
            continue
        client = endpoints(flow[0])[0]
        last, nxt = {}, {}
        for p in flow:
            side = endpoints(p)[0]
            last[side] = p
            nxt[side] = (
                p[TCP].seq + payload_len(p) + (1 if p[TCP].flags.S else 0)
            ) % SEQ_MOD
        server = next((s for s in last if s != client), None)
        if server is None:
            continue
        a, b = (server, client) if closer == "server" else (client, server)
        if remote is not None:
            far = next((e for e in (server, client) if e[0] in remote), None)
        else:
            far = server if capture == "client" else client

        def delay(side, far=far):
            if side != far:
                return 0.0003
            return draw_rtt(rtt, rng)

        t = max(float(p.time) for p in flow) + idle
        steps = (
            (a, "FA", nxt[a], nxt[b], 0),
            (b, "A", nxt[b], nxt[a] + 1, delay(b)),
            (b, "FA", nxt[b], nxt[a] + 1, 0.0002),
            (a, "A", nxt[a] + 1, nxt[b] + 1, delay(a)),
        )
        for side, flags, seq, ack, dt in steps:
            q = last[side].copy()
            q[TCP].flags, q[TCP].seq, q[TCP].ack = flags, seq % SEQ_MOD, ack % SEQ_MOD
            q[TCP].remove_payload()
            t += dt
            added.append(rebuild(q, t))
    return sorted(list(pkts) + added, key=lambda p: float(p.time))


def set_ip_fields(pkts, rng, ttl=None, df=True):
    """Set per-host TTLs and realistic IPv4 IDs, then fix checksums.

    Flowsynth stamps TTL 64 and IP ID 1 on every packet. ttl maps source
    IP -> TTL as seen at the capture point (local Windows 128, local Linux
    64, a remote host a few hops lower, e.g. 52 or 116). IDs start at a
    seeded random value per host and count up per packet, as Windows and
    most embedded stacks do. IPv4 only: IPv6 packets keep Flowsynth's hop
    limit of 64. Run this last, after teardown().
    """
    ttl = ttl or {}
    next_id = {}
    out = []
    for p in pkts:
        if IP not in p:
            out.append(p)
            continue
        q = p.copy()
        src = q[IP].src
        if src in ttl:
            q[IP].ttl = ttl[src]
        if src not in next_id:
            next_id[src] = rng.randrange(1, 65536)
        q[IP].id = next_id[src]
        next_id[src] = (next_id[src] % 65535) + 1
        if df:
            q[IP].flags = "DF"
        out.append(rebuild(q, p.time))
    return out


# TCP behaviour of common stacks, for set_tcp_stack() and Host(stack=...).
# syn_window / synack_window: the unscaled window field in a SYN and in a
# SYN/ACK (synack_window_nots when timestamps aren't agreed, if it
# differs). window: bytes offered once the handshake is done (the field is
# that, shifted right by wscale). options: SYN option order, used in the
# SYN/ACK too; options_nots: the order without timestamps (a SYN with ts
# off, or a SYN/ACK to a peer that offered none). Values are typical
# defaults; real hosts tune them.
STACKS = {
    "windows": {  # Windows 10/11, Server 2016+
        "syn_window": 64240,
        "synack_window": 65535,
        "window": 513 << 8,
        "wscale": 8,
        "ts": False,
        "options": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"],
        "options_nots": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"],
    },
    "linux": {  # kernel 4.x-6.x defaults
        "syn_window": 64240,
        "synack_window": 65160,  # 45 x 1448: Linux rounds to the MSS
        "synack_window_nots": 64240,  # 44 x 1460
        "window": 502 << 7,
        "wscale": 7,
        "ts": True,
        "options": ["MSS", "SAckOK", "Timestamp", "NOP", "WScale"],
        "options_nots": ["MSS", "NOP", "NOP", "SAckOK", "NOP", "WScale"],
    },
    "macos": {
        "syn_window": 65535,
        "synack_window": 65535,
        "window": 2048 << 6,
        "wscale": 6,
        "ts": True,
        "options": ["MSS", "NOP", "WScale", "NOP", "NOP", "Timestamp", "SAckOK", "EOL"],
        "options_nots": ["MSS", "NOP", "WScale", "SAckOK", "EOL"],
    },
}


def stack_profile(stack):
    """A STACKS entry by name, or a dict: STACKS[base] with overrides, e.g.
    {"base": "linux", "window": 29200}."""
    if isinstance(stack, str):
        return dict(STACKS[stack])
    stack = dict(stack)
    # a whole profile (one this returned before) stands on its own
    whole = set(STACKS["windows"]) <= set(stack)
    base = stack.pop("base", None if whole else "linux")
    return {**(STACKS[base] if base else {}), **stack}


def synack_window(prof, ts_ok):
    """The window a stack's SYN/ACK offers: some round it to the MSS less
    the timestamp option, so it depends on whether both ends use them."""
    if ts_ok:
        return prof["synack_window"]
    return prof.get("synack_window_nots", prof["synack_window"])


def both_timestamp(a, b):
    """True when two stacks (names, profiles or None) agree on timestamps.

    Their segments then carry a 12-byte timestamp option, so a full one has
    MSS - 12 bytes of data: compile Flowsynth with
    flow_line(..., mss=1448) (1428 over IPv6) for such a pair.
    """
    return bool(a and b and stack_profile(a)["ts"] and stack_profile(b)["ts"])


def _offers(p, name):
    return any(o[0] == name for o in p[TCP].options or [])


NEGOTIATED = ("WScale", "SAckOK", "Timestamp")
OPTION_SIZE = {"MSS": 4, "WScale": 3, "SAckOK": 2, "Timestamp": 10, "NOP": 1, "EOL": 1}


def _drop_options(names, drop):
    """names without those in drop, and without the NOPs that padded them.
    A timestamp left on a 4-byte boundary gets two NOPs in front, as real
    stacks align it."""
    out, pad = [], []
    for n in names:
        if n == "NOP":
            pad.append(n)
            continue
        if n not in drop:
            out += pad
            if n == "Timestamp" and sum(OPTION_SIZE[o] for o in out) % 4 == 0:
                out += ["NOP", "NOP"]
            out.append(n)
        pad = []
    return out


def _seq_end(p):
    """The sequence number just past a TCP packet's data, SYN or FIN; None
    for a packet with none of them, which no ACK acknowledges."""
    tcp = p[TCP]
    used = len(bytes(tcp.payload)) + bool(tcp.flags.S) + bool(tcp.flags.F)
    return (tcp.seq + used) % SEQ_MOD if used else None


def _covers(ack, end):
    """True when ack acknowledges everything before end (mod 2**32)."""
    return (ack - end) % SEQ_MOD < 2**31


def set_tcp_stack(pkts, stacks, rng, mss=None):
    """Give each host the TCP window and options of its OS.

    Flowsynth sends window 8192 and SYNs with no options at all, which no
    real stack does. stacks maps IP -> a STACKS name ("windows", "linux",
    "macos") or a stack_profile() dict; list every host that speaks TCP.
    SYNs and SYN/ACKs get the stack's options in its order (MSS, window
    scale, SACK, timestamps) and its unscaled window. Later packets get the
    window field shifted by the scale both sides agreed, and, when both
    offered timestamps, a timestamp option whose value counts milliseconds
    from a seeded start and echoes the peer's latest one this host has
    received (on a segment it ACKs, or captured an RTT earlier). MSS is
    the SYN's own MSS option if it has one, else mss, else 1460 (IPv4) or
    1440 (IPv6). When both ends of a flow use timestamps (both_timestamp()),
    data segments must leave 12 bytes for the option: compile Flowsynth
    with flow_line(..., mss=1448), or this raises ValueError. Run it after
    teardown() and before set_ip_fields().
    """
    profiles = {ip: stack_profile(v) for ip, v in stacks.items()}
    order = sorted(range(len(pkts)), key=lambda i: float(pkts[i].time))
    # what each side of each flow offered in its SYN, after rewriting, and
    # when each side's handshake packets were seen
    offered, syn_t, synack_t, first_t = {}, {}, {}, {}
    for i in order:
        p = pkts[i]
        if TCP not in p:
            continue
        src, dst = endpoints(p)
        when = float(p.time)
        if p[TCP].flags.S:
            if p[TCP].flags.A:
                synack_t.setdefault((src, dst), when)
            elif (dst, src) not in synack_t:
                syn_t[(src, dst)] = when  # the last SYN, if one was resent
            prof = profiles.get(src[0])
            if prof:
                names = prof["options"] if prof["ts"] else prof["options_nots"]
                offered[(src, dst)] = set(NEGOTIATED) & set(names)
            else:
                offered[(src, dst)] = {n for n in NEGOTIATED if _offers(p, n)}
        else:
            first_t.setdefault((src, dst), when)

    def lag(src, dst):
        """How long src took to answer dst in the handshake: an RTT for the
        far end, under a millisecond for the near one."""
        if (src, dst) in synack_t and (dst, src) in syn_t:
            gap = synack_t[(src, dst)] - syn_t[(dst, src)]
        elif (src, dst) in first_t and (dst, src) in synack_t:
            gap = first_t[(src, dst)] - synack_t[(dst, src)]
        else:
            return 0.0
        return gap if gap > 0.005 else 0.0

    tsval, t0, mss_of, seen = {}, {}, {}, {}
    out = list(pkts)
    for i in order:
        p = pkts[i]
        if TCP not in p:
            continue
        src, dst = endpoints(p)
        prof = profiles.get(src[0])
        mine = offered.get((src, dst), set())
        theirs = offered.get((dst, src), set())
        ws_ok = "WScale" in mine and "WScale" in theirs
        ts_ok = "Timestamp" in mine and "Timestamp" in theirs
        if (src, dst) not in tsval and prof:
            tsval[(src, dst)] = rng.randrange(1, 2**31)
            t0[(src, dst)] = float(p.time)
        now = float(p.time)
        # echo the peer's latest timestamp that has reached this host: one
        # on a segment this packet ACKs, or one captured long enough ago (the
        # far end sees the near end's packets about an RTT after capture)
        cutoff = now - 0.9 * lag(src, dst)
        echo = 0
        for at, v, end in reversed(seen.get((dst, src), [])):
            acked = end is not None and p[TCP].flags.A and _covers(p[TCP].ack, end)
            if at <= cutoff or acked:
                echo = v
                break
        if not prof:
            # a host left out of stacks keeps its own timestamps, but echoes
            # the peer's rewritten ones
            opts = p[TCP].options or []
            ts = dict(opts).get("Timestamp")
            if ts:
                seen.setdefault((src, dst), []).append((now, ts[0], _seq_end(p)))
                if dst[0] in profiles and not (p[TCP].flags.S and not p[TCP].flags.A):
                    q = p.copy()
                    q[TCP].options = [
                        (n, (v[0], echo)) if n == "Timestamp" else (n, v)
                        for n, v in opts
                    ]
                    out[i] = rebuild(q, p.time)
            continue
        q = p.copy()
        tcp = q[TCP]
        val = (tsval[(src, dst)] + int((now - t0[(src, dst)]) * 1000)) % SEQ_MOD
        if tcp.flags.S:
            seg = next((o[1] for o in tcp.options or [] if o[0] == "MSS"), None)
            seg = seg or mss or (1440 if IPv6 in q else 1460)
            mss_of[(src, dst)] = seg
            names = prof["options"] if prof["ts"] else prof["options_nots"]
            if tcp.flags.A:
                # a SYN/ACK offers only what the SYN did
                names = prof["options"] if ts_ok else prof["options_nots"]
                names = _drop_options(names, set(NEGOTIATED) - theirs)
            if not prof["ts"]:
                names = _drop_options(names, {"Timestamp"})
            values = {
                "MSS": seg,
                "WScale": prof["wscale"],
                "SAckOK": b"",
                "Timestamp": (val, echo if tcp.flags.A else 0),
                "NOP": None,
                "EOL": None,
            }
            tcp.options = [(n, values[n]) for n in names]
            if tcp.flags.A:
                tcp.window = synack_window(prof, ts_ok)
            else:
                tcp.window = prof["syn_window"]
        elif not tcp.flags.R:
            peer_mss = mss_of.get((dst, src)) or (1440 if IPv6 in q else 1460)
            data = len(bytes(tcp.payload))
            if ts_ok and data > peer_mss - 12:
                raise ValueError(
                    f"{src[0]} -> {dst[0]}: a {data}-byte segment "
                    "plus a timestamp option is over the MSS. Both ends use "
                    f"timestamps, so segment at {peer_mss - 12} bytes "
                    f"(flow_line(..., mss={peer_mss - 12}))"
                )
            shift = prof["wscale"] if ws_ok else 0
            tcp.window = max(1, min(prof["window"] >> shift, 0xFFFF))
            tcp.options = (
                [("NOP", None), ("NOP", None), ("Timestamp", (val, echo))]
                if ts_ok
                else []
            )
        else:
            tcp.options = []
        if prof["ts"]:
            seen.setdefault((src, dst), []).append((now, val, _seq_end(p)))
        del tcp.dataofs
        out[i] = rebuild(q, p.time)
    return out


# ------------------------------------------------------------------- scapy


class Host:
    """An endpoint as seen from the capture point.

    For a remote host, mac is the local gateway's MAC and ttl is what
    arrives after a few hops (e.g. 64 - 12 = 52, or 128 - 10 = 118).
    stack is a STACKS name ("windows", "linux", "macos") or a
    stack_profile() dict: tcp_session() then uses that OS's SYN options,
    windows and timestamps. window overrides the stack's established
    window (bytes).
    """

    def __init__(self, ip, mac, ttl=64, window=None, stack=None):
        self.ip, self.mac, self.ttl = ip, mac, ttl
        self.stack = stack_profile(stack) if stack else None
        if window is None:
            window = self.stack["window"] if self.stack else 64240
        self.window = window
        if self.stack:
            self.stack["window"] = window


def frame(src, dst, l4, rng):
    return (
        Ether(src=src.mac, dst=dst.mac)
        / IP(src=src.ip, dst=dst.ip, ttl=src.ttl, id=rng.randrange(65536), flags="DF")
        / l4
    )


def tcp_session(
    t,
    client,
    server,
    sport,
    dport,
    messages,
    rng,
    rtt=0.045,
    mss=1460,
    closer="client",
    near="client",
):
    """One whole TCP connection; returns (packets, end time).

    messages is a list of (">" or "<", bytes). near says which end the
    capture point sits next to: "client" (an outbound connection seen from
    the LAN) or "server" (an inbound connection to a local server). A packet
    from the far end that answers the near end arrives `rtt` later;
    everything else is sub-millisecond. rtt is seconds, or a (low, high)
    range drawn again for each round trip. Data is segmented at the MSS and
    each message is ACKed. A message bigger than the receiver's window is
    sent in flights, each ACKed before the next. Each side offers about its
    host's `window` bytes: as is in its SYN, which is never scaled, and
    shifted by its WScale in every later packet. The connection ends with a
    FIN close started by `closer`, or closer=None to leave it open.
    """
    out = []
    far = "<" if near == "client" else ">"
    # a 12-byte timestamp option on every segment leaves 12 fewer for data
    seg_size = mss - 12 if both_timestamp(client.stack, server.stack) else mss
    seq = {">": rng.randrange(SEQ_MOD), "<": rng.randrange(SEQ_MOD)}
    copts = [
        ("MSS", mss),
        ("NOP", None),
        ("WScale", 8),
        ("NOP", None),
        ("NOP", None),
        ("SAckOK", b""),
    ]
    sopts = [
        ("MSS", mss),
        ("NOP", None),
        ("NOP", None),
        ("SAckOK", b""),
        ("NOP", None),
        ("WScale", 7),
    ]
    last = [None]
    wscale = {">": 8, "<": 7}  # from copts and sopts
    for side, host in ((">", client), ("<", server)):
        if host.stack:  # set_tcp_stack() rewrites the options at the end
            wscale[side] = host.stack["wscale"]
    scaled = {">": False, "<": False}  # has that side sent a non-SYN packet

    def field(side, syn):
        """The window field: unscaled in a SYN, else shifted by WScale so
        both offer about `window` bytes."""
        host = client if side == ">" else server
        if syn and host.stack:
            if side == ">":
                return host.stack["syn_window"]
            return synack_window(host.stack, both_timestamp(client.stack, host.stack))
        if syn:
            return min(host.window, 0xFFFF)  # a SYN's field isn't scaled
        return max(1, min(host.window >> wscale[side], 0xFFFF))

    def window(side):
        """Bytes the side is offering to receive."""
        if not scaled[side]:
            return field(side, True)
        return field(side, False) << wscale[side]

    def send(at, frm, flags, data=b"", options=None):
        back = "<" if frm == ">" else ">"
        src, dst = (client, server) if frm == ">" else (server, client)
        s, d = (sport, dport) if frm == ">" else (dport, sport)
        tcp = TCP(
            sport=s,
            dport=d,
            flags=flags,
            seq=seq[frm] % SEQ_MOD,
            window=field(frm, "S" in flags),
            options=options or [],
        )
        tcp.ack = seq[back] % SEQ_MOD if "A" in flags else 0
        p = frame(src, dst, tcp / Raw(data) if data else tcp, rng)
        p.time = at
        out.append(p)
        seq[frm] += len(data) + (1 if "S" in flags or "F" in flags else 0)
        last[0] = frm
        scaled[frm] = scaled[frm] or "S" not in flags

    def step(frm):
        """Delay before a packet from frm: an RTT if it answers across the WAN."""
        if last[0] is not None and frm == far and last[0] != far:
            return draw_rtt(rtt, rng)
        return 0.0003

    send(t, ">", "S", options=copts)
    t += step("<")
    send(t, "<", "SA", options=sopts)
    t += step(">")
    send(t, ">", "A")
    for frm, data in messages:
        back = "<" if frm == ">" else ">"
        t += step(frm)
        flight, i = 0, 0
        while i < len(data):
            room = window(back) - flight
            if room <= 0:
                # window full: wait for the receiver's ACK
                t += step(back)
                send(t, back, "A")
                t += step(frm)
                flight = 0
                continue
            segment = data[i : i + min(seg_size, room)]
            send(t, frm, "PA", segment)
            flight += len(segment)
            i += len(segment)
            t += 0.00004
        t += step(back)
        send(t, back, "A")
    if closer:
        first = ">" if closer == "client" else "<"
        second = "<" if first == ">" else ">"
        t += 0.2
        send(t, first, "FA")
        t += step(second)
        send(t, second, "A")
        t += 0.0002
        send(t, second, "FA")
        t += step(first)
        send(t, first, "A")
    stacks = {h.ip: h.stack for h in (client, server) if h.stack}
    if stacks:
        out = set_tcp_stack(out, stacks, rng, mss=mss)
    return out, t


def udp_exchange(t, client, server, sport, dport, request, reply, rng, rtt=0.045):
    """A request and its reply `rtt` later (seconds, or a (low, high) range)."""
    rtt = draw_rtt(rtt, rng)
    q = frame(client, server, UDP(sport=sport, dport=dport) / Raw(request), rng)
    q.time = t
    r = frame(server, client, UDP(sport=dport, dport=sport) / Raw(reply), rng)
    r.time = t + rtt
    return [q, r], t + rtt


def icmp_echo(t, src, dst, ident, seq, payload, rng, rtt=0.045):
    """An echo request and its reply `rtt` later (seconds, or a range)."""
    rtt = draw_rtt(rtt, rng)
    q = frame(src, dst, ICMP(type=8, id=ident, seq=seq) / Raw(payload), rng)
    q.time = t
    r = frame(dst, src, ICMP(type=0, id=ident, seq=seq) / Raw(payload), rng)
    r.time = t + rtt
    return [q, r], t + rtt


# --------------------------------------------------------------------- tls


def _name(pairs, printable):
    """An x509.Name from (field, value) pairs, in order.

    printable=True encodes values as PrintableString (DER tag 0x13), as Java,
    many malware kits and most public CAs do; OpenSSL defaults to UTF8String
    (0x0c). Uses cryptography's private _ASN1Type; if a future release moves
    it, values fall back to the default encoding.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    try:
        from cryptography.x509.name import _ASN1Type

        printable_type = _ASN1Type.PrintableString
    except ImportError:  # pragma: no cover - depends on cryptography version
        printable_type = None
    oids = {
        "C": NameOID.COUNTRY_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L": NameOID.LOCALITY_NAME,
        "O": NameOID.ORGANIZATION_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "CN": NameOID.COMMON_NAME,
        "emailAddress": NameOID.EMAIL_ADDRESS,
    }
    attrs = []
    for k, v in pairs:
        if printable and printable_type is not None and k != "emailAddress":
            attrs.append(x509.NameAttribute(oids[k], v, printable_type))
        else:
            attrs.append(x509.NameAttribute(oids[k], v))
    return x509.Name(attrs)


def _write_key(key, path):
    from cryptography.hazmat.primitives import serialization

    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )


def mint_cert(
    subject, not_before, days, serial, cert_path, key_path, issuer=None, printable=True
):
    """Write a self-signed RSA-2048 cert and key as PEM.

    subject/issuer: list of (field, value) pairs in order, e.g.
    [("C", "US"), ("O", "Example"), ("CN", "a.example")]. issuer only sets
    the issuer name; the cert is still signed with its own key. For a cert
    "issued" by a public CA, use mint_chain(), which also sends the
    intermediate the way a real server does.

    The key is random, so a build should mint once and reuse the files.
    Needs the cryptography package.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(subject, printable))
        .issuer_name(_name(issuer or subject, printable))
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_before + datetime.timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(key, key_path)
    return cert.fingerprint(hashes.SHA1()).hex()


def mint_chain(
    ca_subject,
    ca_issuer,
    ca_not_before,
    ca_days,
    leaf_subject,
    leaf_sans,
    leaf_not_before,
    leaf_days,
    serials,
    chain_path,
    key_path,
    printable=True,
):
    """Write a leaf cert issued by a stand-in intermediate CA, as a chain.

    Copy the real intermediate's subject, issuer and validity from crt.sh
    (ca_subject, ca_issuer, ca_not_before, ca_days); its key and signature
    are minted here, so the chain won't validate. The leaf is a DV-style
    server cert: subject, subjectAltName DNS names, serverAuth.

    chain_path gets leaf then intermediate, which is what a server sends and
    what tls_flights() loads; key_path gets the leaf key. serials is
    (intermediate serial, leaf serial); public CAs use random serials of
    about 128 bits. The days arguments may be fractional: a notAfter of
    23:59:59, as many CAs use, is days - 1/86400. Needs the cryptography
    package.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _name(ca_subject, printable)
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(_name(ca_issuer, printable))
        .public_key(ca_key.public_key())
        .serial_number(serials[0])
        .not_valid_before(ca_not_before)
        .not_valid_after(ca_not_before + datetime.timedelta(days=ca_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(leaf_subject, printable))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(serials[1])
        .not_valid_before(leaf_not_before)
        .not_valid_after(leaf_not_before + datetime.timedelta(days=leaf_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in leaf_sans]),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    with open(chain_path, "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
        f.write(ca.public_bytes(serialization.Encoding.PEM))
    _write_key(leaf_key, key_path)
    return leaf.fingerprint(hashes.SHA1()).hex()


def tls_flights(
    cert_path, key_path, exchanges, keylog_path, sni=None, max_version="TLSv1_2"
):
    """Run a real TLS handshake plus application data in memory.

    cert_path may hold a chain (leaf first), as mint_chain() writes.
    exchanges is a list of (request bytes, response bytes). Returns a list
    of (">" or "<", record bytes) in wire order. The randoms can't be
    seeded, so callers should cache the result (see build_tls.py) and keep
    the NSS key log, which lets Wireshark decrypt the capture.
    """
    import ssl

    version = getattr(ssl.TLSVersion, max_version)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(cert_path, key_path)
    sctx.maximum_version = version
    sctx.options |= ssl.OP_NO_TICKET
    cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    cctx.check_hostname, cctx.verify_mode = False, ssl.CERT_NONE
    cctx.maximum_version = version
    cctx.keylog_filename = keylog_path

    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    cli = cctx.wrap_bio(c_in, c_out, server_side=False, server_hostname=sni)
    srv = sctx.wrap_bio(s_in, s_out, server_side=True)
    flights = []

    def pump(src_out, dst_in, direction):
        data = src_out.read()
        if data:
            flights.append((direction, data))
            dst_in.write(data)

    done = [False, False]
    while not all(done):
        for i, side in enumerate((cli, srv)):
            if not done[i]:
                try:
                    side.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        pump(c_out, s_in, ">")
        pump(s_out, c_in, "<")
    # either side may be empty: a beacon with no reply, or a server that
    # speaks first
    for request, response in exchanges:
        if request:
            cli.write(request)
            pump(c_out, s_in, ">")
            srv.read(1 << 20)
        if response:
            srv.write(response)
            pump(s_out, c_in, "<")
            cli.read(1 << 20)
    return flights
