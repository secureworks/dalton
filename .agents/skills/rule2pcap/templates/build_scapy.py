#!/usr/bin/env python3
"""Write NAME.pcap: <what the traffic is>, which fires sid <SID>.

Rebuild (any venv with the skill's requirements.txt installed):
    <venv>/bin/python -I build.py

<Provenance. Say which parts come from public sources (with links) and
which are invented: hosts, ports, timing, payloads.>

---- template notes (delete this block in a real build) ----
Pure scapy template, for what Flowsynth can't do:
  - many interleaved or repeated connections (threshold, detection_filter,
    volume rules);
  - header fields a rule tests: TTL, IP options, TCP flags, window, ICMP
    type/code, fragments;
  - protocols over ICMP or raw IP.
pk.tcp_session() builds a whole connection: handshake, data segmented at
the MSS, ACKs, and a FIN close. The demo sends six raw TCP beacons ten
seconds apart and one ICMP echo, which fire the demo rules in
templates/demo.rules (sids 9000201 and 9000202). Copy pcapkit.py next to
this file.
-------------------------------------------------------------
"""

import datetime
import os
import random
import struct
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)  # python -I leaves the script's directory off sys.path
sys.dont_write_bytecode = True  # keep __pycache__ out of the output directory

import pcapkit as pk  # noqa: E402
from scapy.all import wrpcap  # noqa: E402

NAME = "demo-scapy"
SEED = 9000201  # the target sid: same seed, same bytes on every rebuild
START = datetime.datetime(2024, 3, 12, 9, 15, 2, 410000, tzinfo=datetime.timezone.utc)

rng = random.Random(SEED)
RTT = (0.038, 0.055)  # internet round trip range, seconds

# The capture point is on the victim's LAN: a remote host is seen through
# the gateway's MAC, with a TTL that has dropped a few hops.
# stack gives each host its OS's TCP options, windows and timestamps.
victim = pk.Host("192.168.40.23", "f8:bc:12:61:9a:d4", ttl=128, stack="windows")
c2 = pk.Host("203.0.113.44", "00:1b:54:c2:8e:01", ttl=49, stack="linux")


def beacon(n):
    # Invented framing: magic, version, sequence, length, body.
    body = b"host=WS-FIN-07;user=jmills;up=%d" % (n * 10)
    return b"R2P\x01" + struct.pack(">HH", n, len(body)) + body


def build():
    pkts, t = [], START.timestamp()
    sport = rng.randrange(pk.WINDOWS_PORTS[0], pk.WINDOWS_PORTS[1] - 10)
    for n in range(6):
        messages = [(">", beacon(n)), ("<", b"R2P\x02\x00\x00")]
        # near="client": captured on the victim's LAN. Use near="server" for an
        # inbound connection to a local server.
        session, _ = pk.tcp_session(
            t, victim, c2, sport + n, 4444, messages, rng, rtt=RTT
        )
        pkts += session
        t += 10 + rng.uniform(-0.5, 0.5)  # 10s sleep with jitter
    echo, _ = pk.icmp_echo(
        START.timestamp() + 3.2,
        victim,
        c2,
        rng.randrange(65536),
        1,
        b"r2p-ping" + bytes(24),
        rng,
        rtt=RTT,
    )
    pkts += echo
    pkts.sort(key=lambda p: float(p.time))
    pcap = os.path.join(here, f"{NAME}.pcap")
    wrpcap(pcap, pkts)
    os.chmod(pcap, 0o644)
    return pcap


if __name__ == "__main__":
    print(build())
