#!/usr/bin/env python3
"""Write NAME.pcap: <what the traffic is>, which fires sid <SID>.

Rebuild (any venv with the skill's requirements.txt installed):
    <venv>/bin/python -I build.py           # reuse the cert and TLS session
    <venv>/bin/python -I build.py --fresh   # new cert, key and session

<Provenance. Say where the certificate fields come from (public reporting,
a profile, a sample) and what is invented.>

---- template notes (delete this block in a real build) ----
TLS template, for rules on certificates, SNI, JA3/JA4 or handshake fields.
The handshake is real: Python's ssl runs both ends in memory, and their
records are carried verbatim through Flowsynth. A minted cert, an RSA key
and TLS randoms can't be seeded, so the cert, key and records are cached
(NAME.crt/.key, session.json). Rebuilds stay byte-identical until an
input in inputs() changes, or --fresh: then the cert or session is made
anew. Add anything new the cert or handshake depends on to inputs().
NAME-keys.log decrypts the capture in Wireshark. The demo fires sid 9000301
in templates/demo.rules. Copy pcapkit.py next to this file.

For a rule on a public CA's issuer (Let's Encrypt, ZeroSSL, ...) use
pk.mint_chain() instead of pk.mint_cert(): copy the real intermediate's
subject, issuer and validity from crt.sh, and the server sends leaf plus
intermediate as real ones do. The cert files, session.json and the key log
are part of the deliverable: list them in the README.

The ClientHello and ServerHello are OpenSSL's. If the rule tests JA3/JA4
or exact extension lists, build the hello by hand instead (scapy's TLS
layers, or raw bytes).
-------------------------------------------------------------
"""

import datetime
import hashlib
import json
import os
import random
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)  # python -I leaves the script's directory off sys.path
sys.dont_write_bytecode = True  # keep __pycache__ out of the output directory

import pcapkit as pk  # noqa: E402
from scapy.all import rdpcap, wrpcap  # noqa: E402

NAME = "demo-tls"
SEED = 9000301
START = datetime.datetime(2024, 5, 2, 19, 44, 10, 80000, tzinfo=datetime.timezone.utc)

VICTIM, SERVER, PORT = "10.8.14.77", "198.51.100.23", 443
VICTIM_MAC, GW_MAC = "f8:bc:12:22:6b:90", "00:1b:54:c2:8e:01"
RTT = (0.038, 0.052)  # internet round trip range, seconds
# Each host's OS: TCP options, windows, timestamps (pk.set_tcp_stack).
STACKS = {VICTIM: "windows", SERVER: "linux"}
# both ends using timestamps leaves 12 fewer bytes per segment for data
# both ends timestamping leave MSS - 12 for data (1460 IPv4, 1440 IPv6)
SEGMENT = (
    (1428 if ":" in VICTIM else 1448)
    if pk.both_timestamp(STACKS[VICTIM], STACKS[SERVER])
    else None
)
SNI = None  # many implants dial an IP and send no SNI; set a name if the rule needs one
SUBJECT = [("C", "US"), ("O", "Secure Login Ltd"), ("CN", "secure-login.example.org")]
CERT_START = datetime.datetime(2024, 4, 30, 8, 0, 0, tzinfo=datetime.timezone.utc)
CERT_DAYS = 365

rng = random.Random(SEED)
crt, key = os.path.join(here, f"{NAME}.crt"), os.path.join(here, f"{NAME}.key")
cache, keylog = (
    os.path.join(here, "session.json"),
    os.path.join(here, f"{NAME}-keys.log"),
)


def exchanges():
    request = pk.http_message(
        "GET /owa/auth/logon.aspx HTTP/1.1",
        [
            ("Host", "secure-login.example.org"),
            ("User-Agent", "Mozilla/5.0"),
            ("Accept", "*/*"),
        ],
    )
    response = pk.http_message(
        "HTTP/1.1 200 OK",
        [
            ("Server", "nginx"),
            ("Content-Type", "text/html"),
            ("Connection", "keep-alive"),
        ],
        b"<html><body>Sign in</body></html>",
    )
    return [(request, response)]


def inputs():
    """Fingerprints of what the cached cert, and the cached session, are made from."""
    cert = repr((SUBJECT, CERT_START, CERT_DAYS, SEED))
    session = repr((cert, SNI, exchanges()))
    return tuple(hashlib.sha256(x.encode()).hexdigest() for x in (cert, session))


def gap(p, new_flow, earlier):
    # Capture point on the victim's LAN: the server's replies arrive an RTT
    # later, and back-to-back segments of one flight are fast.
    return pk.reply_gap(p, earlier, {SERVER}, rng, rtt=RTT)


def build(fresh=False):
    cert_in, session_in = inputs()
    saved = {}
    if os.path.exists(cache):
        with open(cache) as f:
            saved = json.load(f).get("inputs", {})
    if (
        fresh
        or saved.get("cert") != cert_in
        or not (os.path.exists(crt) and os.path.exists(key))
    ):
        # its own generator, so minting doesn't shift the values drawn from rng
        serial = random.Random(SEED + 1).randrange(1 << 32, 1 << 63)
        pk.mint_cert(SUBJECT, CERT_START, CERT_DAYS, serial, crt, key)
        fresh = True
    if fresh or saved.get("session") != session_in:
        if os.path.exists(keylog):
            os.remove(keylog)
        flights = pk.tls_flights(crt, key, exchanges(), keylog, sni=SNI)
        with open(keylog) as f:
            keys = f.read()
        with open(cache, "w") as f:
            json.dump(
                {
                    "inputs": {"cert": cert_in, "session": session_in},
                    "flights": [[d, b.hex()] for d, b in flights],
                    "keylog": keys,
                },
                f,
                indent=1,
            )
    with open(cache) as f:
        session = json.load(f)
    with open(keylog, "w") as f:
        f.write(session["keylog"])

    sport = rng.randrange(*pk.WINDOWS_PORTS)  # or pk.LINUX_PORTS for a Linux client
    synth, pcap = (
        os.path.join(here, f"{NAME}.synth"),
        os.path.join(here, f"{NAME}.pcap"),
    )
    with open(synth, "w") as f:
        f.write("# Generated by build.py -- edit that, not this.\n")
        f.write(
            pk.flow_line(
                "t", "tcp", VICTIM, sport, SERVER, PORT, VICTIM_MAC, GW_MAC, SEGMENT
            )
        )
        for direction, data in session["flights"]:
            f.write(pk.event_line("t", direction, bytes.fromhex(data)))
    pk.compile_synth(synth, pcap)

    pkts = pk.randomize_isns(list(rdpcap(pcap)), rng)
    pk.restamp(pkts, START, gap)
    pkts = pk.teardown(pkts, closer="client", remote={SERVER}, rtt=RTT, rng=rng)
    pkts = pk.set_tcp_stack(pkts, STACKS, rng)
    pkts = pk.set_ip_fields(pkts, rng, ttl={VICTIM: 128, SERVER: 52})
    wrpcap(pcap, pkts)
    os.chmod(pcap, 0o644)
    return pcap


if __name__ == "__main__":
    print(build(fresh="--fresh" in sys.argv))
