# Flowsynth cheat sheet

Flowsynth compiles a small text language (`.synth`) into a pcap. It
handles TCP handshakes, sequence numbers, segmentation and ACKs. It is
installed by requirements.txt and run as a module:

    python -m flowsynth -f pcap -w out.pcap in.synth

`pcapkit.compile_synth()` does this. Write the `.synth` from Python (see
`templates/build_flowsynth.py`) rather than by hand, so payload bytes stay
exact and escaped.

## Syntax

```
# a flow: name, protocol, client > server, attributes
flow h tcp 10.20.30.41:51515 > 203.0.113.80:80 ( tcp.initialize; src_mac:f8:bc:12:4e:21:07; dst_mac:00:1b:54:c2:8e:01; );
flow d udp 10.20.30.41:53000 > 10.20.0.53:53 ( src_mac:f8:bc:12:4e:21:07; dst_mac:00:25:90:1c:44:3a; );

# events: ">" client to server, "<" server to client
h > ( content:"GET / HTTP/1.1\x0d\x0aHost: a.example\x0d\x0a\x0d\x0a"; );
h < ( content:"HTTP/1.1 200 OK\x0d\x0aContent-Length: 0\x0d\x0a\x0d\x0a"; );
```

- **IPv6 addresses** go in brackets: `[2001:db8::1]:443`.
  `pcapkit.flow_line()` adds them, so pass the bare address.
- **Flow attributes:**
  - `tcp.initialize` generates the three-way handshake. Without it, the
    flow starts midstream.
  - `mss:N` sets the segment size (default 1460).
  - `src_mac:` and `dst_mac:` set the MACs.
- **Event attributes:**
  - `content:"..."`, which can be repeated; the parts are concatenated.
  - `filecontent:"path"` reads a file. It's disabled in Dalton's web UI but
    works on the command line.
  - `tcp.seq:N` and `tcp.ack:N` set sequence numbers manually.
  - `tcp.flags.syn`, `tcp.flags.ack`, `tcp.flags.synack` and
    `tcp.flags.rst` set flags.
  - `tcp.noack` suppresses the automatic ACK.
- **Escapes:** content strings understand only `\xHH`. Everything else is
  taken literally after shell-style tokenising. Use `pcapkit.esc()` for any
  bytes that aren't plain text.

## What it does for you

- **ACKs:** after each TCP data event, the receiver ACKs automatically,
  unless the event has `tcp.noack`.
- **Segmentation:** payloads longer than the MSS are split into
  MSS-sized segments.
- **Checksums and lengths** are correct.

## What it gets wrong, and the fix

These are Flowsynth 1.4 defects. Fixes for the MAC, ISN, port and FIN
problems are being prepared for Flowsynth 1.5; the pcapkit workarounds stay
harmless with it.

| Problem | Fix |
| --- | --- |
| Random MACs (`RandMAC`) re-randomise per packet, and about half have the group (multicast) bit set | Always give `src_mac` and `dst_mac` on every flow (`pcapkit.flow_line()` does) |
| `tcp.initialize` starts every flow at ISN 10 and 100 | `pcapkit.randomize_isns(pkts, rng)` |
| Packets are stamped with wall-clock time at build | `pcapkit.restamp(pkts, start, gap)` |
| No FIN support, so flows never close | `pcapkit.teardown(pkts, closer=..., idle=..., remote=WAN_HOSTS, rtt=RTT, rng=rng)`. Don't hand-roll FIN events with `tcp.flags.*`; the ACK numbers come out wrong |
| Window 8192 on every packet, and SYNs with no TCP options | `pcapkit.set_tcp_stack(pkts, {ip: "windows" or "linux" or "macos"}, rng)`, after teardown. When both ends use timestamps, compile with `flow_line(..., mss=1448)` (`pcapkit.both_timestamp()`) |
| Ports left as `any` are random per build | Always give explicit ports, drawn from the seeded `rng` |
| Two flows on the same addresses and ports are one connection to Suricata, so the second one's data may never be inspected | Give each connection its own source port (`randomize_isns()` and `teardown()` raise otherwise) |
| TTL 64 and IP ID 1 on every packet | `pcapkit.set_ip_fields(pkts, rng, ttl={...})`, run last |
| No other IP header control (options, fragments) | Build those packets with scapy (`templates/build_scapy.py`) |
| One flow at a time per declaration; awkward for hundreds of interleaved connections | Use `pcapkit.tcp_session()` in scapy |

## When to skip Flowsynth

Use the scapy template instead when the rule tests header fields (`ttl`,
`ipopts`, `flags`, `window`, `itype`/`icode`, `fragbits`), when it needs
many connections (threshold, detection_filter, volume), or when the protocol
isn't TCP or UDP (ICMP, raw IP). The TLS template carries real handshake
records through Flowsynth; it's the right start for certificate, SNI and
TLS-field rules.
