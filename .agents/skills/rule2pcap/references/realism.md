# Making the traffic realistic

A pcap that fires the rule is the minimum. It should also look like the
real thing to an analyst who opens it in Wireshark. Prefer what public
sources show. Where you invent, invent what the real implant, exploit or
client would plausibly send, and list it in the write-up.

## Hosts and addresses

- Put the inside host (victim, client or server) in RFC1918 space and
  outside hosts in 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24. Use
  IPv6 (2001:db8::/32) only when the rule is about IPv6: Dalton's
  `HOME_NET` is IPv4 only (see gotchas, "Variables and the job config"). A well-known public service (a public resolver, a CDN)
  may keep its real address if it matters to the story.
- Never use real victim addresses, even from public reports. An attacker
  IOC address from public reporting is allowed, but label it as one in the
  write-up.
- Give each host one fixed unicast MAC. Remote hosts appear behind the
  local gateway's MAC. Real vendor OUIs make it look real, e.g.
  `00:1b:54` (Cisco) or `00:25:90` (Supermicro). The group bit (lowest bit
  of the first octet) must be 0.
- TTLs: Windows starts at 128 and Linux at 64. A remote host's packets
  arrive a few hops lower (49, 52, 116...). Flowsynth stamps TTL 64 and IP
  ID 1 on everything; fix both with `pcapkit.set_ip_fields()`, run last.
  Use the TCP window and options of the claimed OS: `pcapkit.STACKS` has
  Windows, Linux and macOS (`set_tcp_stack()` for Flowsynth output,
  `Host(stack=...)` for `tcp_session()`).
- Client ports: Windows uses 49152-65535 and Linux 32768-60999
  (`pcapkit.WINDOWS_PORTS`, `pcapkit.LINUX_PORTS`).
- Capture point: assume the sensor sits on the inside host's LAN. The
  outside host's replies arrive an RTT after what they answer; back-to-back
  segments of one flight, and local replies, are sub-millisecond
  (`pcapkit.reply_gap()`). Flowsynth ACKs every segment, so a large send
  from the inside host gets an RTT per segment; build one with
  `pcapkit.tcp_session()`. For an inbound attack on a local server, the
  outside client is the remote end (`tcp_session(near="server")`).

## Names

- Use domains, URLs and hostnames from public reporting when they exist,
  and cite them.
- Invented names should look like the family's naming style, and must not
  belong to a real third party. Use `example.com`, `example.net`,
  `example.org` or `.example` / `.test` names, or check the name isn't a
  live site.
- When the rule's bytes require a real brand or domain (`linkedin.com` in a
  host, a typo-squat like `paypa1.com`):
  - Use it only where the rule needs it, and never contact it.
  - If an unanchored match allows it, embed it in a look-alike under a
    reserved name (`linkedin.com.jobs-portal.example`).
  - Note the choice in the README.
- Look a name up in DNS before connecting to it, when the real client
  would.

## Timing

- **Round trips:** LAN replies arrive in under a millisecond. Internet
  round trips take 20 to 150 ms. A resolver takes a few ms to tens of ms.
  Use one RTT range for the whole build, closes included.
- **Closes:** a client closes soon after it's done; a server closes an
  idle keep-alive connection after its timeout (often 5 to 60 s), and a
  `Connection: close` response right away. Set `teardown()`'s `idle` to
  match. An alert on the last data of a flow can wait for the close.
- **Beacons:** sleep plus jitter as the family does, e.g. 60 s ±20%.
  Don't send beacons back to back unless the rule is about a burst.
- **Dates:** match the threat's era. Keep HTTP `Date:` headers,
  certificate validity, TLS versions, User-Agents and server banners
  consistent with the capture time. Nothing in the future.
- **Seed every random choice from the target sid** so a rebuild is
  byte-identical. Cache anything that can't be seeded (TLS randoms,
  minted keys).

## Protocol details

- **HTTP:** use the real client's header order and User-Agent for that
  era, exact `Content-Length`, a `Host` header, and plausible server
  headers and status codes. Keep-alive or close as the real client does.
- **DNS:** use matching transaction IDs, the question echoed in the
  answer, and sensible TTLs. `pcapkit.dns_messages()` builds A or AAAA
  answers, NODATA and NXDOMAIN. A real host often sends A and AAAA
  together; leave the AAAA out if it would fire the rule a second time,
  and say so.
- **TLS:** run a real handshake where possible (the TLS template). Say
  which side's hello is OpenSSL's rather than the real stack's. For a cert
  from a public CA, copy the real intermediate's names, string types and
  validity from crt.sh, and send leaf plus intermediate
  (`pcapkit.mint_chain()`).
- **SMTP:** the server speaks first (220 banner). Use EHLO with a multi-line
  250 reply, then MAIL FROM, RCPT TO, DATA, the message ending in a lone
  ".", then QUIT and 221, after which the server closes. If the server
  advertises STARTTLS and the client uses it, nothing after EHLO is
  visible. A rule on envelope or message fields only sees plaintext SMTP,
  so leave STARTTLS out and say so.
- **TCP:** every segment ACKed (a cumulative ACK counts), never more data
  in flight than the receiver's window, no sequence gaps, MSS-sized
  segments, and a FIN or RST close.

## Payload content

- Reproduce the protocol framing the rule and the sources describe.
  Opaque or encrypted blobs can be seeded random bytes of the right length
  and alphabet.
- Never include working malware binaries or live credentials. Where the
  rule doesn't inspect a field, an inert placeholder is fine: a PDF whose
  JavaScript does nothing, or a "payload" that's a harmless stub. For
  Windows executables use `pcapkit.inert_pe()`: valid PE32 headers (file
  type tools and `filemagic` see "PE32 executable") and no code. Bytes the rule matches must be exact even if
  they are exploit bytes; they need not be functional.
- Use invented users, hostnames, emails and passwords: `jmills`,
  `WS-FIN-07`, `dmorgan@example.com`.

## Scope

- Include the context that makes the story readable: the DNS lookup, the
  landing page before the exploit, the check-in before the tasking. Leave
  out unrelated background noise. A focused capture is easier to verify.
- One pcap per rule. If the rule needs a separate setter flow or a
  repetition count, that's still one pcap.
