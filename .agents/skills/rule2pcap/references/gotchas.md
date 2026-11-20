# Engine and testing gotchas

Things that make a correct-looking pcap fail to fire, fire in the wrong
place, or fire for the wrong reason. Each one cost real debugging time.
Check this list before changing the traffic.

## How Suricata inspects

- **Server data is parsed when the client ACKs it.** In IDS mode the
  stream engine hands data to the app-layer parser and to raw-stream
  inspection only once it's acknowledged. A to_client match can land on a
  later packet than the one carrying the bytes. If the capture ends before
  that ACK, the data is inspected only when the flow is flushed at the end
  of the pcap: the alert lands on a pseudo-packet, and its order against
  other alerts changes. Make sure every data segment is ACKed.
- **The raw stream is inspected in chunks** (a few KB), and the last chunk
  at flow end. If a rule depends on state set by another rule (a flowbit),
  put the matched bytes late enough that the setter has already run on an
  earlier chunk.
- **No teardown means late inspection.** Without a FIN or RST, the end of a
  flow is inspected only at flow timeout or when the pcap ends. That
  reorders alerts against rules that ran earlier. Flowsynth 1.4 emits no
  teardown; add one with `pcapkit.teardown()`.
- **Some alerts land on pseudo-packets anyway.** Rules with no content (a
  bare `byte_test`) and raw-stream matches on a flow whose protocol wasn't
  recognised can alert when the stream is flushed, even with a proper
  close. (`dsize` is checked on packets only, so a `dsize` rule alerts on
  the data packet.) The alert then has `pcap_cnt` null and a `pkt_src`
  such as "stream (flow timeout)". That's normal, not a defect.
- **The alert packet isn't the matching packet.** Because data is
  inspected when it's ACKed, or when the stream is flushed, the alert is
  usually logged on a later packet than the one carrying the bytes (an
  ACK, or the FIN exchange). The write-up records both.
- **Matches per event vary on raw TCP.** How many times one event matches
  depends on the rule and the flow, and it feeds threshold and
  detection_filter counts. Seen on 8.0.6 and 7.0.17: `content` with
  `depth` matched on the packet and again on the stream, so six beacons in
  six connections made 12 matches; the same content without `depth` made
  6. Six small beacons in one connection made a single match, because the
  stream is inspected in chunks. A rule with only `flow` matches every
  packet in its direction, ACKs and FINs included. So does a rule with
  only addresses and ports, plus once more at flow end, and so does one on
  `ttl`, `window` or another header field, for every packet that has it. `dsize` and `flags` rules, UDP
  rules, and app-layer buffers (`http.*`, `dns.*`, `tls.*`,
  `file.data`...) count once per packet or transaction. Don't predict it,
  measure it: run a copy of the rule with `threshold:type threshold,track
  by_src,count 1,seconds 60`, which alerts on every match. Then:
  1. Check the firing pcap reaches the count. If events merged into one
     match, give each its own connection, or tell the user the rule can't
     count events on one long connection.
  2. Size any below-threshold variant from the same measurement, not from
     count − 1, and test it with `--expect-absent <sid>`.
  3. A `type limit` rule alerts from the first match, so it has no
     below-threshold variant.
- **Raw content plus app-layer state on to_client may never fire in IDS
  mode.** Examples are `content` with `ssl_state` or `ssl_version`. The
  state is set when the data is parsed, which is a later packet than the
  one where the raw content matched. Test with `--set stream.inline=true`.
  If it fires only that way, say plainly that the rule only fires in IPS
  (inline) mode.
- **App-layer detection needs both directions.** Rules on `http`, `tls`,
  `dns` and the like need the protocol detected, which needs a handshake
  and traffic both ways. Check `app_proto` in the eve alert, or the
  `anomaly` counts in the test output.
- **HTTP bodies are inspected only up to a limit.** libhtp hands
  Suricata the first `request-body-limit` bytes of a request body and the
  first `response-body-limit` bytes of a response body. That bounds
  `http.request_body`, `http.response_body` and HTTP `file.data` (which
  is the request body on a to_server rule). The limit is 100 KiB in the
  stock suricata.yaml and Dalton's default configs, 4 KiB if the key is
  unset, and `server-config` blocks can override it per address. Content
  past the limit never matches, and junk padding ahead of the payload is a
  known evasion: Assetnote's react2shell-scanner has a `--waf-bypass`
  option that pads by 128 KiB. Keep matched bytes well inside the limit.
  The limit is set per sensor, so Dalton's value says nothing about the
  user's production sensors; always say so in the write-up (`rule_facts.py`
  notes it as `body-limit`). When attack tools pad:
  1. Build a padded variant and test it with `--expect-absent <sid>`.
  2. Confirm the cause by raising the limit for that side, e.g.
     `--set app-layer.protocols.http.libhtp.default-config.request-body-limit=256kb`
     (or `response-body-limit`), with `--expect-sid <sid>`: it must fire
     now. If it still doesn't, the pcap is broken, not the rule; check
     `pcap_lint.py` (e.g. `beyond-window`).
  3. Say in the write-up that the rule misses bodies padded past the
     sensor's limit, whatever that is set to.
- **libhtp merges duplicate headers.** Two `Location:` headers become one
  value in `http.header`. Match repeats in `http.header.raw`. Expect an
  `applayer:RESPONSE_HEADER_REPETITION` anomaly; it's correct, not a defect.
- **Decoders validate before setting flags.** A malformed IP option is
  rejected before `ipopts` sees it, so real exploit bytes may not fire a
  header-field rule. Say so rather than "fixing" the bytes.
- **A drop or reject rule stops inspection of the rest of its flow, even in
  IDS mode.** Later rules on that flow won't fire. Test with `alert` when
  that matters, and say you did.

## Rule dependencies

- **`flowbits:isset` with no setter.** Look for the real setter: same
  vendor, nearby sids, same flowbit name in ET. If you can't find it, write
  a stand-in setter in test.rules that sets the flowbit the way the name
  suggests, and say it's a stand-in.
- **`flowbits:noalert` rules never alert.** To test one, check
  `metadata.flowbits` on the eve event, or test a copy with `noalert`
  removed. Add the rule that uses the flowbit (`isset`) so something fires.
- **Threshold and detection_filter** need enough matches inside the window,
  tracked by the right address. Measure the matches per event (above).
- **Datasets, iprep, Lua and hash lists** need files the job doesn't have.
  A Dalton job can't supply them through this skill; say the rule can't be
  tested as written, and test a copy without that keyword only if the user
  agrees.
- **The rule's direction can be wrong.** Some vendor rules have the header
  or `flow` inverted relative to real traffic. The rule is canonical: build
  traffic that fires it. Note the conflict in the write-up, and ask the user
  first if that means building traffic no real attack would produce.

## Variables and the job config

- Dalton's default config sets `HOME_NET` to the RFC1918 ranges and
  `EXTERNAL_NET` to `!$HOME_NET`. Inside hosts must be RFC1918 and outside
  hosts must not be. Use 192.0.2.0/24, 198.51.100.0/24 or 203.0.113.0/24
  for outside hosts.
- That `HOME_NET` is IPv4 only, so over IPv6 no host is inside and a rule
  on `$HOME_NET` or `$EXTERNAL_NET` can't fire, with no error. Build over
  IPv4 unless the rule is about IPv6. If it is, add the inside hosts'
  IPv6 range to `HOME_NET` for the test, and say so in the write-up:
  `--set "vars.address-groups.HOME_NET=[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,2001:db8:10::/48]"`.
- Port variables follow Suricata's defaults, e.g. `$HTTP_PORTS` is 80.
  `rule_facts.py` lists the ones a rule uses.
- Dalton rejects rules containing non-ASCII text, and gives rules with no
  sid one from 806421601 up.

## Test-harness behaviour

- **Dalton jobs run Suricata multi-threaded** (the default autofp runmode)
  unless socket control is used. Threshold alerts then land on different
  packets from run to run. For repeatable placement, test with
  `--set runmode=single`.
- **On Suricata 8, socket-control jobs (`--socket-control`) keep per-host
  threshold counters between jobs** in the agent's long-running Suricata
  ([Suricata #8603](https://redmine.openinfosecfoundation.org/issues/8603);
  7.0.17 starts each pcap fresh). Results drift with what ran before, so
  don't use socket control for threshold rules.
- **The docker runner** starts a fresh process with `--runmode single`. Ask
  the user first, as the skill says.
- **Test every engine version that's online.** Keyword support and buffer
  behaviour differ between major versions. Report each version's result
  separately.
- **Read the anomaly counts in the test output.** Unexpected `applayer:`
  anomalies usually mean the traffic is malformed, even when the rule
  fires. `stream:` anomalies would too, but Dalton's stock configs don't
  log them, so a clean result doesn't prove the TCP is right: run
  `pcap_lint.py` as well. These are known to appear on genuine traffic and can be
  accepted without changing the build:
  - `applayer:APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION` on SMTP in
    Suricata 7, and on SSLv2 sessions;
  - `applayer:RESPONSE_HEADER_REPETITION` when the response deliberately
    repeats a header.

  Anything else: find out why before shipping.
- **`smtp.mail_from`** (Suricata 8) holds the address with its angle
  brackets and stops before ESMTP parameters: for `MAIL
  FROM:<a@b.example> SIZE=698` it's `<a@b.example>`.
- **Rules with newer keywords** (`smtp.mail_from`, `from_base64` and other
  Suricata 8 additions) fail to load on older engines. `test` lists those
  engines in `not_loaded` and judges the pass on the rest.

## Debugging a rule that won't fire

Work down this list, one change at a time:

1. Run `dalton_client.py validate`. Did every engine load the rule?
2. Check `pcap_lint.py` for errors: checksums, missing handshake, sequence
   gaps.
3. Check the header: are the pcap's addresses and ports inside the rule's
   variables? An IPv6 build is never in Dalton's `HOME_NET` (see
   "Variables and the job config").
4. Check the eve alert or flow for `app_proto`. Was the protocol detected?
5. Split the rule into one rule per condition, each with its own sid, and
   see which conditions match and on which packet (`pcap_cnt` in the test
   output). Conditions that match on different packets point to the
   inspection-timing items above.
6. Look at what the parser extracted: the eve app-layer record
   (`http`, `dns`, `tls`, `smtp`...) for the flow shows the fields the
   buffers come from. Rerun with `--dump-buffers` to get buffer dumps on
   the job's page in Dalton's web UI. They cover HTTP, DNS and TLS only,
   and aren't in the API output.
7. Try `--set stream.inline=true`, and a teardown if there isn't one.
8. Re-read the rule's modifiers: `depth`/`offset` count from the buffer
   start, `distance`/`within` from the previous match, `nocase` is
   per-content, and `startswith`/`endswith` anchor to the buffer.
