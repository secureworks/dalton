---
name: rule2pcap
description: Build a packet capture (pcap) that triggers a given Suricata rule, shaped like the real-world traffic behind the rule, and prove it fires by running it through Dalton. Use when someone has a Suricata rule (or a rules file) and wants a pcap that fires it, wants test or demo traffic for a rule, or wants to know whether a rule fires on realistic traffic.
license: Apache-2.0
compatibility: Needs Python 3.10+ and either a Dalton instance with Suricata agents or local Dalton Suricata images in Docker. Web access helps with research but is optional.
---

# rule2pcap

Turn a Suricata rule into a pcap that fires it. Research what the real
traffic looks like, build the capture reproducibly, test it on every
Suricata version Dalton has, and report honestly what is confirmed and
what is invented.

| Path (in this skill's directory) | Purpose |
| --- | --- |
| `scripts/dalton_client.py` | `preflight`, `validate` (load rules in each engine), `test` (run a pcap, report sids fired) |
| `scripts/rule_facts.py` | decode a rule: contents as bytes, buffers, client/server roles, research leads, a suggested output directory, notes on what complicates building it |
| `scripts/pcap_lint.py` | check a pcap for unrealistic or broken packets; `--frames` lists every frame |
| `templates/` | starting `build.py` scripts plus `pcapkit.py` helpers |
| `references/` | `gotchas.md`, `flowsynth.md`, `realism.md`, `research.md`, `writeup.md` |

## Paths used below

Set these once, as absolute paths, and use them in every command:

- `SKILL`: this skill's directory.
- `WORK`: where the user wants the work done (by default, the current
  directory).
- `VENV`: the build venv, by default `$WORK/.venv-rule2pcap`. Call its Python
  by absolute path; a relative path through `..` makes Python 3.14 print
  `sys.prefix` warnings. Don't resolve its symlinks (`realpath`): that
  leads to the system Python, without the venv's packages.
- `OUT`: the deliverable directory, `$WORK/rule2pcap-output/<suggested_dir>`.
  `rule_facts.py` prints a top-level `suggested_dir` as `<sid>-<slug>`,
  where the slug is the msg lowercased with non-alphanumerics turned into
  `-`, at most 40 characters. It's named for the rule the pcap must fire,
  not a `noalert` setter; if several rules can alert, it uses the first,
  and each rule has its own `suggested_dir` if the target is another. If
  the user names another location, use that.

Steps 1 and 2.1 run in `$WORK/rule2pcap-output/`, before `$OUT` exists;
run everything after that from `$OUT`. Every script prints JSON. Keep raw
script output, such as test results, in `$WORK/rule2pcap-output/logs/`
(create it first), not in `$OUT`.

Deliverable, in `$OUT`:
- the pcap;
- `build.py` (plus `pcapkit.py`), which regenerates it byte-for-byte;
- the `.synth` file, if Flowsynth was used;
- any TLS cert, key, `session.json` and key log;
- `test.rules`;
- a `README.md` write-up.

## 0. Preflight

Do this first. Starting Dalton takes a while, so it can run while you
research.

1. **Build venv.** If `$VENV` doesn't exist, create it:
   ```
   python3 -m venv $VENV
   $VENV/bin/pip install --no-cache-dir -r $SKILL/requirements.txt
   ```
   Never install into the system Python. If you can't create a venv, stop
   and tell the user what's missing.
2. **Check the environment:**
   ```
   $VENV/bin/python $SKILL/scripts/dalton_client.py preflight --python $VENV/bin/python
   ```
   Dalton's URL comes from `DALTON_URL` (default `http://localhost`).
3. **Read `ready`** in the output:
   - **`dalton` is true:** use Dalton for all testing. This is the normal
     path. `engines` lists the versions `test` and `validate` will use:
     one agent per version. `sensors` lists every agent; one named like
     `suricata/8.0.6/ctf` runs a custom config, and is used only when no
     stock agent runs that version or you pass it with `--engine-tech`.
   - **Dalton is unreachable:** if the URL is local, the user may need to
     start it (`./start-dalton.sh` in the Dalton repo). Ask them; don't
     start it yourself.
   - **`auth: required`:** Dalton wants credentials.
     - Upstream Dalton with `auth_prefix` set needs `DALTON_USER`.
     - Other deployments need a header. Ask the user which header and
       value, or where to read them. Never guess, and never read
       credentials from files you weren't pointed to.
     - Then `export DALTON_HEADERS='Name: value'` (several headers go one
       per line). The environment, or a mode-600 file you source in each
       command, keeps the value out of the process list and the
       transcript.
     - Don't pass secrets with `--header`, don't echo them, and never
       write them into `$OUT`.
   - **Reachable but no Suricata sensors:** the agents aren't running.
     Ask the user to start them.
4. **Docker fallback.** Only if Dalton can't be used and `docker_fallback`
   is true:
   - Ask the user before running anything.
   - Show them the exact commands from `test --runner docker --dry-run ...`,
     and the images it would use.
   - Explain what the fallback does: it runs those local Suricata images
     directly, with no network, reading only the pcap and rules.
   - Explain what it doesn't give them: no Dalton job links and no buffer
     dumps.

   Proceed only on a clear yes. If neither path is available, you can
   still build the pcap, but label it **UNVERIFIED** everywhere.

## 1. Get the rule

If the user hasn't given one, ask for the Suricata rule text or a rules
file. Accept supporting rules too, such as the rule that sets a flowbit the
target checks. Snort rules are out of scope for now; say so if you're
given one.

If the user wants the pcap as evidence that the rule detects a real
exploit or malware, say once that a pcap built from the rule begs the
question; a capture of the real traffic is the test for that. This pcap
checks the rule's syntax and structure. Then carry on if they still want it.

Save the rules to `$WORK/rule2pcap-output/test.rules`, and run step 2.1
in that directory: it prints `suggested_dir`. Then create `$OUT`, move
`test.rules` into it, and `cd` there for the rest.

## 2. Read the rule

1. **Decode it** (in `$WORK/rule2pcap-output/`, as step 1 says):
   ```
   $VENV/bin/python $SKILL/scripts/rule_facts.py test.rules
   ```
   This gives:
   - the contents as bytes, with their buffers and modifiers;
   - which side is client and which is server;
   - research leads and `suggested_dir`;
   - notes on what complicates building it.

   Work out exactly what bytes must appear, in which buffer, in which
   direction, and in what order. The `byte_test`/`byte_jump` notes spell
   out the arithmetic. For a keyword or modifier you're unsure of, read
   the Suricata rules docs for the version under test (research.md,
   "Suricata documentation"), not from memory.
2. **Load it in the engines:**
   ```
   $VENV/bin/python $SKILL/scripts/dalton_client.py validate --rules test.rules > $WORK/rule2pcap-output/logs/validate.json
   ```
   This submits a short Dalton job per engine, taking tens of seconds.
   Suricata is the judge of whether a rule is well-formed. Reading the
   result:
   - `valid: true` with `needs_newer_engine: true` means older engines
     lack a keyword (`unknown_keywords`). That's a version requirement,
     not an error.
   - `valid: false` means a real syntax problem, unless `not_run` lists an
     engine: it didn't run (exit code 2). See "Engines that didn't run" in
     step 5.
3. **Tell the user about any error-level notes and every real syntax
   error.** Don't rewrite the rule silently. Small obvious typos are worth
   pointing out. Don't try to be clever about style.
4. **Act on the notes:**
   - `no-setter`: find or stand in the flowbit setter.
   - `noalert`: the rule never alerts by itself.
   - `threshold`: you need repeats (see step 4).
   - `ips-only`: it may need inline mode.
   - `external-dependency`: it may be untestable as written.
   - `header-fields`: build with scapy.
   - `dsize` / `stream_size`: the data must arrive as one segment of that
     size, or before the other side sends anything.
   - `min-version`: older engines won't load it.
   - `no-content`: the alert may land on a pseudo-packet.
   - `body-limit`: the rule only sees an HTTP body up to the sensor's
     configured limit. Tell the user in the write-up's Notes and in your
     summary, since their production limit may differ from Dalton's.

   `references/gotchas.md` explains each.

## 3. Research

Follow `references/research.md`:
1. Start from the leads.
2. Grep the prod rulesets Dalton has; research.md says where they are.
3. Look at CVE data and advisories, then family write-ups and public
   pcaps.

Scale it to the rule. With empty `leads` and a generic msg, one or two
searches and a ruleset grep are enough. Then say "not confirmed: built from
the rule". Keep a source list with URLs as you go. If web access needs
permission, ask for it. If you have none, say so and continue.

The rule is canonical. When sources conflict with it, build to the rule
and note the conflict. Ask the user first if firing the rule would mean
traffic no real instance would produce.

## 4. Plan, then build

1. **Plan the traffic.** Before writing code, write a short traffic plan.
   It becomes the README's "What's in the capture". Cover:
   - each flow, its endpoints and direction;
   - what is said, in order;
   - which packet carries the matching bytes;
   - where the capture point is: on the inside host's LAN, so the outside
     host's replies arrive an RTT later;
   - what comes from sources and what you will invent.

   For a threshold or detection_filter rule, send count + 1 matching
   events, inside the window, from the tracked address. On raw TCP one
   event doesn't always make one match: measure, and size any
   below-threshold variant, as gotchas.md ("Matches per event vary")
   says. Test with `--set runmode=single`, or the alert lands on a
   different packet each run.
2. **Pick a template**, copying it to `$OUT/build.py` along with
   `$SKILL/templates/pcapkit.py`:
   - `build_flowsynth.py`: HTTP, DNS, SMTP and most TCP/UDP application
     traffic, including `dsize`/`stream_size` rules whose payload fits in
     one segment.
   - `build_scapy.py`: header-field rules, exact segmentation, many or
     interleaved connections (threshold, volume), ICMP and raw IP. For
     repeated HTTP requests (e.g. an HTTP threshold rule), build each
     connection with `pk.http_message()`.
   - `build_tls.py`: certificate, SNI and TLS-handshake rules. It caches
     the cert, key and handshake, and rebuilds them when an input they
     depend on changes; `--fresh` forces new ones.
3. **Edit the build:**
   - Set `NAME` and `SEED` (use the target sid), and the start time.
   - Set the hosts, their OS (`STACKS`, or `Host(stack=...)` in scapy),
     TTLs and ports, following `references/realism.md`.
   - Set the timing: the RTT range, and the `idle` before each close
     (`pk.teardown()` says what's typical).
   - Replace the demo payloads.
   - Delete the template-notes block.
   - Fill in the docstring's provenance.

   Keep every random choice on the seeded `rng`.
4. **Run it twice**: `$VENV/bin/python -I build.py`. The pcap should be
   byte-identical both times.

## 5. Check and test

```
$VENV/bin/python $SKILL/scripts/pcap_lint.py <name>.pcap
$VENV/bin/python $SKILL/scripts/dalton_client.py test --pcap <name>.pcap --rules test.rules > $WORK/rule2pcap-output/logs/<name>-test.json
```

- **Lint:** fix every lint error. Fix or justify every warning, and note
  justified ones in the README.
- **Test:** it passes when every expected sid fires on every engine that
  loads the rule.
  - By default the expected sids are every rule in test.rules that isn't
    `noalert`. Use `--expect-sid` to narrow that, and `--expect-absent`
    for a sid that must not fire (a below-threshold or near-miss pcap).
  - Per engine, `expected_fired` says which fired, `alert_lines` holds the
    engine's own alert lines for the write-up, `first` gives the packet
    the first alert landed on, and `frames` lists every alert's frame.
  - A null `pcap_cnt` with a `pkt_src` like "stream (flow timeout)" means
    a pseudo-packet; see gotchas.
- **Engines that can't load the rule:** `not_loaded` lists them, typically
  older versions without a keyword the rule uses. Their `expected_fired`
  is null and they don't count against the pass. Report them as "needs
  Suricata N or later", not as failures. An engine goes there when an
  expected sid fails to load, or a setter it depends on (a flowbit, xbit
  or hostbit it checks) does. Another rule that fails, such as an unrelated
  rule in the same file, is listed in `rule_warnings`, and the engine is
  still judged.
- **Engines that didn't run:** `not_run` lists engines that never read the
  pcap: the job timed out, was interrupted or crashed, or the engine
  stopped on an error. Nothing is known about them, so the test fails with
  exit code 2. Read that result's `errors` first: a config error, such as a
  bad `--set`, needs fixing, not rerunning. Otherwise run it again, perhaps
  with a longer `--timeout`; if it keeps happening, tell the user.
- **Anomalies:** read `anomalies` in the test output. Unexpected
  `applayer:` events (and `stream:` events, on configs that log them;
  Dalton's stock configs don't) usually mean malformed traffic, even when
  the rule fires. A few are normal for some protocols on some versions;
  `references/gotchas.md` lists the known ones.
- **Engine settings:** use `--set key=value` only when the rule needs it
  (e.g. `stream.inline=true`), and report it.
- **Prod ruleset:** optionally, run again with `--prod-ruleset <path from
  preflight>`. Hits from other vendors' rules for the same threat
  corroborate the traffic; a flood of unrelated hits suggests something
  odd. If the target sid is also in the prod ruleset at the same rev, the
  engine keeps the prod copy and `rule_warnings` says so; bump `rev` in
  test.rules to test yours.

## 6. Iterate

If it doesn't fire, work down the debugging list in
`references/gotchas.md` before changing the traffic, and check the
keyword's page in that engine version's docs. Change one thing per run.

Stop after about five build-and-test cycles without progress. Report to
the user what fires, what doesn't, and your best diagnosis, rather than
looping.

A rule that fires only with an engine override (inline mode), or only with
a stand-in setter, counts as done if you say so clearly.

## 7. Report

1. **List the frames:** `$VENV/bin/python $SKILL/scripts/pcap_lint.py
   --frames <name>.pcap`. Write the README's frame table from this
   listing, not from memory. The alert often lands on a later packet than
   the one carrying the matched bytes; record both.
2. **Write `README.md`** from `references/writeup.md`:
   - the result per engine, with alert lines and job links;
   - whether the traffic is publicly confirmed;
   - what's in the capture;
   - an explicit list of everything invented;
   - notes;
   - sources, with links, flagging any seen only as search snippets.
3. **Tell the user:**
   - the full absolute path of the pcap and the output directory;
   - the per-version result;
   - the main things invented;
   - inspection limits that depend on their sensors' config (`body-limit`);
   - anything they need to decide on.

## Ground rules

- Never claim the pcap fires without a passing test from this run. If
  testing wasn't possible, the pcap is UNVERIFIED; say so.
- Never present invented details as researched ones.
- No real victim data, working malware or live credentials in the pcap.
  See `references/realism.md`.
- Never download or run malware samples or exploit code; read them.
- Ask before using the docker fallback, before changing the user's rule,
  and before building traffic that contradicts the sources.
- Keep the capture focused: the threat's traffic and the context that
  explains it, not background noise.
