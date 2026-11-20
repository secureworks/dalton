# Researching the threat behind a rule

The goal is traffic that matches what the real threat sends, so the pcap
is useful beyond "it fires". Research before building, but stop once you
have enough: an hour of searching for a generic rule is wasted.

## Where to start

`rule_facts.py` prints `leads` for each rule: CVEs, URLs, hashes and named
families from `reference`, `metadata` and `msg`. The `msg` usually names
the family, exploit or tool.

## Suricata documentation

The rules reference for each engine version under test (from preflight's
`engines`, e.g. `suricata/8.0.6`) is at
`https://docs.suricata.io/en/suricata-<version>/rules/index.html`, with a
page per keyword group (`http-keywords.html`, `payload-keywords.html`,
`flow-keywords.html`, `thresholding.html`...). Use the versioned pages,
not `latest`: buffers and keywords differ between 7 and 8. Read them for
what a buffer holds, what a modifier changes, and keyword defaults.

The engine is the final word: when it behaves differently from the docs,
build to what it does and note the difference in the write-up. Fetching
the docs sends nothing of the user's; it may still need web approval.

## Sources, in rough order

1. **Rulesets the Dalton host already has.** `dalton_client.py preflight`
   lists Dalton's prod rulesets (e.g. ET). The paths in `prod_rulesets` are
   inside Dalton's controller container, and Dalton's API can't search
   them. When Dalton runs in Docker on this machine, preflight also prints
   `prod_rulesets_on_host`:
   - `host_dir`: the same files on this machine; grep them there.
   - `container`: if there's no `host_dir`, grep inside it:
     `docker exec <container> grep -h -i PATTERN /opt/dalton/rulesets/suricata/*.rules`

   Without either, ask the user where the rulesets are.

   Grep for the family, CVE or distinctive bytes. Other vendors' rules for
   the same threat often carry the real bytes, md5 references to samples,
   and sibling rules that show the rest of the conversation. If you can't
   reach the rulesets, run the finished pcap with `--prod-ruleset` instead:
   other vendors' rules firing on it is also corroboration.
2. **CVE data.** Query the NVD API:
   `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-YYYY-NNNN`.
   The HTML page renders client-side and comes back empty to scripts.
   Follow its references: vendor advisories, researcher write-ups, PoCs.
   Dead links are often on the Wayback Machine
   (`https://web.archive.org/web/2016*/<url>`).
3. **Malware families.** Malpedia, vendor threat reports, public sandbox
   reports, and analysis blogs. Analysis blogs often include request and
   response captures or protocol tables.
4. **Public pcaps.** malware-traffic-analysis.net and similar. Use them as
   reference for shape, headers and timing. Don't ship their bytes: they
   can contain real victim data and live payloads.
5. **Tool and C2 framework source.** Public profiles (for example Malleable
   C2), PoC code, and open-source implants. Read the code to see what goes
   on the wire. Don't run it.

If web access needs approval in your environment, ask for it. If there is
none, say so and build from the rule and what you already know.

## Read the bytes, not a summary

Fetch tools that summarize a page paraphrase it, drop code blocks, and
may withhold exploit details outright. When a page carries bytes that
matter (a request, headers, a payload, a code sample), fetch it raw
(`curl -sL`) and read its `<pre>` and `<code>` blocks. In the source list,
mark pages you read only through a summary, as you mark search snippets.
Like any web access, `curl` may need the user's approval first.

## Test the rule against what was seen

When a source shows attack bytes observed in the wild, check whether the
rule matches them, even if you build the pcap from another source such as
a public PoC. A rule that misses the observed traffic is the most useful
thing the write-up can tell its author. Build that variant, test it, and
put the result under Notes, with the bytes that miss.

For a widely exploited CVE, look past the first PoC to what mass
exploitation sends: honeypot and threat-intel reports, and the public
scanners attackers adopt. They often differ from the PoC (other parts,
fixed boundaries, extra headers), and the write-up should say which one
the pcap follows. If the dominant tool has evasion options, such as body
padding, encodings or chunking, try the rule against those too.

## One source per flow

Keep each flow true to one source. Don't put one tool's or actor's headers
on another's body, or date a later tool's traffic to an earlier sighting:
that is a session nobody sent. If you do combine sources, say so in the
write-up, and don't list the combination as confirmed.

## When there's nothing to find

For a generic or behavioural rule, there may be nothing to find: empty
`leads`, a msg that names no family or CVE, no references. In that case
do one or two searches and the ruleset grep. Then stop, and write "Not
confirmed: built from the rule" and "Sources: none".

## Encrypted or encoded protocols

Before inventing ciphertext, try to recover the plaintext structure:

- Look for static keys published for the family.
- When two rules from different vendors match different encrypted bytes of
  the same message, XOR them against a guessed plaintext. A consistent
  keystream confirms the guess.
- Check known message formats from academic papers on the family.

If that works, build the session in the real protocol and say how the
plaintext was recovered. If not, use bytes the rule requires plus seeded
random bytes, and say so.

## Conflicts

The rule is canonical: the pcap must fire it. When sources disagree with
the rule, build to the rule and record the disagreement in the write-up.
Examples are a different port, an inverted direction, or a threshold far
from what the advisory describes. Ask the user before going further if
satisfying the rule means traffic no real instance would produce. They may
want the rule fixed instead.

## Safety

- Never download, unpack or run malware samples, and never run exploit
  PoCs against anything. Read them.
- Don't send the user's rule text, names or project details to outside
  services beyond the search terms the research needs.

## Record as you go

Keep a list of every source with its URL and what it supported. Mark the
sources you saw only as search-result snippets and couldn't open. The
write-up's Sources section comes from this list.
