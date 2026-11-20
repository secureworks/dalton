# Write-up template

Save this as `README.md` in the output directory and fill in every
section. Keep it factual. Say plainly what is confirmed by sources and what
is invented. The user may hand the pcap to others, who will rely on this
file.

Read back any escape sequence you wrote into it (`\u0020`, `\x0d`): a
tool call can decode it into the character it stands for, so the README
shows a space where you meant `\u0020`. Check the bytes with `grep -n`.

````markdown
# <sid>: <rule msg>

<One paragraph: what the traffic is, who talks to whom, and why it fires
the rule.>

## Result

| Engine | Fired | Alerts | Job |
| --- | --- | --- | --- |
| suricata/8.0.6 | yes | 1 | <Dalton job URL, or "docker: suricata-current:latest"> |
| suricata/7.0.17 | not loaded: needs Suricata 8 (smtp.mail_from) | - | <...> |

Alert line(s), as the engine printed them (`alert_lines` in the test
output):

```
<eve or fast.log alert line per engine>
```

Test settings beyond the defaults: <none | e.g. stream.inline=true, and
why>. Stand-in rules: <none | sid and what it stands in for>.

## Is this traffic publicly confirmed?

<One of: confirmed (sources show this traffic), partly (what is and isn't
confirmed), not confirmed (no public description found; built from the
rule). Be specific.>

## What's in the capture

| Frames | Flow | What |
| --- | --- | --- |
| 1-2 | 10.20.30.41:53000 -> 10.20.0.53:53 | DNS A lookup for ... |
| 3-13 | 10.20.30.41:51515 -> 203.0.113.80:80 | HTTP POST check-in; the matched bytes are in frame 6, the alert is logged on frame 7 (the ACK) |

Build this table from `pcap_lint.py --frames`, not from memory.

## Invented

- <Every invented element: addresses, ports, names, timing, header values,
  bodies, keys, and anything filled with seeded random bytes.>

## Notes

- <Conflicts between the rule and sources, rule quirks, IPS-only
  behaviour, pcap_lint findings left on purpose.>
- <Inspection limits the rule depends on, such as an HTTP body limit
  (`body-limit` note): what Dalton used, and that the user's sensors may
  be configured differently.>

## Files

- `<name>.pcap`: the capture
- `build.py` (+ `pcapkit.py`): rebuilds it byte-for-byte
- `<name>.synth`: Flowsynth source, if used (paste into Dalton's Flowsynth UI)
- `<name>.crt`/`.key`, `session.json`, `<name>-keys.log`: TLS builds only;
  the cached cert and handshake that keep rebuilds byte-identical, and the
  key log that decrypts the capture in Wireshark
- `test.rules`: the rule, plus any stand-in rules

Rebuild with the Python of any venv that has the skill's
`requirements.txt` installed: `python -I build.py`.

## Sources

- [Title](URL): what it supported
- [Title](URL): what it supported (seen only as a search snippet)

(or "None: no public description was found")
````
