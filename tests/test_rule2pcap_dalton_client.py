import email.parser
import email.policy
import json
import os
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.rule2pcap_scripts import load

dc = load("dalton_client")

CONF = '%YAML 1.1\n---\nvars:\n  address-groups:\n    HOME_NET: "[10.0.0.0/8]"\nstream:\n  inline: auto\n'
# Dalton's error page, trimmed: app/templates/dalton/error.html in the site layout
ERROR_PAGE = """<!DOCTYPE html><html><head>
<link href="/static/css/bootstrap.css" rel="stylesheet">
<style>body { padding-top: 60px; }</style></head><body>
<div class="navbar"><ul class="nav"><li class="active"><a href="/">Dalton Home</a>&nbsp;</li>
<li><a href="/dalton/queue">Queue</a></li><li><a href="/dalton/sensor">Sensors</a></li></ul></div>
<div class="container"><div class="row">
<div class="alert alert-error"><h2><span>Error!</span></h2></div><p/>
<div class="span9">
<p>Invalid rule, action (start of rule) &quot;(msg:&quot; not supported.</p>
</div></div></div></body></html>"""
EVE = "\n".join(
    json.dumps(e)
    for e in (
        {
            "event_type": "alert",
            "pcap_cnt": 4,
            "src_ip": "203.0.113.5",
            "src_port": 80,
            "dest_ip": "10.0.0.5",
            "dest_port": 49152,
            "app_proto": "http",
            "alert": {"signature_id": 1000001, "signature": "TEST one"},
        },
        {"event_type": "anomaly", "anomaly": {"type": "stream", "event": "X"}},
        {"event_type": "flow"},
    )
)


class FakeDalton:
    """Just enough of Dalton's controller API to drive the client."""

    def __init__(self):
        self.mode = "ok"
        self.submissions = []
        self.job_tech = {}
        state = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def reply(self, code, body=b"", ctype="text/plain", headers=None):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(body if isinstance(body, bytes) else body.encode())

            def guard(self):
                if state.mode == "401":
                    self.reply(401, b'{"error": "Authentication required."}')
                    return False
                if state.mode == "setuser":
                    self.reply(302, headers={"Location": "/dalton/setuser"})
                    return False
                return True

            def do_GET(self):
                if not self.guard():
                    return
                path = self.path
                if path.startswith("/dalton/controller_api/get-current-sensors/"):
                    techs = ["suricata/8.0.6/ctf", "suricata/8.0.6", "suricata/7.0.17"]
                    self.reply(200, json.dumps({"sensor_tech": techs}))
                elif path.startswith("/dalton/controller_api/get-prod-rulesets/"):
                    self.reply(200, json.dumps({"prod-rulesets": ["/r/ET.rules"]}))
                elif path.startswith("/dalton/controller_api/request_engine_conf"):
                    self.reply(200, CONF.replace("\n", "\r\n"))
                elif path.startswith("/dalton/controller_api/job_status_code/"):
                    jid = path.rstrip("/").split("/")[-1]
                    timed_out = state.mode == "timeout-old" and (
                        state.job_tech.get(jid) == "suricata/7.0.17"
                    )
                    self.reply(200, "4" if timed_out else "2")
                elif path.startswith("/dalton/controller_api/v2/"):
                    parts = path.rstrip("/").split("/")
                    key, jid = parts[-1], parts[-2]
                    tech = state.job_tech.get(jid, "")
                    error = ""
                    if state.mode == "rule-error" or (
                        state.mode == "old-engine-gap" and tech == "suricata/7.0.17"
                    ):
                        error = (
                            "Error message(s) found in IDS output.\n\n"
                            "Error: detect-parse: unknown rule keyword 'depthh'.\n\n"
                            'Error: detect: error parsing signature "alert ..." at line 1\n'
                        )
                    if state.mode == "other-rule-error" and tech == "suricata/7.0.17":
                        # a second rule in the file, not the one under test
                        error = (
                            "Error message(s) found in IDS output.\n\n"
                            "E: detect-parse: unknown rule keyword 'smtp.mail_from'.\n"
                            'E: detect: error parsing signature "alert smtp any any -> '
                            'any any (smtp.mail_from; content:\\"x\\"; sid:2;)" from '
                            "file /x.rules at line 2\n"
                        )
                    fast = (
                        "11/14/2026-01:02:03.000000  [**] [1:1000001:1] TEST one [**] "
                        "[Classification: (null)] [Priority: 3] {TCP} "
                        "203.0.113.5:80 -> 10.0.0.5:49152\n"
                    )
                    ids = "Suricata version 8.0.6 RELEASE\n"
                    if state.mode == "requires-old" and tech == "suricata/7.0.17":
                        # Suricata 7 skips a rule whose requires: it doesn't meet
                        ids += (
                            "Info: detect: Skipping signature due to missing "
                            "requirements: alert ... sid:1000001; rev:1;) from file "
                            "/x.rules at line 1\n"
                        )
                    if state.mode == "warning":
                        # a warning about a valid rule is not a rule error
                        ids += (
                            "Warning: detect-classtype: signature sid:1000001 uses "
                            'unknown classtype: "my-class", using default priority 3.\n'
                        )
                    if state.mode == "engine-stopped":
                        # e.g. a bad --set: the job is done but no pcap was read
                        error = (
                            "Error message(s) found in IDS output.\n\n"
                            'Error: runmodes: The custom type "bogus" doesn\'t exist\n'
                        )
                    else:
                        ids += "Notice: pcap: read 1 file, 3 packets, 300 bytes\n"
                    if state.mode == "ids-only-error":
                        # Suricata's own format, which the agent's error filter misses
                        ids += (
                            "E: detect-parse: unknown rule keyword 'depthh'.\n"
                            'E: detect: error parsing signature "alert ..." at line 1\n'
                        )
                    data = {"eve": EVE, "alert": fast, "error": error, "ids": ids}.get(
                        key
                    )
                    body = {"error": data is None, "error_msg": None, "data": data}
                    self.reply(200, json.dumps(body), "application/json")
                else:
                    self.reply(404)

            def do_POST(self):
                if not self.guard():
                    return
                length = int(self.headers["Content-Length"])
                raw = self.rfile.read(length)
                msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                    b"Content-Type: "
                    + self.headers["Content-Type"].encode()
                    + b"\r\n\r\n"
                    + raw
                )
                form = {}
                for part in msg.iter_parts():
                    name = part.get_param("name", header="content-disposition")
                    form[name] = part.get_payload(decode=True)
                state.submissions.append(form)
                if state.mode == "error":
                    self.reply(200, ERROR_PAGE)
                elif b"teapotJob" in b"".join(k.encode() for k in form):
                    jid = f"teapot_{len(state.submissions):016x}"
                    state.job_tech[jid] = form["sensor_tech"].decode()
                    self.reply(200, jid)
                else:
                    jid = f"{len(state.submissions):016x}"
                    state.job_tech[jid] = form["sensor_tech"].decode()
                    self.reply(302, headers={"Location": f"/dalton/job/{jid}"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def dalton():
    fake = FakeDalton()
    yield fake
    fake.close()


@pytest.fixture
def files(tmp_path):
    pcap = tmp_path / "x.pcap"
    pcap.write_bytes(b"\xd4\xc3\xb2\xa1fake")
    rules = tmp_path / "test.rules"
    rules.write_text(
        'alert http any any -> any any (msg:"set"; flowbits:set,a; flowbits:noalert; sid:1000000;)\n'
        '# alert http any any -> any any (msg:"off"; sid:999;)\n'
        'alert http any any -> any any (msg:"TEST one"; flowbits:isset,a; sid:1000001;)\n'
    )
    return pcap, rules


def run(capsys, argv):
    code = dc.main(argv)
    return code, json.loads(capsys.readouterr().out)


def test_parse_headers():
    assert dc.parse_headers("X-Key: abc\nbogus\nX-Other:  d e ") == {
        "X-Key": "abc",
        "X-Other": "d e",
    }


def test_default_techs_prefers_stock_config_once_per_version():
    sensors = [
        "suricata/8.0.6/ctf",
        "suricata/8.0.6",
        "suricata/8.0.6",
        "suricata/6.0.1/x",
    ]
    assert dc.default_techs(sensors) == ["suricata/8.0.6", "suricata/6.0.1/x"]


def test_alerting_sids_skips_noalert_and_comments(files):
    _, rules = files
    assert dc.alerting_sids(rules.read_text()) == ["1000001"]


def test_summarise_eve_and_fast_fallback():
    fired, anomalies = dc.summarise(dc.parse_eve(EVE))
    assert fired["1000001"]["count"] == 1
    assert fired["1000001"]["first"]["pcap_cnt"] == 4
    assert anomalies == {"stream:X": 1}
    fast = (
        "11/14/2026-01:02:03.000000  [**] [1:42:3] TEST fast [**] [Classification: x]"
    )
    fired, _ = dc.summarise([], fast)
    assert fired == {
        "42": {"count": 1, "msg": "TEST fast", "first": None, "frames": []}
    }


def test_summarise_lists_every_alert_frame():
    events = [
        {"event_type": "alert", "pcap_cnt": 4, "alert": {"signature_id": 7}},
        {
            "event_type": "alert",
            "pcap_cnt": None,
            "pkt_src": "stream (flow timeout)",
            "alert": {"signature_id": 7},
        },
    ]
    fired, _ = dc.summarise(events)
    assert fired["7"]["count"] == 2
    assert fired["7"]["frames"] == [4, "stream (flow timeout)"]


def test_ruleset_locations_maps_bind_mounts(monkeypatch):
    inspect = [
        {
            "Name": "/other",
            "Mounts": [{"Type": "bind", "Source": "/x", "Destination": "/data"}],
        },
        {
            "Name": "/dalton_controller",
            "Mounts": [
                # a shallower mount the deeper one shadows
                {"Type": "bind", "Source": "/srv/dalton", "Destination": "/opt/dalton"},
                {
                    "Type": "bind",
                    "Source": "/home/u/dalton/rulesets",
                    "Destination": "/opt/dalton/rulesets",
                },
            ],
        },
    ]

    def fake_run(cmd, **kw):
        out = "a1\nb2\n" if cmd[:2] == ["docker", "ps"] else dc.json.dumps(inspect)
        return dc.subprocess.CompletedProcess(cmd, 0, stdout=out)

    monkeypatch.setattr(dc.shutil, "which", lambda name: "/usr/bin/docker")
    monkeypatch.setattr(dc.subprocess, "run", fake_run)
    where = dc.ruleset_locations(["/opt/dalton/rulesets/suricata/et.rules"])
    assert where == {
        "container": "dalton_controller",
        "host_dir": "/home/u/dalton/rulesets/suricata",
    }
    assert dc.ruleset_locations(["/elsewhere/et.rules"]) is None
    # a named volume has no host directory to grep
    inspect[1]["Mounts"][1] = {
        "Type": "volume",
        "Source": "/var/lib/docker/volumes/r/_data",
        "Destination": "/opt/dalton/rulesets",
    }
    where = dc.ruleset_locations(["/opt/dalton/rulesets/suricata/et.rules"])
    assert where == {"container": "dalton_controller", "host_dir": None}


def test_failed_setter_blocks_the_rule_that_checks_its_bit():
    rules = (
        'alert tls any any -> any any (msg:"s"; tls.alpn; content:"h2"; '
        "flowbits:set,r2p.x; flowbits:noalert; sid:100;)\n"
        'alert tcp any any -> any any (msg:"t"; flowbits:isset,r2p.x; '
        "flowbits:set,r2p.y; sid:101;)\n"
        'alert tcp any any -> any any (msg:"u"; flowbits:isset,r2p.y|r2p.z; sid:102;)\n'
        'alert tcp any any -> any any (msg:"flowbits:isset,r2p.x;"; sid:103;)\n'
        'alert tcp any any -> any any (msg:"v"; xbits:set,q,track ip_src; sid:104;)\n'
        'alert tcp any any -> any any (msg:"w"; xbits:isset,q,track ip_src; sid:105;)\n'
        'alert tcp any any -> any any (msg:"x"; flowbits:set,r2p.x; sid:106;)\n'
    )
    # 101 and, through it, 102 depend on 100; the bit in 103's msg is text
    assert dc.broken_by(["100"], rules.rsplit("\n", 2)[0]) >= {
        "100",
        "101",
        "102",
    }
    assert "103" not in dc.broken_by(["100"], rules)
    assert dc.broken_by(["104"], rules) == {"104", "105"}
    # another rule (106) still sets r2p.x
    assert dc.broken_by(["100"], rules) == {"100"}
    # xbits tracked by ip_pair live apart from hostbits
    pair = (
        'alert tcp any any -> any any (msg:"a"; xbits:set,foo,track ip_pair; sid:1;)\n'
        'alert tcp any any -> any any (msg:"b"; hostbits:set,foo,src; sid:2;)\n'
        'alert tcp any any -> any any (msg:"c"; hostbits:isset,foo,src; sid:3;)\n'
        'alert tcp any any -> any any (msg:"d"; xbits:isset,foo,track ip_pair; sid:4;)\n'
        'alert tcp any any -> any any (msg:"e"; xbits:isset,foo,track ip_src; sid:5;)\n'
    )
    assert dc.broken_by(["2"], pair) == {"2", "3", "5"}
    assert dc.broken_by(["1"], pair) == {"1", "4"}
    # but a rule that only unsets it doesn't
    unsets = rules.replace(
        "flowbits:set,r2p.x; sid:106", "flowbits:unset,r2p.x; sid:106"
    )
    assert {"100", "101", "102"} <= dc.broken_by(["100"], unsets)

    def report():
        line = 'E: detect: error parsing signature "alert tls ... sid:100;)"'
        return {
            "results": [{"tech": "suricata/7.0.17", "status": "done", "errors": line}]
        }

    lone = rules.split("\n")[0] + "\n" + rules.split("\n")[1]
    r = report()
    dc.mark_rule_errors(r, ["101"], lone)
    assert r["not_loaded"] == ["suricata/7.0.17"] and r["rule_warnings"] == []
    r = report()
    dc.mark_rule_errors(r, ["103"], rules)
    assert r["not_loaded"] == [] and "sid(s) 100" in r["rule_warnings"][0]


def test_apply_sets_edits_nested_keys():
    out = dc.apply_sets(
        CONF,
        [
            "stream.inline=true",
            "vars.address-groups.HOME_NET=[192.168.0.0/16]",
            "new.key=1",
        ],
    )
    assert "inline: 'true'" in out or "inline: true" in out
    assert (
        "HOME_NET: '[192.168.0.0/16]'" in out or 'HOME_NET: "[192.168.0.0/16]"' in out
    )
    assert "new:\n  key:" in out


def test_preflight_reports_sensors(dalton, capsys):
    _, report = run(capsys, ["preflight", "--url", dalton.url])
    assert report["dalton"]["auth"] == "ok"
    assert report["dalton"]["prod_rulesets"] == ["/r/ET.rules"]
    assert report["ready"]["dalton"] is True


@pytest.mark.parametrize("mode", ["401", "setuser"])
def test_preflight_reports_auth_required(dalton, capsys, mode):
    dalton.mode = mode
    code, report = run(capsys, ["preflight", "--url", dalton.url])
    assert code == 1
    assert report["dalton"]["auth"] == "required"
    assert report["ready"]["dalton"] is False


def test_preflight_unreachable(capsys):
    code, report = run(capsys, ["preflight", "--url", "http://127.0.0.1:9"])
    assert code == 1
    assert report["dalton"]["reachable"] is False


def test_test_runs_one_job_per_version_and_passes(dalton, files, capsys):
    pcap, rules = files
    code, report = run(
        capsys,
        [
            "test",
            "--url",
            dalton.url,
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--set",
            "stream.inline=true",
        ],
    )
    assert code == 0 and report["pass"] is True
    assert report["expect"] == ["1000001"]
    assert [r["tech"] for r in report["results"]] == [
        "suricata/8.0.6",
        "suricata/7.0.17",
    ]
    first = report["results"][0]
    assert first["job_url"] == f"{dalton.url}/dalton/job/{first['jid']}"
    assert first["anomalies"] == {"stream:X": 1}
    sub = dalton.submissions[0]
    assert sub["sensor_tech"] == b"suricata/8.0.6"
    assert sub["coverage-pcap0"] == pcap.read_bytes()
    assert (
        b"inline: " in sub["custom_engineconf"]
        and b"auto" not in sub["custom_engineconf"]
    )
    assert sub["optionEveLog"] == b"on"


def test_test_fails_when_expected_sid_missing(dalton, files, capsys):
    pcap, rules = files
    code, report = run(
        capsys,
        [
            "test",
            "--url",
            dalton.url,
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--expect-sid",
            "5",
            "--engine-tech",
            "suricata/7.0.17",
            "--teapot",
        ],
    )
    assert code == 1 and report["pass"] is False
    assert report["results"][0]["jid"].startswith("teapot_")
    assert report["results"][0]["expected_fired"] == {"5": False}


def test_submission_error_page_is_reported(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "error"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 2
    assert report["error"].endswith(
        'Invalid rule, action (start of rule) "(msg:" not supported.'
    )
    assert "Dalton Home" not in report["error"] and "padding" not in report["error"]


def test_docker_dry_run_prints_commands_and_runs_nothing(files, capsys, tmp_path):
    pcap, rules = files
    code, report = run(
        capsys,
        [
            "test",
            "--runner",
            "docker",
            "--dry-run",
            "--image",
            "suricata-current:latest",
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--set",
            "stream.inline=true",
        ],
    )
    assert code == 0 and report["dry_run"] is True
    (cmd,) = report["commands"]
    # never pulls an image: the docker runner uses local images only
    assert cmd.startswith("docker run --rm --pull never --name rule2pcap-")
    assert " --network none " in cmd
    # nothing was created: the paths are placeholders for a real run's temp dir
    assert "rule2pcap-XXXXXXXX" in cmd and "rule2pcap-XXXXXXXX" in report["note"]
    assert f"{pcap}:/in/x.pcap:ro" in cmd
    assert "--runmode single" in cmd and "--set stream.inline=true" in cmd
    # the time limit is enforced inside the container, so it always ends normally
    assert "timeout 600 suricata -k none" in cmd
    if hasattr(os, "getuid"):
        assert f"chown -R {os.getuid()}:{os.getgid()} /out" in cmd


def test_tiny_pcap_is_a_clean_single_packet(tmp_path):
    path = tmp_path / "v.pcap"
    dc.tiny_pcap(str(path))
    result = load("pcap_lint").lint(str(path))
    assert result["summary"]["packets"] == 1
    assert [f for f in result["findings"] if f["level"] == "error"] == []


@pytest.mark.parametrize("mode, valid", [("ok", True), ("rule-error", False)])
def test_validate_reports_rule_errors(dalton, files, capsys, mode, valid):
    _, rules = files
    dalton.mode = mode
    code, report = run(capsys, ["validate", "--url", dalton.url, "--rules", str(rules)])
    assert report["valid"] is valid and code == (0 if valid else 1)
    first = report["results"][0]
    assert first["loaded"] is valid
    assert len(first["rule_errors"]) == (0 if valid else 2)
    assert dalton.submissions[0]["coverage-pcap0"][:4] == b"\xd4\xc3\xb2\xa1"


def test_engine_that_cannot_load_the_rule_is_reported_not_failed(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "rule-error"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    # every engine rejected the rules: nothing to judge, so not a pass
    assert code == 1 and report["pass"] is False
    assert report["not_loaded"] == ["suricata/8.0.6", "suricata/7.0.17"]


def test_test_reports_alert_lines_and_pkt_src(dalton, files, capsys):
    pcap, rules = files
    _, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    first = report["results"][0]
    assert first["alert_lines"][0].endswith("203.0.113.5:80 -> 10.0.0.5:49152")
    assert "pkt_src" in first["fired"]["1000001"]["first"]


def test_older_engine_missing_a_keyword_is_a_version_gap(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "old-engine-gap"
    code, report = run(capsys, ["validate", "--url", dalton.url, "--rules", str(rules)])
    assert code == 0 and report["valid"] is True
    assert report["needs_newer_engine"] is True
    assert report["loaded_on"] == ["suricata/8.0.6"]
    assert report["not_loaded"] == ["suricata/7.0.17"]
    assert report["results"][1]["unknown_keywords"] == ["depthh"]
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 0 and report["pass"] is True
    assert report["results"][1]["expected_fired"] is None


def test_preflight_lists_the_engines_test_will_use(dalton, capsys):
    _, report = run(capsys, ["preflight", "--url", dalton.url])
    assert report["dalton"]["engines"] == ["suricata/8.0.6", "suricata/7.0.17"]


def test_validate_finds_errors_only_in_engine_output(dalton, files, capsys):
    _, rules = files
    dalton.mode = "ids-only-error"
    code, report = run(capsys, ["validate", "--url", dalton.url, "--rules", str(rules)])
    assert code == 1 and report["valid"] is False
    for result in report["results"]:
        assert result["unknown_keywords"] == ["depthh"]
        assert result["rule_errors"][0].startswith("E: detect-parse")


def test_unfinished_job_is_not_run_and_fails(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "timeout-old"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 2 and report["pass"] is False
    assert report["not_run"] == ["suricata/7.0.17"] and report["not_loaded"] == []


def test_nothing_to_check_fails(dalton, files, capsys, tmp_path):
    pcap, _ = files
    rules = tmp_path / "noalert.rules"
    rules.write_text(
        'alert tcp any any -> any any (msg:"set"; flowbits:set,x; noalert; sid:5;)\n'
    )
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 1 and report["pass"] is False and "no sids" in report["error"]


@pytest.mark.parametrize("command", ["test", "validate"])
def test_engine_that_stopped_before_the_pcap_is_not_run(dalton, files, capsys, command):
    # e.g. --set runmode=bogus: Dalton marks the job done, but nothing was read
    pcap, rules = files
    dalton.mode = "engine-stopped"
    argv = [command, "--url", dalton.url, "--rules", str(rules)]
    if command == "test":
        argv += ["--pcap", str(pcap)]
    code, report = run(capsys, argv)
    assert code == 2
    assert report["not_run"] == ["suricata/8.0.6", "suricata/7.0.17"]
    assert report["not_loaded"] == []
    assert report.get("pass", report.get("valid")) is False
    assert "runmodes" in report["results"][0]["errors"]


def test_alerting_sids_edge_cases():
    rules = (
        'alert tcp any any -> any any (msg:"x"; noalert; \\\n'
        "  sid:1;)\n"
        'pass tcp any any -> any any (msg:"p"; sid:2;)\n'
        'alert tcp any any -> any any (msg:"has sid:3; in msg"; sid:4;)\n'
        'alert tcp any any -> any any (msg:"two \\\n'
        '  lines"; sid:5;)\n'
    )
    assert dc.alerting_sids(rules) == ["4", "5"]


def test_continued_rules_are_sent_joined(dalton, files, capsys, tmp_path):
    pcap, _ = files
    rules = tmp_path / "multi.rules"
    rules.write_text(
        'alert http any any -> any any (msg:"TEST one"; \\\n    sid:1000001;)\n'
    )
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 0 and report["expect"] == ["1000001"]
    sent = dalton.submissions[0]["custom_ruleset"].decode()
    assert sent == 'alert http any any -> any any (msg:"TEST one";     sid:1000001;)\n'


def test_docker_keep_logs_reuse_starts_clean(files, capsys, tmp_path, monkeypatch):
    pcap, rules = files
    keep = tmp_path / "logs"
    runs = []

    def fake_run(cmd, **kwargs):
        # stands in for docker: appends one alert to eve.json, as Suricata does
        log_dir = next(v.split(":")[0] for v in cmd if str(v).endswith(":/out"))
        sid = 1000001 if not runs else 2
        runs.append(sid)
        with open(os.path.join(log_dir, "eve.json"), "a") as fh:
            alert = {"event_type": "alert", "alert": {"signature_id": sid}}
            fh.write(json.dumps(alert) + "\n")
        out = "i: pcap: read 1 file, 3 packets, 300 bytes\n"
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(dc.subprocess, "run", fake_run)
    argv = [
        "test",
        "--runner",
        "docker",
        "--image",
        "suricata-current:latest",
        "--pcap",
        str(pcap),
        "--rules",
        str(rules),
        "--keep-logs",
        str(keep),
    ]
    assert run(capsys, argv)[0] == 0
    code, report = run(capsys, argv)
    # the second run's alert only, not the first run's left in the reused directory
    assert code == 1 and list(report["results"][0]["fired"]) == ["2"]


@pytest.mark.parametrize(
    "line, is_error",
    [
        ("Error: detect-parse: unknown rule keyword 'depthh'.", True),
        ('E: detect: error parsing signature "alert ..." from file x at line 1', True),
        (
            "[10 - Suricata-Main] 2026-11-14 Error: detect: error parsing signature",
            True,
        ),
        (
            "<Error> - [ERRCODE: SC_ERR_INVALID_SIGNATURE(39)] - error parsing "
            'signature "alert ..."',
            True,
        ),
        (
            "Warning: detect-classtype: signature sid:1 uses unknown classtype: "
            '"x", using default priority 3.',
            False,
        ),
        (
            "Warning: detect-filestore: One or more rule(s) depends on the "
            "file-store output",
            False,
        ),
        ("Notice: detect: 1 rule files processed.", False),
        ("Error: conf-yaml-loader: Failed to parse configuration file", False),
    ],
)
def test_rule_error_lines(line, is_error):
    assert bool(dc.RULE_ERROR_RE.search(line)) is is_error


def test_warning_about_a_valid_rule_still_passes(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "warning"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    assert code == 0 and report["pass"] is True and report["not_loaded"] == []


@pytest.mark.parametrize(
    "line",
    [
        "Notice: pcap: read 1 file, 3 packets, 300 bytes",  # 7 and later
        "<Notice> - Pcap-file module read 1 files, 3 packets, 300 bytes",  # 4.1-6
        "<Notice> - Pcap-file module read 4 packets, 1234 bytes",  # 4.0 and older
    ],
)
def test_pcap_read_line_across_versions(line):
    assert dc.PCAP_READ_RE.search(line)


def test_continuation_with_trailing_whitespace():
    text = 'alert tcp any any -> any any (msg:"x"; \\  \n  sid:1;)\n'
    assert dc.join_continuations(text) == (
        'alert tcp any any -> any any (msg:"x";   sid:1;)\n'
    )
    assert dc.alerting_sids(text) == ["1"]


def test_apply_sets_list_index():
    conf = "%YAML 1.1\n---\noutputs:\n  - fast:\n      enabled: yes\n  - eve-log:\n      enabled: yes\n"
    out = dc.apply_sets(conf, ["outputs.1.eve-log.enabled=no"])
    assert "- eve-log:\n    enabled: 'no'" in out and "enabled: true" in out
    with pytest.raises(dc.DaltonError, match="no item 5"):
        dc.apply_sets(conf, ["outputs.5.x=1"])


def test_another_rule_failing_does_not_drop_the_engine(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "other-rule-error"
    code, report = run(
        capsys,
        [
            "test",
            "--url",
            dalton.url,
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--expect-sid",
            "1000001",
        ],
    )
    # sid 2 failed on 7.0.17, but the expected sid loaded: judge the engine
    assert code == 0 and report["pass"] is True and report["not_loaded"] == []
    assert report["results"][1]["failed_sids"] == ["2"]
    assert report["results"][1]["expected_fired"] == {"1000001": True}
    assert "sid(s) 2" in report["rule_warnings"][0]
    # but if the failing rule is the one expected, the engine isn't judged
    _, report = run(
        capsys,
        [
            "test",
            "--url",
            dalton.url,
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
            "--expect-sid",
            "2",
        ],
    )
    assert report["not_loaded"] == ["suricata/7.0.17"]


def test_rule_skipped_for_requires_is_not_loaded(dalton, files, capsys):
    pcap, rules = files
    dalton.mode = "requires-old"
    code, report = run(
        capsys,
        ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)],
    )
    # judged on 8.0.6 only; 7.0.17 needs a newer engine, not better traffic
    assert code == 0 and report["pass"] is True
    assert report["not_loaded"] == ["suricata/7.0.17"]
    code, report = run(capsys, ["validate", "--url", dalton.url, "--rules", str(rules)])
    assert code == 0 and report["valid"] is True
    assert report["needs_newer_engine"] is True


def test_docker_runner_strips_rule_indentation(files, capsys, tmp_path, monkeypatch):
    pcap, _ = files
    rules = tmp_path / "indented.rules"
    rules.write_text('  alert tcp any any -> any any (msg:"x"; sid:1000001;)\n')
    sent = []

    def fake_run(cmd, **kwargs):
        rules_file = next(
            v.split(":")[0] for v in cmd if str(v).endswith(":/rules/test.rules:ro")
        )
        sent.append(open(rules_file).read())
        return subprocess.CompletedProcess(cmd, 0, "i: pcap: read 1 file\n", "")

    monkeypatch.setattr(dc.subprocess, "run", fake_run)
    run(
        capsys,
        [
            "test",
            "--runner",
            "docker",
            "--image",
            "suricata-current:latest",
            "--pcap",
            str(pcap),
            "--rules",
            str(rules),
        ],
    )
    assert sent == ['alert tcp any any -> any any (msg:"x"; sid:1000001;)\n']


def test_expect_absent(dalton, files, capsys):
    pcap, rules = files
    base = ["test", "--url", dalton.url, "--pcap", str(pcap), "--rules", str(rules)]
    # the fake fires 1000001: a must-not-fire check on it fails
    code, report = run(capsys, base + ["--expect-absent", "1000001"])
    assert code == 1 and report["pass"] is False
    assert report["expect"] == [] and report["expect_absent"] == ["1000001"]
    assert report["results"][0]["expected_absent"] == {"1000001": False}
    # and one on a sid that doesn't fire passes, alongside the default expect
    code, report = run(capsys, base + ["--expect-absent", "4242"])
    assert code == 0 and report["pass"] is True and report["expect"] == ["1000001"]


def test_duplicate_rule_is_loaded_not_failed():
    rule = 'alert http any any -> any any (msg:"x"; content:"GET"; sid:777; rev:1;)'
    errors = (
        f'E: detect-parse: Duplicate signature "{rule}"\n'
        f'E: detect: error parsing signature "{rule}" from file /w/r.rules at line 2\n'
    )
    report = {
        "results": [{"tech": "suricata/8.0.6", "status": "done", "errors": errors}]
    }
    dc.mark_rule_errors(report, ["777"], rule + "\n" + rule)
    (r,) = report["results"]
    assert r["loaded"] and r["rule_errors"] == [] and report["not_loaded"] == []
    assert "sid(s) 777 twice" in report["rule_warnings"][0]
    # another rule's real error is still reported
    bad = 'alert tcp any any -> any any (msg:"y"; nope; sid:8;)'
    report["results"][0]["errors"] = (
        errors + f'E: detect: error parsing signature "{bad}" from file x at line 3\n'
    )
    dc.mark_rule_errors(report, ["8"], rule + "\n" + bad)
    assert report["not_loaded"] == ["suricata/8.0.6"]
