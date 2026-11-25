import csv
import io
import json
import os
import re
import signal
import subprocess
import sys
import tempfile

import guard
from flask import Flask, jsonify, request
from legacy_keywords import LEGACY_KEYWORD_ALIASES

SURICATA_BINARY = "suricata"

# SLS (suricata-language-server) is GPL-3.0; this file is Apache-2.0. It is
# invoked here only as a separate OS process via its own --batch-file CLI,
# never imported, so the two stay arm's-length programs talking over an
# argv/stdout boundary rather than one combined/linked work. Its console
# script lives next to this interpreter's own binary inside the venv (see
# Dockerfile_suricata's `linter` stage).
SLS_BINARY = os.path.join(
    os.path.dirname(os.path.abspath(sys.executable)), "suricata-language-server"
)
# guard.MAX_LINES is the only line limit. SLS's own --max-lines is consulted
# solely on the LSP didChange path, never in --batch-file mode, so passing it
# here would be a knob that does nothing.
SLS_TIMEOUT = 10


def _get_engine_version():
    out = subprocess.run(
        [SURICATA_BINARY, "-V"], capture_output=True, text=True, check=True
    ).stdout
    match = re.search(r"version\s+([\d.]+)", out)
    return match.group(1) if match else out.strip()


def _get_keywords():
    """Parse `suricata --list-keywords=csv` and add back the legacy
    sticky-buffer spellings current engines still accept but no longer
    advertise. Keywords come from Suricata itself, not from any
    third-party database - see legacy_keywords.py for why."""
    out = subprocess.run(
        [SURICATA_BINARY, "--list-keywords=csv"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    reader = csv.DictReader(io.StringIO(out), delimiter=";")
    by_name = {}
    for row in reader:
        name = row["name"]
        by_name[name] = {
            "name": name,
            "description": row["description"],
            "app_layer": row["app layer"],
            "features": row["features"],
            "documentation": row["documentation"],
        }

    keywords = list(by_name.values())
    for legacy_name, modern_name in LEGACY_KEYWORD_ALIASES.items():
        modern = by_name.get(modern_name)
        if modern is None:
            # The engine this container was built against doesn't have the
            # modern keyword under the name we expect - skip rather than
            # offer a completion for something that would fail to parse.
            continue
        keywords.append(
            {
                "name": legacy_name,
                "description": f"{modern['description']} (legacy name for '{modern_name}')",
                "app_layer": modern["app_layer"],
                "features": modern["features"],
                "documentation": modern["documentation"],
                "legacy_for": modern_name,
            }
        )
    return keywords


ENGINE_VERSION = _get_engine_version()
KEYWORDS = _get_keywords()

app = Flask(__name__)


class SyntaxCheckFailed(Exception):
    """SLS did not produce a usable answer (crashed, timed out, or printed
    something that is not a diagnostic). The caller turns this into a
    non-200 so the controller reports "unavailable" rather than passing an
    empty diagnostics list off as a clean bill of health."""


def _run_syntax_check(rule_path, engine_analysis):
    """Run SLS's own batch-mode CLI as a subprocess and parse its
    line-delimited JSON diagnostics (one `suricatals.to_message()` dict per
    line, or the literal "null" for a diagnostic SLS didn't finish building -
    dropped here rather than passed on to the caller).

    Runs with cwd set to the rule file's own (empty, throwaway) directory,
    so any relative path a rule names - SLS resolves dataset load targets
    with a cwd-relative os.path.exists() - hits nothing real. TMPDIR points
    there too: SLS creates its scratch directory with mkdtemp(prefix="sls_")
    under the default temp location, and steering that inside a directory the
    caller is about to remove means a timed-out or crashed run cannot leak
    scratch space onto the container's small tmpfs.
    """
    workdir = os.path.dirname(rule_path)
    cmd = [
        SLS_BINARY,
        "--batch-file",
        rule_path,
        "--suricata-binary",
        SURICATA_BINARY,
    ]
    if not engine_analysis:
        cmd.append("--no-engine-analysis")
    env = dict(os.environ, TMPDIR=workdir)
    # start_new_session puts SLS and the Suricata it forks in their own
    # process group, so a timeout can kill the whole tree. Killing only SLS
    # would leave an orphaned, CPU-bound Suricata holding the container's
    # one CPU while the next check queues behind it.
    proc = subprocess.Popen(
        cmd,
        cwd=workdir,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=SLS_TIMEOUT)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        raise SyntaxCheckFailed(f"SLS timed out after {SLS_TIMEOUT}s") from None

    diagnostics = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            # SLS prints its own "ERROR: ..." lines to stdout; anything that
            # is not a diagnostic means the run did not go as planned.
            raise SyntaxCheckFailed(f"unexpected SLS output: {line[:200]}") from None
        if message is not None:
            diagnostics.append(message)

    # A crash (Suricata failing to start, a traceback inside SLS) leaves a
    # nonzero exit and an empty stdout. Reporting that as "no diagnostics"
    # would render as a clean result for rules that were never checked.
    if proc.returncode != 0 and not diagnostics:
        detail = stderr.strip().splitlines()[-1] if stderr.strip() else ""
        raise SyntaxCheckFailed(
            f"SLS exited with status {proc.returncode}: {detail[:200]}"
        )
    return diagnostics


def _guard_rejection_diagnostic(rejection):
    return {
        "range": {
            "start": {"line": rejection.line, "character": 0},
            "end": {"line": rejection.line, "character": 1},
        },
        "message": rejection.message,
        "source": "Dalton Rule Guard",
        "severity": 1,  # LSP Error
        "content": "",
        "sid": 0,
    }


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine_version": ENGINE_VERSION})


@app.route("/keywords", methods=["GET"])
def keywords():
    return jsonify({"engine_version": ENGINE_VERSION, "keywords": KEYWORDS})


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = {}
    rules = data.get("rules") or ""
    if not isinstance(rules, str):
        # Without this a JSON object or list reaches .strip() and 500s.
        return jsonify({"error": "'rules' must be a string"}), 400
    engine_analysis = bool(data.get("engine_analysis", False))

    try:
        guard.check_rule_buffer(rules)
    except guard.GuardRejection as rejection:
        return jsonify(
            {
                "engine_version": ENGINE_VERSION,
                "diagnostics": [_guard_rejection_diagnostic(rejection)],
            }
        )

    # An empty, isolated working directory (see _run_syntax_check for how it
    # is made the subprocess's cwd and TMPDIR): any relative path a rule
    # names resolves to nothing, rather than something real on the
    # container's filesystem, and whatever SLS leaves behind goes with it.
    with tempfile.TemporaryDirectory() as tmpdir:
        rule_path = os.path.join(tmpdir, "dalton.rules")
        with open(rule_path, "w", encoding="utf-8") as f:
            f.write(rules)
        try:
            messages = _run_syntax_check(rule_path, engine_analysis)
        except SyntaxCheckFailed as exc:
            app.logger.error("syntax check failed: %s", exc)
            return jsonify({"error": str(exc)}), 502

    return jsonify({"engine_version": ENGINE_VERSION, "diagnostics": messages})
