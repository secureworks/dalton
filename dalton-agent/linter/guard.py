"""Reject anything in a rule buffer that the Suricata Language Server would
act on beyond ordinary rule syntax checking, before SLS ever sees the text.

SLS is built for a developer editing a file on their own machine and reads
directives straight out of the buffer on that assumption
(signature_validator.py in the SLS source):

  ## SLS suricata-options:   -> shlex.split() straight onto the Suricata argv
  ## SLS pcap-file:          -> reads a file off disk and runs Suricata against it
  ## SLS replace:            -> rewrites the buffer via re.sub
  ## SLS dataset-dir: / suricata-version: -> path and image-tag control

It also copies any `lua:<path>.lua;` (or `luajit:`) target that exists on
disk next to the rules.

This module has no heavy imports so it can be unit tested without Suricata
or SLS installed. Match MORE loosely than SLS's own directive regex
(`^##\\s*SLS\\s+`) - the point is that no buffer should be able to slip past
this guard and then be acted on by SLS, so when in doubt, reject.
"""

import re

SLS_DIRECTIVE = re.compile(r"^\s*##\s*SLS\b")
# Must not match 'luaxform:' - a real Suricata 8 keyword - so the colon has
# to follow directly (optionally through whitespace) after 'lua'/'luajit'.
LUA_KEYWORD = re.compile(r"\blua(?:jit)?\s*:")

# The ordinary `dataset:` rule keyword, not a "## SLS" directive, which is why
# it needs its own rule. _rules_buffer_prepare_dataset() takes the
# load/save/state target straight out of the rule and does
# shutil.copyfile/open(..., "w") on os.path.join(tmpdir, target) with no
# sanitisation. os.path.join does not contain a traversal: "../x" escapes the
# temporary directory and an absolute path replaces it outright, so an
# unchecked target is a create-or-truncate primitive at any path the linter
# user can write. The container's read_only rootfs is what stops that today.
#
# Legitimate use is a bare filename, so that is all we allow. Every
# load/save/state target on a line mentioning dataset: is checked, which is
# looser than SLS's own single-match regex and so errs the safe way.
DATASET_KEYWORD = re.compile(r"\bdataset\s*:", re.IGNORECASE)
DATASET_TARGET = re.compile(r"\b(?:load|save|state)\s+([^\s;]+)", re.IGNORECASE)
SAFE_DATASET_NAME = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.-]*\Z")

MAX_BYTES = 64 * 1024
MAX_LINES = 200


class GuardRejection(Exception):
    """Raised with a human-readable reason; the caller turns this into a
    diagnostic anchored to the offending line rather than an HTTP error."""

    def __init__(self, message, line=0):
        super().__init__(message)
        self.message = message
        self.line = line


def check_rule_buffer(buffer):
    """Raise GuardRejection if `buffer` isn't safe to hand to SLS. Returns
    None on success."""
    try:
        size = len(buffer.encode("utf-8"))
    except UnicodeEncodeError:
        # JSON permits lone surrogates, which are not encodable text. Refuse
        # them here rather than letting .encode() raise out of the request.
        raise GuardRejection("Rules must be valid UTF-8 text.") from None

    if size > MAX_BYTES:
        raise GuardRejection(
            f"Rule buffer is {size} bytes, over the {MAX_BYTES}-byte limit."
        )

    lines = buffer.splitlines()
    if len(lines) > MAX_LINES:
        raise GuardRejection(
            f"Rule buffer has {len(lines)} lines, over the {MAX_LINES}-line limit."
        )

    for lineno, line in enumerate(lines):
        if SLS_DIRECTIVE.match(line):
            raise GuardRejection(
                "'## SLS' directives are not permitted here; they let the "
                "checker read files, rewrite the buffer, or pass arguments "
                "straight to Suricata.",
                line=lineno,
            )
        if LUA_KEYWORD.search(line):
            raise GuardRejection(
                "lua:/luajit: keywords are not permitted here; they would "
                "load a Lua script from disk next to the rules.",
                line=lineno,
            )
        if DATASET_KEYWORD.search(line):
            for target in DATASET_TARGET.findall(line):
                if not SAFE_DATASET_NAME.match(target):
                    raise GuardRejection(
                        "A 'dataset' file must be a plain filename here; "
                        f"{target!r} is not one.",
                        line=lineno,
                    )
