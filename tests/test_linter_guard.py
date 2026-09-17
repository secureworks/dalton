"""Unit tests for dalton-agent/linter/guard.py.

Loaded by file path rather than package import: `dalton-agent/` has a
hyphen in its name, so it isn't an importable Python package, and guard.py
has no heavy imports (no Suricata, no SLS) so it doesn't need to be.
"""

import importlib.util
import os
import unittest

_GUARD_PATH = os.path.join(
    os.path.dirname(__file__), "..", "dalton-agent", "linter", "guard.py"
)
_spec = importlib.util.spec_from_file_location("linter_guard", _GUARD_PATH)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)


class TestSlsDirectiveGuard(unittest.TestCase):
    def assert_rejected(self, buffer):
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer(buffer)

    def assert_allowed(self, buffer):
        guard.check_rule_buffer(buffer)  # should not raise

    def test_suricata_options_directive_rejected(self):
        self.assert_rejected(
            'alert tcp any any -> any any (msg:"x"; sid:1;)\n'
            "## SLS suricata-options: --dump-config"
        )

    def test_pcap_file_directive_rejected(self):
        self.assert_rejected("## SLS pcap-file: /etc/passwd")

    def test_replace_directive_rejected(self):
        self.assert_rejected("## SLS replace: s/foo/bar/")

    def test_dataset_dir_directive_rejected(self):
        self.assert_rejected("## SLS dataset-dir: /tmp")

    def test_suricata_version_directive_rejected(self):
        self.assert_rejected("## SLS suricata-version: 8.0.6")

    def test_no_space_after_hashes_rejected(self):
        self.assert_rejected("##SLS suricata-options: --dump-config")

    def test_leading_tab_rejected(self):
        self.assert_rejected("\t## SLS pcap-file: /etc/passwd")

    def test_extra_spaces_between_hashes_and_sls_rejected(self):
        self.assert_rejected("##   SLS pcap-file: /etc/passwd")

    def test_leading_whitespace_before_hashes_rejected(self):
        self.assert_rejected("   ## SLS pcap-file: /etc/passwd")

    def test_ordinary_comment_not_rejected(self):
        self.assert_allowed(
            "# this is just a normal comment, not an SLS directive\n"
            'alert tcp any any -> any any (msg:"x"; sid:1;)'
        )

    def test_comment_containing_sls_substring_not_a_directive(self):
        # 'SLS' appearing without the '##' prefix pattern must not trip the guard
        self.assert_allowed("# talking about SLS the language server here")

    def test_rejection_reports_offending_line(self):
        buffer = (
            'alert tcp any any -> any any (msg:"x"; sid:1;)\n'
            "## SLS pcap-file: /etc/passwd"
        )
        try:
            guard.check_rule_buffer(buffer)
            self.fail("expected GuardRejection")
        except guard.GuardRejection as e:
            self.assertEqual(e.line, 1)


class TestLuaKeywordGuard(unittest.TestCase):
    def test_lua_keyword_rejected(self):
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer(
                'alert tcp any any -> any any (msg:"x"; lua:evil.lua; sid:1;)'
            )

    def test_luajit_keyword_rejected(self):
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer(
                'alert tcp any any -> any any (msg:"x"; luajit:evil.lua; sid:1;)'
            )

    def test_lua_keyword_with_space_before_colon_rejected(self):
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer(
                'alert tcp any any -> any any (msg:"x"; lua :evil.lua; sid:1;)'
            )

    def test_luaxform_not_mistaken_for_lua_keyword(self):
        """luaxform is a real Suricata 8 keyword, distinct from lua:/luajit:.
        Assert the actual literal token survives into the checked buffer -
        an earlier version of this test built a string that stripped the
        'luaxform:' token before asserting, which passed while proving
        nothing."""
        buffer = (
            'alert tcp any any -> any any (msg:"x"; luaxform:script.lua,arg; sid:1;)'
        )
        self.assertIn("luaxform:", buffer)
        guard.check_rule_buffer(buffer)  # must not raise


class TestSizeLimits(unittest.TestCase):
    def test_byte_limit_enforced(self):
        oversized = "a" * (guard.MAX_BYTES + 1)
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer(oversized)

    def test_byte_limit_counts_utf8_bytes_not_characters(self):
        # each of these characters is 2 bytes in UTF-8 but 1 character;
        # a naive len(str) check would let this slip under the byte cap
        char_count = guard.MAX_BYTES - 10
        oversized = "é" * char_count  # 'é', 2 bytes in UTF-8
        self.assertLess(len(oversized), guard.MAX_BYTES)
        self.assertGreater(len(oversized.encode("utf-8")), guard.MAX_BYTES)
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer(oversized)

    def test_line_limit_enforced(self):
        oversized = "\n".join(["# comment"] * (guard.MAX_LINES + 1))
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer(oversized)

    def test_within_limits_allowed(self):
        guard.check_rule_buffer('alert tcp any any -> any any (msg:"x"; sid:1;)')


class TestDatasetTargets(unittest.TestCase):
    """`dataset:` is an ordinary rule keyword rather than a "## SLS" directive,
    but SLS acts on it too: it copies or creates the named file, joining the
    name onto its temp directory without sanitising it. os.path.join does not
    contain a traversal, so these have to be rejected here."""

    def rule(self, fragment):
        return f'alert http any any -> any any (msg:"x"; {fragment} sid:1;)'

    def rejects(self, fragment):
        try:
            guard.check_rule_buffer(self.rule(fragment))
        except guard.GuardRejection:
            return True
        return False

    def test_traversal_is_rejected(self):
        self.assertTrue(self.rejects("dataset:isset,d, load ../pwned;"))

    def test_absolute_path_is_rejected(self):
        # os.path.join(tmpdir, "/etc/shadow") is "/etc/shadow" -- the temp
        # directory is discarded entirely, so this is the dangerous one.
        self.assertTrue(self.rejects("dataset:isset,d, load /etc/shadow;"))

    def test_subdirectory_and_dotfile_are_rejected(self):
        self.assertTrue(self.rejects("dataset:isset,d, load sub/dir;"))
        self.assertTrue(self.rejects("dataset:isset,d, load .hidden;"))

    def test_every_operation_is_checked(self):
        for op in ("load", "save", "state"):
            with self.subTest(op=op):
                self.assertTrue(self.rejects(f"dataset:isset,d, {op} ../escape;"))

    def test_plain_filenames_are_allowed(self):
        for name in ("mydata", "my_data.lst", "hosts-v2.txt"):
            with self.subTest(name=name):
                self.assertFalse(self.rejects(f"dataset:isset,d, load {name};"))

    def test_rules_without_dataset_are_untouched(self):
        self.assertFalse(self.rejects('content:"load /etc/shadow";'))

    def test_lone_surrogate_is_refused_not_raised(self):
        # JSON permits lone surrogates; encoding one to UTF-8 raises.
        with self.assertRaises(guard.GuardRejection):
            guard.check_rule_buffer("\ud800")


if __name__ == "__main__":
    unittest.main()
