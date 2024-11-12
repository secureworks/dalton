import unittest

import pytest

from app.dalton import prefix_strip


@pytest.mark.usefixtures("client")
class TestDalton(unittest.TestCase):
    def test_dalton_about(self):
        response = self.client.get("/dalton/about")
        assert b"About Dalton" in response.data

    def test_prefix_strip(self):
        """Test the prefix_strip function."""
        prefixes_to_strip = ["abcd", "defg"]
        self.assertEqual(prefix_strip("abcd1234", prefixes_to_strip), "1234")
        self.assertEqual(prefix_strip("defg1234", prefixes_to_strip), "1234")
        self.assertEqual(prefix_strip("12345678", prefixes_to_strip), "12345678")
        # Also test with default prefix to strip - "rust_"
        self.assertEqual(prefix_strip("rust_1234"), "1234")
        self.assertEqual(prefix_strip("12345678"), "12345678")
