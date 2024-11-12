import unittest

import pytest


@pytest.mark.usefixtures("client")
class TestDalton(unittest.TestCase):
    def test_dalton_about(self):
        response = self.client.get("/dalton/about")
        assert b"About Dalton" in response.data
