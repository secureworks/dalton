import unittest

from flask import Flask

from app import create_app


class TestFactory(unittest.TestCase):
    def test_testing(self):
        result = create_app({"TESTING": True})
        self.assertIsInstance(result, Flask)
        self.assertTrue(result.testing)
