"""Unit tests for dalton module."""

import json
import random
import unittest
from unittest import mock

import pytest

from app.dalton import (
    REDIS_EXPIRE,
    STAT_CODE_DONE,
    create_hash,
    prefix_strip,
)


@pytest.mark.usefixtures("client")
class TestDalton(unittest.TestCase):
    """Test dalton functionality."""

    def test_dalton_main(self):
        """Ensure the index page loads."""
        res = self.client.get("/dalton/")
        self.assertEqual(res.status_code, 200, "It should render")
        self.assertIn(b"Dalton", res.data)

    def test_dalton_about(self):
        response = self.client.get("/dalton/about")
        self.assertIn(b"About Dalton", response.data)

    def test_prefix_strip(self):
        """Test the prefix_strip function."""
        prefixes_to_strip = ["abcd", "defg"]
        self.assertEqual(prefix_strip("abcd1234", prefixes_to_strip), "1234")
        self.assertEqual(prefix_strip("defg1234", prefixes_to_strip), "1234")
        self.assertEqual(prefix_strip("12345678", prefixes_to_strip), "12345678")
        # Also test with default prefix to strip - "rust_"
        self.assertEqual(prefix_strip("rust_1234"), "1234")
        self.assertEqual(prefix_strip("12345678"), "12345678")

    def test_create_hash(self):
        """Test create_hash with bytes."""
        uid = "73756293-827f-4829-9515-f5a77c36ad0c"
        ip = "127.0.0.22"
        expected = "430637bdaa1e8dd5fc032dc4deb14791"
        digest = create_hash([uid, ip])
        self.assertEqual(expected, digest)

    @mock.patch("app.dalton.get_redis")
    def test_sensor_page(self, get_redis):
        """Check if the sensor page can load."""
        redis = mock.Mock()
        # Return False when asked if "sensors" exists.
        redis.exists.return_value = False
        get_redis.return_value = redis
        res = self.client.get("/dalton/sensor")
        self.assertEqual(res.status_code, 200, "A page with sensors")

    @mock.patch("app.dalton.get_redis")
    def test_request_job(self, get_redis):
        """Try to request a job. It should not crash."""
        redis = mock.Mock()
        redis.lpop.return_value = None
        get_redis.return_value = redis
        versions = ["2.0.9", "3.0", "9.9.9"]
        for version in versions:
            url = f"/dalton/sensor_api/request_job?SENSOR_ENGINE_VERSION={version}"
            res = self.client.get(url)
            self.assertEqual(res.status_code, 200, res.data.decode())

    def test_dalton_get_job(self):
        res = self.client.get("/dalton/sensor_api/get_job/12345")
        self.assertEqual(res.status_code, 200)
        self.assertIn(
            "Job 12345 does not exist on disk.  It is either invalid "
            "or has been deleted.",
            res.data.decode(),
        )

    @mock.patch("app.dalton.get_redis")
    def test_job_results(self, get_redis):
        """Try to provide job results. It should not crash."""
        mock_redis = mock.Mock()
        mock_redis.get.return_value = 1
        get_redis.return_value = mock_redis
        job_id = 34
        url = f"/dalton/sensor_api/results/{job_id}"
        job_results = {"status": "1"}
        data = dict(json_data=json.dumps(job_results))
        res = self.client.post(url, data=data)
        self.assertEqual(res.status_code, 200)

    @mock.patch("app.dalton.create_hash")
    @mock.patch("app.dalton.get_redis")
    def test_post_job_results(self, get_redis, create_hash):
        """Exercise `post_job_results`."""
        redis = mock.Mock()
        redis.get.return_value = 1
        get_redis.return_value = redis
        the_hash = str(random.randint(1, 999999999))
        create_hash.return_value = the_hash
        job_id = random.randint(1, 999999999)
        job_status = str(random.randint(1, 999999999))
        job_status_dict = {"status": job_status}
        data = {
            "json_data": json.dumps(job_status_dict),
        }
        res = self.client.post(f"/dalton/sensor_api/results/{job_id}", data=data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual("OK", res.data.decode())
        redis.set.assert_any_call(f"{job_id}-status", f"Final Job Status: {job_status}")
        redis.set.assert_any_call(f"{the_hash}-current_job", "")
        redis.expire.assert_any_call(f"{the_hash}-current_job", REDIS_EXPIRE)
        redis.set.assert_any_call(f"{job_id}-statcode", STAT_CODE_DONE)

    @mock.patch("app.dalton.get_redis")
    def test_post_job_results_invalid_format(self, get_redis):
        """Validate job id format in `post_job_results`.

        Issue #245
        """
        job_id = "${};!"
        url = f"/dalton/sensor_api/results/{job_id}"
        job_results = {"status": "1"}
        data = dict(json_data=json.dumps(job_results))
        res = self.client.post(url, data=data)
        self.assertIn(
            "Invalid Job ID",
            res.data.decode(),
        )
        self.assertEqual("Error", res.headers["X-Dalton-Webapp"])
