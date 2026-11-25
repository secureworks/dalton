"""Unit tests for dalton module."""

import json
import random
import unittest
from unittest import mock

import pytest

from app.dalton import (
    REDIS_EXPIRE,
    STAT_CODE_DONE,
    STAT_CODE_QUEUED,
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

    @mock.patch("app.dalton.get_redis")
    def test_queue_json_api_empty(self, get_redis):
        """Test queue JSON API returns proper structure when empty."""
        redis = mock.Mock()
        redis.exists.return_value = False
        get_redis.return_value = redis

        res = self.client.get("/dalton/controller_api/get-queue-json")
        self.assertEqual(res.status_code, 200)

        data = json.loads(res.data)
        self.assertIn("jobs", data)
        self.assertIn("summary", data)
        self.assertIn("has_users", data)
        self.assertEqual(data["jobs"], [])
        self.assertEqual(data["summary"]["queued_jobs"], 0)
        self.assertEqual(data["summary"]["running_jobs"], 0)
        self.assertEqual(data["summary"]["total_displayed"], 0)
        self.assertEqual(data["has_users"], False)

    @mock.patch("app.dalton.get_redis")
    def test_queue_json_api_with_jobs(self, get_redis):
        """Test queue JSON API returns jobs correctly."""
        redis = mock.Mock()
        redis.llen.return_value = 2
        redis.lrange.return_value = ["job1", "job2"]

        # Define which keys exist
        existing_keys = {
            "recent_jobs",
            "job1-submission_time",
            "job1-status",
            "job2-submission_time",
            "job2-status",
            "job1-alert",
        }

        def mock_exists(key):
            return key in existing_keys

        def mock_get(key):
            values = {
                "job1-submission_time": "Jan 24 10:00:00",
                "job1-statcode": str(STAT_CODE_DONE),
                "job1-tech": "suricata/7.0.14",
                "job1-user": "testuser",
                "job1-error": None,
                "job1-teapotjob": None,
                "job1-alert": "[**] Alert 1 [**]\n[**] Alert 2 [**]",
                "job2-submission_time": "Jan 24 10:05:00",
                "job2-statcode": str(STAT_CODE_QUEUED),
                "job2-tech": "snort/2.9.20",
                "job2-user": None,
                "job2-error": None,
                "job2-teapotjob": None,
            }
            return values.get(key)

        redis.exists.side_effect = mock_exists
        redis.get.side_effect = mock_get
        get_redis.return_value = redis

        res = self.client.get("/dalton/controller_api/get-queue-json?num_jobs=10")
        self.assertEqual(res.status_code, 200)

        data = json.loads(res.data)
        self.assertEqual(len(data["jobs"]), 2)
        self.assertEqual(data["summary"]["queued_jobs"], 1)
        self.assertEqual(data["has_users"], True)

        # Check first job structure
        job1 = data["jobs"][0]
        self.assertEqual(job1["jid"], "job1")
        self.assertEqual(job1["tech"], "suricata/7.0.14")
        self.assertEqual(job1["user"], "testuser")
        self.assertEqual(job1["alert_count"], 2)  # 2 alerts from mock data
        self.assertIn("status", job1)
        self.assertIn("status_code", job1)

    @mock.patch("app.dalton.get_redis")
    def test_queue_json_api_num_jobs_param(self, get_redis):
        """Test queue JSON API respects num_jobs parameter."""
        redis = mock.Mock()
        redis.exists.return_value = True
        redis.llen.return_value = 5
        redis.lrange.return_value = [f"job{i}" for i in range(5)]

        def mock_get(key):
            # Default values for all jobs
            if "-submission_time" in key:
                return "Jan 24 10:00:00"
            if "-statcode" in key:
                return str(STAT_CODE_DONE)
            if "-tech" in key:
                return "suricata/7.0.14"
            if "-user" in key:
                return None
            if "-error" in key:
                return None
            if "-alert" in key:
                return "0"
            if "-teapotjob" in key:
                return None
            return None

        redis.get.side_effect = mock_get
        get_redis.return_value = redis

        # Request only 2 jobs
        res = self.client.get("/dalton/controller_api/get-queue-json?num_jobs=2")
        self.assertEqual(res.status_code, 200)

        data = json.loads(res.data)
        self.assertEqual(len(data["jobs"]), 2)
        self.assertEqual(data["summary"]["total_displayed"], 2)

    @mock.patch("app.dalton.get_redis")
    def test_queue_json_api_invalid_num_jobs(self, get_redis):
        """Test queue JSON API handles invalid num_jobs gracefully."""
        redis = mock.Mock()
        redis.exists.return_value = False
        get_redis.return_value = redis

        # Test with invalid string
        res = self.client.get("/dalton/controller_api/get-queue-json?num_jobs=invalid")
        self.assertEqual(res.status_code, 200)

        # Test with negative number (should use default)
        res = self.client.get("/dalton/controller_api/get-queue-json?num_jobs=-5")
        self.assertEqual(res.status_code, 200)


@pytest.mark.usefixtures("client")
class TestRuleKeywordsProxy(unittest.TestCase):
    """Test the /dalton/controller_api/rule_keywords fail-open proxy to the
    linter's /keywords endpoint. auth_prefix is "disabled" by default in
    tests (as in the shipped dalton.conf), so check_user passes through
    without any auth mocking needed."""

    def setUp(self):
        import app.dalton as dalton_module

        self.dalton_module = dalton_module
        # the in-process cache is module-level state; don't leak it between tests
        self._reset_cache()

    def tearDown(self):
        self._reset_cache()

    def _reset_cache(self):
        self.dalton_module._keywords_cache = None
        self.dalton_module._keywords_cache_time = 0.0

    def _expire_cache(self):
        """Age the cached payload past KEYWORDS_CACHE_TTL so the next request
        goes back to the linter."""
        self.dalton_module._keywords_cache_time -= (
            self.dalton_module.KEYWORDS_CACHE_TTL + 1
        )

    def _mock_response(self, status=200, body=b'{"keywords": ["sid"]}'):
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        resp.status = status
        resp.read.return_value = body
        return resp

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_success(self, urlopen):
        urlopen.return_value = self._mock_response()
        res = self.client.get("/dalton/controller_api/rule_keywords")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["available"])
        self.assertFalse(data["stale"])
        self.assertEqual(data["keywords"], ["sid"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_connection_refused(self, urlopen):
        urlopen.side_effect = ConnectionRefusedError()
        res = self.client.get("/dalton/controller_api/rule_keywords")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_timeout(self, urlopen):
        urlopen.side_effect = TimeoutError()
        res = self.client.get("/dalton/controller_api/rule_keywords")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_non_200(self, urlopen):
        urlopen.return_value = self._mock_response(status=500)
        res = self.client.get("/dalton/controller_api/rule_keywords")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_unparseable_body(self, urlopen):
        urlopen.return_value = self._mock_response(body=b"not json")
        res = self.client.get("/dalton/controller_api/rule_keywords")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_valid_json_non_object(self, urlopen):
        """json.loads succeeds on '["nope"]'; a naive .get() on that would raise."""
        urlopen.return_value = self._mock_response(body=b'["nope"]')
        res = self.client.get("/dalton/controller_api/rule_keywords")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    def test_unconfigured_url(self):
        self.dalton_module.KEYWORDS_URL = ""
        try:
            res = self.client.get("/dalton/controller_api/rule_keywords")
            self.assertEqual(res.status_code, 200)
            self.assertFalse(json.loads(res.data)["available"])
        finally:
            self.dalton_module.KEYWORDS_URL = "http://dalton_linter:8081/keywords"

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_outage_degrades_to_stale_not_absent(self, urlopen):
        """A linter outage after a prior success should serve the cached
        response marked stale, not report unavailable."""
        urlopen.return_value = self._mock_response()
        res = self.client.get("/dalton/controller_api/rule_keywords")
        self.assertTrue(json.loads(res.data)["available"])

        self._expire_cache()
        urlopen.side_effect = ConnectionRefusedError()
        res = self.client.get("/dalton/controller_api/rule_keywords")
        data = json.loads(res.data)
        self.assertTrue(data["available"])
        self.assertTrue(data["stale"])
        self.assertEqual(data["keywords"], ["sid"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_fresh_cache_does_not_hit_linter(self, urlopen):
        """Within the TTL the cached payload is served without a round trip,
        and it is reported as fresh, not stale."""
        urlopen.return_value = self._mock_response()
        self.client.get("/dalton/controller_api/rule_keywords")
        self.assertEqual(urlopen.call_count, 1)

        urlopen.side_effect = AssertionError("linter must not be contacted")
        res = self.client.get("/dalton/controller_api/rule_keywords")
        data = json.loads(res.data)
        self.assertEqual(urlopen.call_count, 1)
        self.assertTrue(data["available"])
        self.assertFalse(data["stale"])
        self.assertEqual(data["keywords"], ["sid"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_cached_payload_not_polluted_by_response_flags(self, urlopen):
        """The available/stale flags are added to the response, not to the
        stored payload, so a later stale serve cannot inherit stale=False."""
        urlopen.return_value = self._mock_response()
        self.client.get("/dalton/controller_api/rule_keywords")
        self.assertNotIn("stale", self.dalton_module._keywords_cache)
        self.assertNotIn("available", self.dalton_module._keywords_cache)


@pytest.mark.usefixtures("client")
class TestCheckRulesProxy(unittest.TestCase):
    """Test the /dalton/controller_api/check_rules fail-open proxy to the
    linter's /check endpoint."""

    def _mock_response(self, status=200, body=b'{"diagnostics": []}'):
        resp = mock.MagicMock()
        resp.__enter__.return_value = resp
        resp.status = status
        resp.read.return_value = body
        return resp

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_success(self, urlopen):
        urlopen.return_value = self._mock_response()
        res = self.client.post(
            "/dalton/controller_api/check_rules",
            data=json.dumps({"rules": "alert tcp any any -> any any (sid:1;)"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data["available"])
        self.assertEqual(data["diagnostics"], [])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_connection_refused(self, urlopen):
        urlopen.side_effect = ConnectionRefusedError()
        res = self.client.post(
            "/dalton/controller_api/check_rules",
            data=json.dumps({"rules": "alert"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_timeout(self, urlopen):
        urlopen.side_effect = TimeoutError()
        res = self.client.post(
            "/dalton/controller_api/check_rules",
            data=json.dumps({"rules": "alert"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_non_200(self, urlopen):
        urlopen.return_value = self._mock_response(status=500)
        res = self.client.post(
            "/dalton/controller_api/check_rules",
            data=json.dumps({"rules": "alert"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_unparseable_body(self, urlopen):
        urlopen.return_value = self._mock_response(body=b"not json")
        res = self.client.post(
            "/dalton/controller_api/check_rules",
            data=json.dumps({"rules": "alert"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    @mock.patch("app.dalton.urllib.request.urlopen")
    def test_valid_json_non_object(self, urlopen):
        urlopen.return_value = self._mock_response(body=b'["nope"]')
        res = self.client.post(
            "/dalton/controller_api/check_rules",
            data=json.dumps({"rules": "alert"}),
            content_type="application/json",
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(json.loads(res.data)["available"])

    def test_unconfigured_url(self):
        import app.dalton as dalton_module

        dalton_module.RULE_CHECK_URL = ""
        try:
            res = self.client.post(
                "/dalton/controller_api/check_rules",
                data=json.dumps({"rules": "alert"}),
                content_type="application/json",
            )
            self.assertEqual(res.status_code, 200)
            self.assertFalse(json.loads(res.data)["available"])
        finally:
            dalton_module.RULE_CHECK_URL = "http://dalton_linter:8081/check"

    def test_no_body_does_not_raise(self):
        """POSTing with no/invalid JSON body must not 500 - it should be
        treated the same as an empty ruleset."""
        res = self.client.post("/dalton/controller_api/check_rules")
        self.assertEqual(res.status_code, 200)
