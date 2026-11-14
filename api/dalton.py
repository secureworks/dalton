"""Dalton API client."""

from __future__ import annotations

import html
import re
import time

import requests
import urllib3.exceptions
from urllib3.exceptions import ConnectTimeoutError, ProxyError

RETRIES = 3
SLEEP_TIME = 60
# wait before retrying a connection failure: long enough for a restart, short
# enough that a wrong port fails quickly
CONNECT_SLEEP_TIME = 10
TIMEOUT = 60
# Dalton processes the pcap before it answers a job submission; this only
# stops the client waiting forever
SUBMIT_TIMEOUT = 3600
# longest wait a server's Retry-After can ask for
MAX_RETRY_AFTER = 300

# GETs are retried on any of these. A job submission (POST) is retried only on
# a 429, which means the request wasn't processed, so a retry can't create a
# second job (a proxy's 503 can come after Dalton queued it).
RETRY_CODES_GET = (429, 500, 502, 503, 504)
RETRY_CODES_POST = (429,)

# what a teapot job submission returns: a job ID, or several, comma-separated,
# when the pcap was split
TEAPOT_JIDS_RE = re.compile(r"^teapot_[0-9a-f]{16}(,teapot_[0-9a-f]{16})*$")


class DaltonAPIError(Exception):
    """Dalton rejected a request without an HTTP error status."""


class DaltonAPI:
    def __init__(
        self, api_link, timeout=TIMEOUT, submit_timeout=SUBMIT_TIMEOUT, headers=None
    ):
        """
        Args:
            api_link (str): Dalton base URL. Ex. http://localhost
            timeout (float): seconds to wait for a connection, and for a reply to a GET.
                A (connect, read) tuple sets the two separately.
            submit_timeout (float): seconds to wait for the reply to a job submission.
                Dalton processes the pcap before it replies, so the default is an hour;
                None waits forever. A submission that times out may still have been queued.
            headers (dict): extra headers sent with every request, e.g. an API key
        """
        self.api_link = api_link
        self.timeout = timeout
        self.submit_timeout = submit_timeout
        self.headers = headers

    def _request(
        self, method: str, endpoint: str, retry_codes, timeout, **kwargs
    ) -> requests.Response:
        """Make a request, trying up to RETRIES times.

        A retryable status waits for the server's Retry-After, if it gives one in
        seconds (up to MAX_RETRY_AFTER), or SLEEP_TIME. Connection failures are
        retried after CONNECT_SLEEP_TIME: for a GET any failure, for a POST only
        one that happened before the request was sent. A host name that doesn't
        resolve isn't retried. Each attempt uses a new connection, so a POST never
        goes out on a kept-alive connection the server is closing.
        """
        attempts = max(1, RETRIES)
        for attempt in range(1, attempts + 1):
            last = attempt == attempts
            try:
                response = requests.request(
                    method,
                    url=f"{self.api_link}/{endpoint}",
                    headers=self.headers,
                    timeout=timeout,
                    **kwargs,
                )
            except requests.exceptions.SSLError:
                raise
            except (
                requests.ConnectionError,
                requests.Timeout,
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ContentDecodingError,
            ) as exc:
                if (
                    last
                    or _name_not_resolved(exc)
                    or not (method == "GET" or _never_sent(exc))
                ):
                    raise
                time.sleep(CONNECT_SLEEP_TIME)
                continue
            if response.status_code in retry_codes and not last:
                time.sleep(_retry_after(response))
                continue
            response.raise_for_status()
            return response

    def _dalton_get(self, endpoint: str) -> requests.Response:
        return self._request("GET", endpoint, RETRY_CODES_GET, self.timeout)

    def _dalton_post(self, endpoint: str, data: dict, files) -> requests.Response:
        # read the files once, from where the caller left them, so that every
        # attempt sends the same bytes (requests reads them into memory anyway)
        pairs = files.items() if hasattr(files, "items") else (files or [])
        files = [(name, _read_file(name, value)) for name, value in pairs]
        connect = self.timeout[0] if isinstance(self.timeout, tuple) else self.timeout
        return self._request(
            "POST",
            endpoint,
            RETRY_CODES_POST,
            (connect, self.submit_timeout),
            data=data,
            files=files,
        )

    def submit_job(
        self,
        sensor_tech: str,
        prod_ruleset: str,
        configuration: str,
        custom_rules: str,
        files: dict | list,
    ) -> str:
        """Submits a job for a specific sensor tech, ruleset, configuration and pcap.

        Args:
            sensor_tech (str): sensor tech and version. Ex. suricata/6.0.10
            prod_ruleset (str): path to prod ruleset. Ex. /opt/dalton/rulesets/suricata/ET-20230301-all-suricata.rules
            configuration (str): sensor configuration. Can be read from a yaml file. See "examples/job_submission.py"
            custom_rules (str): rules to be tested. Can be read from a rules file. See "examples/job_submission.py"
            files (dict | list): the pcap files, as a dict or a list of (name, value) pairs.
                Ex. {"coverage-pcap0": ("test_job.pcap", pcap)}. An open file is read from its current
                position, as requests would; pass bytes to submit the same pcap more than once.

        Returns:
            str: the job ID, or a comma-separated list of job IDs if Dalton split the pcap.
            Ex. 'teapot_0123456789abcdef'

        Raises:
            DaltonAPIError: Dalton returned an error page instead of a job ID.
        """
        data = {
            "sensor_tech": sensor_tech,
            "optionProdRuleset": "prod",
            "prod_ruleset": prod_ruleset,
            "custom_engineconf": configuration,
            "custom_ruleset": custom_rules,
            "teapotJob": 1,
        }
        if custom_rules:
            # Dalton ignores custom_ruleset unless this is set
            data["optionCustomRuleset"] = "custom"
        response = self._dalton_post("dalton/coverage/summary", data=data, files=files)
        # a teapot job's response is its job ID; anything else is Dalton's error page
        jids = response.text.strip()
        if not TEAPOT_JIDS_RE.match(jids):
            raise DaltonAPIError(
                f"Dalton did not accept the job: {_error_text(jids)[:500]}"
            )
        return jids

    def get_sensor_tech(self, sensor: str) -> list:
        """Get sensor type and version.

        Args:
            sensor (str): Type of sensor. Can be: suricata, zeek, snort.

        Returns:
            list: List of techs. Ex. ['suricata/6.0.10', 'suricata/5.0.7']
        """
        response = self._dalton_get(
            f"dalton/controller_api/get-current-sensors/{sensor}"
        )
        return response.json()["sensor_tech"]

    def get_prod_rulesets(self, sensor: str) -> list:
        """Get prod ruleset path for Dalton agent.

        Args:
            sensor (str): Type of sensor. Can be: suricata, zeek, snort.

        Returns:
            list: Ruleset paths. Ex. ['/opt/dalton/rulesets/suricata/ET-20230301-all-suricata.rules']
        """
        response = self._dalton_get(f"dalton/controller_api/get-prod-rulesets/{sensor}")
        return response.json()["prod-rulesets"]

    def get_max_pcaps(self) -> int:
        """Get max number of pcaps that can be submitted with one job.

        Returns:
            int: Maximum number of pcaps.
        """
        response = self._dalton_get("dalton/controller_api/get-max-pcap-files")
        return response.json()

    def get_current_sensors(self) -> dict:
        """Get all sensors that are running on Dalton agent.

        Returns:
            dict: Sensor technologies including versions. Ex.
            {'eda70976dc9e0e1c0fc1a8c5696c2e6c': {'uid': '3088f3e0759f',
            'ip': '172.19.0.7',
            'time': 'Mar 01 17:53:26 (0 minutes ago)',
            'tech': 'snort/2.9.15.1',
            'agent_version': '3.1.1'},
            'd0d5709c1d27c85e1eef1462bb13e665': {'uid': '837dd3bacbae',
            'ip': '172.19.0.7',
            'time': 'Mar 01 17:53:27 (0 minutes ago)',
            'tech': 'suricata/6.0.10',
            'agent_version': '3.1.1'},
            '1cbbf6f4021f2a3f3276feb657c732d0': {'uid': 'e41fca927924',
            'ip': '172.19.0.7',
            'time': 'Mar 01 17:53:26 (0 minutes ago)',
            'tech': 'snort/2.9.18.1',
            'agent_version': '3.1.1'},
            '27840880aee4668c6677c57f91eea364': {'uid': '0410c78e9a10',
            'ip': '172.19.0.7',
            'time': 'Mar 01 17:53:27 (0 minutes ago)',
            'tech': 'zeek/4.0.2',
            'agent_version': '3.1.1'},
            '27fbaece89d6e67e69d00e1dd0af67bb': {'uid': '5f4ee1cbac85',
            'ip': '172.19.0.7',
            'time': 'Mar 01 17:53:27 (0 minutes ago)',
            'tech': 'suricata/5.0.7',
            'agent_version': '3.1.1'}}
        """
        response = self._dalton_get(
            "dalton/controller_api/get-current-sensors-json-full"
        )
        return response.json()


def _error_text(page: str) -> str:
    """The message on Dalton's error page, or the page's text if it isn't one."""
    match = re.search(r'(?is)<div class="span9">(.*?)</div>', page)
    text = match.group(1) if match else page
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return " ".join(html.unescape(text).split())


def _read_file(name, value):
    """A requests files value with any open file replaced by its contents."""
    if isinstance(value, (tuple, list)):
        if len(value) > 1 and hasattr(value[1], "read"):
            return (value[0], value[1].read(), *value[2:])
        return value
    if hasattr(value, "read"):
        # requests names the upload after the file; keep that name
        return (requests.utils.guess_filename(value) or name, value.read())
    return value


def _reason(exc: Exception):
    """The urllib3 error behind a requests connection error, if there is one."""
    reason = getattr(exc.args[0], "reason", None) if exc.args else None
    # a ProxyError can wrap a failure from before or after the request went out
    if isinstance(reason, ProxyError):
        reason = getattr(reason, "original_error", None)
    return reason


def _never_sent(exc: Exception) -> bool:
    """Whether a request failed while connecting, before the server (or proxy) saw it."""
    return isinstance(_reason(exc), ConnectTimeoutError)


def _name_not_resolved(exc: Exception) -> bool:
    """Whether the host name didn't resolve (urllib3 2 only), which a retry won't fix."""
    error = getattr(urllib3.exceptions, "NameResolutionError", None)
    return error is not None and isinstance(_reason(exc), error)


def _retry_after(response: requests.Response) -> float:
    """Seconds to wait before retrying: the server's Retry-After, or SLEEP_TIME."""
    value = response.headers.get("Retry-After", "").strip()
    if value.isascii() and value.isdigit():
        return min(int(value), MAX_RETRY_AFTER)
    return SLEEP_TIME
