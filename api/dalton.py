"""Dalton API client."""

import re
import time

import requests
from requests.exceptions import HTTPError

RETRIES = 3
SLEEP_TIME = 60
TIMEOUT = 60

# GETs are retried on any of these. A job submission (POST) is retried only on
# the codes that mean the request wasn't processed, so a retry can't create a
# second job.
RETRY_CODES_GET = (429, 500, 502, 503, 504)
RETRY_CODES_POST = (429, 503)

# what a teapot job submission returns: a job ID, or several, comma-separated,
# when the pcap was split
TEAPOT_JIDS_RE = re.compile(r"^teapot_[0-9a-f]{16}(,teapot_[0-9a-f]{16})*$")


class DaltonAPIError(Exception):
    """Dalton rejected a request without an HTTP error status."""


class DaltonAPI:
    def __init__(self, api_link, timeout=TIMEOUT):
        self.api_link = api_link
        self.timeout = timeout

    def _request(
        self, method: str, endpoint: str, retry_codes, **kwargs
    ) -> requests.Response:
        """Make a request, retrying after SLEEP_TIME seconds on a retryable status."""
        for attempt in range(1, RETRIES + 1):
            # a retried upload has to send its files from the start again
            for value in (kwargs.get("files") or {}).values():
                fileobj = value[1] if isinstance(value, tuple) else value
                if hasattr(fileobj, "seek"):
                    fileobj.seek(0)
            response = requests.request(
                method,
                url=f"{self.api_link}/{endpoint}",
                timeout=self.timeout,
                **kwargs,
            )
            try:
                response.raise_for_status()
            except HTTPError:
                if response.status_code in retry_codes and attempt < RETRIES:
                    time.sleep(SLEEP_TIME)
                    continue
                raise
            return response

    def _dalton_get(self, endpoint: str) -> requests.Response:
        return self._request("GET", endpoint, RETRY_CODES_GET)

    def _dalton_post(self, endpoint: str, data: dict, files: dict) -> requests.Response:
        return self._request("POST", endpoint, RETRY_CODES_POST, data=data, files=files)

    def submit_job(
        self,
        sensor_tech: str,
        prod_ruleset: str,
        configuration: str,
        custom_rules: str,
        files: dict,
    ) -> str:
        """Submits a job for a specific sensor tech, ruleset, configuration and pcap.

        Args:
            sensor_tech (str): sensor tech and version. Ex. suricata/6.0.10
            prod_ruleset (str): path to prod ruleset. Ex. /opt/dalton/rulesets/suricata/ET-20230301-all-suricata.rules
            configuration (str): sensor configuration. Can be read from a yaml file. See "examples/job_submission.py"
            custom_rules (str): rules to be tested. Can be read from a rules file. See "examples/job_submission.py"
            files (dict): dictionary that includes tuple with pcap file. Ex. {"coverage-pcap0": ("test_job.pcap", pcap)}

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
        response = self._dalton_post("dalton/coverage/summary", data=data, files=files)
        # a teapot job's response is its job ID; anything else is Dalton's error page
        jids = response.text.strip()
        if not TEAPOT_JIDS_RE.match(jids):
            raise DaltonAPIError(
                f"Dalton did not accept the job: {_page_text(jids)[:500]}"
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


def _page_text(html: str) -> str:
    """The visible text of an HTML page, whitespace collapsed."""
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", html)
    text = re.sub(r"<[^>]+>", " ", text)
    return " ".join(text.split())
