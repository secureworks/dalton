import os
import random
import shutil
import unittest
import uuid
from io import BytesIO
from unittest import mock
from urllib.parse import urlencode

import pytest

from app.flowsynth import (
    check_pcap_path,
    get_pcap_file_path,
    get_pcap_path,
    unicode_safe,
)

KNOWN_PCAP_ID = "98765"
KNOWN_PCAP_CONTENTS = b"hi there"


@pytest.mark.usefixtures("client")
class TestFlowsynth(unittest.TestCase):
    def setUp(self):
        self.pcap_base = "/tmp/pcaps"
        check_pcap_path(self.pcap_base)

    def tearDown(self):
        shutil.rmtree(self.pcap_base)

    def test_flowsynth_home(self):
        response = self.client.get("/flowsynth/")
        self.assertIn(b"Build Packet Capture", response.data)
        self.assertEqual(200, response.status_code)

    def test_flowsynth_about(self):
        response = self.client.get("/flowsynth/about")
        self.assertEqual(200, response.status_code)
        self.assertIn(b"About Flowsynth", response.data)

    def test_flowsynth_compile(self):
        response = self.client.get("/flowsynth/compile")
        self.assertEqual(200, response.status_code)
        self.assertIn(b"Compile", response.data)

    def test_get_pcap_file_path(self):
        basename = "snap"
        path = get_pcap_file_path(basename)

        expected = get_pcap_path() + "/" + basename + ".pcap"
        self.assertEqual(expected, path)

    @classmethod
    def read_pcap_file(cls, filename=None, random=False, pcap_id=KNOWN_PCAP_ID):
        """Read a PCAP file from test data."""
        filename = filename or f"pcap_{pcap_id}.pcap"
        path = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "files", filename
        )
        with open(path, "rb") as content_file:
            content = content_file.read()
            if random:
                content = content + str(uuid.uuid4()).encode()
            return BytesIO(content)

    def test_unicode_safe(self):
        testdata = "abcd1234"
        self.assertEqual(testdata, unicode_safe(testdata))
        testdata = "きたない\n"
        self.assertEqual("\n", unicode_safe(testdata))

    @mock.patch("app.flowsynth.get_pcap_file_path")
    def test_retrieve_pcap(self, mock_pcap_path):
        """Confirm '/flowsynth/pcap/get_pcap' endpoint is working."""
        # Copy the KNOWN_PCAP file into PCAP_PATH/<pcap_id>.pcap.
        pcap_id = random.randint(100000, 999999)
        path = get_pcap_file_path(pcap_id, path=self.pcap_base)
        mock_pcap_path.side_effect = [path]
        with open(path, "wb") as fd:
            pcap_data = self.read_pcap_file(None, random=True)
            fd.write(pcap_data.read())
        url = f"/flowsynth/pcap/get_pcap/{pcap_id}"
        response = self.client.get(url)
        self.assertEqual(200, response.status_code)
        self.assertEqual("application/vnd.tcpdump.pcap", response.content_type)
        self.assertEqual(
            f"attachment;filename={pcap_id}.pcap",
            response.headers["Content-Disposition"],
        )
        self.assertIn(KNOWN_PCAP_CONTENTS, response.data)

    def test_generate(self):
        """Ensure we can call the /generate endpoint."""
        # NOTE these are L's and not ones
        input_data_string = "data would go here"
        expected_output = r"data\x20would\x20go\x20here"
        post_args = {
            "l3_src_ip": "$HOME_NET",
            "l3_dst_ip": "$HOME_NET",
            "l3_protocol": "TCP",
            "l3_flow_established": "yes",
            "l4_src_port": "any",
            "l4_dst_port": "any",
            "payload_format": "http",  # 'http', 'raw' or 'cert'
            "payload_http_request_contentlength": "on",
            "request_header": "",
            "request_body": input_data_string,
            "generate_method": "build",
        }
        url = "/flowsynth/generate"
        response = self.client.post(
            url,
            data=urlencode(post_args),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(200, response.status_code)
        self.assertIn("flow default tcp 192", response.data.decode())
        self.assertIn(expected_output, response.data.decode())

    @mock.patch("app.flowsynth.check_pcap_path")
    @mock.patch("app.flowsynth.get_pcap_file_path")
    def test_pcap_compile_fs(self, mock_pcap_path, mock_check_pcap_path):
        """Ensure we can call the pcap/compile_fs endpoint."""
        post_args = {
            "code": "flow default tcp 192.168.51.44:45348 > 172.16.146.20:45694 (tcp.initialize;);"
            'default > (content:""; content:"\x0d\x0aContent-Length: 12"; content:"\x0d\x0a\x0d\x0a";'
            'content:"blah-blah"; );',
        }
        path = get_pcap_file_path(KNOWN_PCAP_ID, path=self.pcap_base)
        mock_pcap_path.side_effect = [path]
        response = self.client.post(
            "/flowsynth/pcap/compile_fs",
            data=urlencode(post_args),
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(200, response.status_code, "Flowsynth command worked")
        self.assertIn(b"Success", response.data)
        self.assertIn(b"Click Here to Download PCAP", response.data)
