"""Tests for the Dalton API client in api/dalton.py."""

import io
import socket
import threading

import pytest
import requests
from urllib3.exceptions import MaxRetryError, NewConnectionError, ProtocolError

from api import dalton
from api.dalton import DaltonAPI, DaltonAPIError

JID = "teapot_0123456789abcdef"


def make_response(status=200, text="", headers=None):
    response = requests.Response()
    response.status_code = status
    response.headers.update(headers or {})
    response._content = text.encode()
    response.url = "http://dalton.test/"
    return response


# a refused connection, which never reached the server
REFUSED = requests.ConnectionError(
    MaxRetryError(None, "/", NewConnectionError(None, "Connection refused"))
)
# a connection dropped after the request was sent
DROPPED = requests.ConnectionError(
    ProtocolError("Connection aborted.", ConnectionResetError())
)


class FakeRequests:
    """Stands in for Session.request: replays responses (or raises) and records calls."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        files = kwargs.get("files") or {}
        pairs = files.items() if hasattr(files, "items") else files
        sent = {name: value[1].read() for name, value in pairs}
        self.calls.append({"method": method, "url": url, **kwargs, "sent": sent})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.fixture
def sleeps(monkeypatch):
    slept = []
    monkeypatch.setattr(dalton.time, "sleep", slept.append)
    return slept


@pytest.fixture
def fake(monkeypatch, sleeps):
    def install(*responses):
        fake_requests = FakeRequests(*responses)
        monkeypatch.setattr(requests.Session, "request", fake_requests)
        return fake_requests

    return install


def submit(client, pcap=b"pcap bytes", files=None):
    return client.submit_job(
        sensor_tech="suricata/8.0.6",
        prod_ruleset="/opt/dalton/rulesets/suricata/x.rules",
        configuration="%YAML 1.1\n",
        custom_rules='alert ip any any -> any any (msg:"x"; sid:1;)',
        files=files or {"coverage-pcap0": ("test.pcap", io.BytesIO(pcap))},
    )


def test_get_is_made_once(fake):
    requests_ = fake(make_response(text='{"sensor_tech": ["suricata/8.0.6"]}'))
    assert DaltonAPI("http://dalton.test").get_sensor_tech("suricata") == [
        "suricata/8.0.6"
    ]
    assert len(requests_.calls) == 1
    call = requests_.calls[0]
    assert (call["method"], call["url"]) == (
        "GET",
        "http://dalton.test/dalton/controller_api/get-current-sensors/suricata",
    )
    assert call["timeout"] == dalton.TIMEOUT


def test_submit_returns_job_id_and_posts_once(fake):
    requests_ = fake(make_response(text=JID))
    assert submit(DaltonAPI("http://dalton.test")) == JID
    assert len(requests_.calls) == 1
    data = requests_.calls[0]["data"]
    assert data["teapotJob"] == 1
    assert data["optionCustomRuleset"] == "custom"
    assert data["custom_ruleset"].startswith("alert ")
    # Dalton processes the pcap before replying: no read timeout by default
    assert requests_.calls[0]["timeout"] == (dalton.TIMEOUT, None)


def test_submit_timeout_is_configurable(fake):
    requests_ = fake(make_response(text=JID))
    submit(DaltonAPI("http://dalton.test", timeout=5, submit_timeout=600))
    assert requests_.calls[0]["timeout"] == (5, 600)


def test_submit_split_pcap_job_ids(fake):
    jids = f"{JID},teapot_fedcba9876543210"
    fake(make_response(text=jids))
    assert submit(DaltonAPI("http://dalton.test")) == jids


def test_submit_error_page(fake):
    page = "<html><head><style>p {}</style></head><body><p>Error: no sensor</p></body></html>"
    fake(make_response(text=page))
    with pytest.raises(DaltonAPIError, match="Error: no sensor"):
        submit(DaltonAPI("http://dalton.test"))


def test_get_retries_then_succeeds(fake):
    requests_ = fake(make_response(500), make_response(503), make_response(text="5"))
    assert DaltonAPI("http://dalton.test").get_max_pcaps() == 5
    assert len(requests_.calls) == 3


def test_get_gives_up_after_retries(fake):
    requests_ = fake(*[make_response(502) for _ in range(dalton.RETRIES)])
    with pytest.raises(requests.HTTPError):
        DaltonAPI("http://dalton.test").get_max_pcaps()
    assert len(requests_.calls) == dalton.RETRIES


def test_not_found_is_not_retried(fake):
    requests_ = fake(make_response(404))
    with pytest.raises(requests.HTTPError):
        DaltonAPI("http://dalton.test").get_max_pcaps()
    assert len(requests_.calls) == 1


def test_submit_retry_resends_the_whole_pcap(fake):
    requests_ = fake(make_response(503), make_response(text=JID))
    assert submit(DaltonAPI("http://dalton.test"), pcap=b"0123456789") == JID
    assert [call["sent"]["coverage-pcap0"] for call in requests_.calls] == [
        b"0123456789"
    ] * 2


def test_submit_not_retried_when_it_may_have_run(fake):
    # a 500 may come after the job was queued; retrying could submit it twice
    requests_ = fake(make_response(500))
    with pytest.raises(requests.HTTPError):
        submit(DaltonAPI("http://dalton.test"))
    assert len(requests_.calls) == 1


def test_submit_files_as_a_list(fake):
    pcap = io.BytesIO(b"0123456789")
    requests_ = fake(make_response(503), make_response(text=JID))
    files = [("coverage-pcap0", ("test.pcap", pcap))]
    assert submit(DaltonAPI("http://dalton.test"), files=files) == JID
    assert [call["sent"]["coverage-pcap0"] for call in requests_.calls] == [
        b"0123456789"
    ] * 2


def test_get_retries_connection_errors(fake):
    requests_ = fake(DROPPED, requests.ReadTimeout(), make_response(text="5"))
    assert DaltonAPI("http://dalton.test").get_max_pcaps() == 5
    assert len(requests_.calls) == 3


def test_submit_retried_when_connection_refused(fake):
    requests_ = fake(REFUSED, make_response(text=JID))
    assert submit(DaltonAPI("http://dalton.test")) == JID
    assert len(requests_.calls) == 2


def test_submit_not_retried_when_connection_dropped(fake):
    # the request was sent, so the job may have been queued
    requests_ = fake(DROPPED)
    with pytest.raises(requests.ConnectionError):
        submit(DaltonAPI("http://dalton.test"))
    assert len(requests_.calls) == 1


def test_tls_errors_are_not_retried(fake):
    requests_ = fake(requests.exceptions.SSLError("certificate verify failed"))
    with pytest.raises(requests.exceptions.SSLError):
        DaltonAPI("https://dalton.test").get_max_pcaps()
    assert len(requests_.calls) == 1


def test_retry_after_is_honoured(fake, sleeps):
    fake(
        make_response(429, headers={"Retry-After": "7"}),
        make_response(503, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}),
        make_response(text="5"),
    )
    assert DaltonAPI("http://dalton.test").get_max_pcaps() == 5
    assert sleeps == [7, dalton.SLEEP_TIME]


def test_never_sent_with_real_connections():
    # a port nothing listens on refuses the connection
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
    with pytest.raises(requests.ConnectionError) as refused:
        requests.post(f"http://127.0.0.1:{closed_port}/", data={"a": 1}, timeout=5)
    assert dalton._never_sent(refused.value)

    # a server that reads the request and hangs up without replying
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()

    def hang_up():
        conn, _ = server.accept()
        conn.recv(65536)
        conn.close()

    thread = threading.Thread(target=hang_up, daemon=True)
    thread.start()
    port = server.getsockname()[1]
    with pytest.raises(requests.ConnectionError) as dropped:
        requests.post(f"http://127.0.0.1:{port}/", data={"a": 1}, timeout=5)
    thread.join()
    server.close()
    assert not dalton._never_sent(dropped.value)


def test_submit_without_custom_rules(fake):
    requests_ = fake(make_response(text=JID))
    DaltonAPI("http://dalton.test").submit_job(
        sensor_tech="suricata/8.0.6",
        prod_ruleset="/opt/dalton/rulesets/suricata/x.rules",
        configuration="%YAML 1.1\n",
        custom_rules="",
        files={"coverage-pcap0": ("test.pcap", io.BytesIO(b"x"))},
    )
    assert "optionCustomRuleset" not in requests_.calls[0]["data"]
