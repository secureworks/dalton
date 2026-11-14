"""Tests for the Dalton API client in api/dalton.py."""

import io

import pytest
import requests

from api import dalton
from api.dalton import DaltonAPI, DaltonAPIError

JID = "teapot_0123456789abcdef"


def make_response(status=200, text=""):
    response = requests.Response()
    response.status_code = status
    response._content = text.encode()
    response.url = "http://dalton.test/"
    return response


class FakeRequests:
    """Stands in for requests.request: replays responses and records calls."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        files = kwargs.get("files") or {}
        sent = {name: value[1].read() for name, value in files.items()}
        self.calls.append({"method": method, "url": url, **kwargs, "sent": sent})
        return self.responses.pop(0)


@pytest.fixture
def fake(monkeypatch):
    def install(*responses):
        fake_requests = FakeRequests(*responses)
        monkeypatch.setattr(dalton.requests, "request", fake_requests)
        return fake_requests

    monkeypatch.setattr(dalton.time, "sleep", lambda seconds: None)
    return install


def submit(client, pcap=b"pcap bytes"):
    return client.submit_job(
        sensor_tech="suricata/8.0.6",
        prod_ruleset="/opt/dalton/rulesets/suricata/x.rules",
        configuration="%YAML 1.1\n",
        custom_rules='alert ip any any -> any any (msg:"x"; sid:1;)',
        files={"coverage-pcap0": ("test.pcap", io.BytesIO(pcap))},
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
    assert requests_.calls[0]["data"]["teapotJob"] == 1


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
