"""B23: AWS SNS adapter with SigV4, checked against AWS's published examples."""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
import pytest

from kubeness.notification import NotificationPayload
from kubeness.notifier import NotifierConfig, ProviderError, SnsProvider, signing_key, sigv4_headers

from kpi_report import kpi
from test_notifier import payload

SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"  # AWS documentation example key


def test_signing_key_matches_the_aws_example():
    key = signing_key(SECRET, "20120215", "us-east-1", "iam")
    assert key.hex() == "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"


def test_signature_matches_the_aws_listusers_example():
    headers = sigv4_headers(
        "GET", "https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08", b"",
        {"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
        "AKIDEXAMPLE", SECRET, "us-east-1", "iam", datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc))
    assert headers["Authorization"].endswith(
        "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7")
    assert "Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request" in headers["Authorization"]


def test_p01_publish_request():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, text="<PublishResponse/>")

    arn = "arn:aws:sns:eu-north-1:123456789012:kubeness"
    sns = SnsProvider(arn, "AKIDEXAMPLE", SECRET, timeout=5, transport=httpx.MockTransport(handler),
                      clock=lambda: datetime(2026, 11, 16, 12, 0, tzinfo=timezone.utc))
    p = NotificationPayload.model_validate(payload())
    sns.send(p)
    (req,) = seen
    assert str(req.url) == "https://sns.eu-north-1.amazonaws.com/"
    form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()}
    assert form["Action"] == "Publish" and form["TopicArn"] == arn and form["Message"] == p.text
    assert form["Subject"].startswith("[WARNING]") and len(form["Subject"]) <= 100
    auth = req.headers["Authorization"]
    ok = (auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261116/eu-north-1/sns/aws4_request")
          and "SignedHeaders=content-type;host;x-amz-date" in auth)
    kpi("P01", "SigV4 Publish request with the right scope and TopicArn", int(ok), "bool", eq=1)


def test_sns_errors_are_provider_errors():
    t = httpx.MockTransport(lambda r: httpx.Response(403, text="<Error><Code>AuthorizationError</Code></Error>"))
    sns = SnsProvider("arn:aws:sns:eu-north-1:1:t", "AKID", "s", timeout=5, transport=t)
    with pytest.raises(ProviderError, match="403"):
        sns.send(NotificationPayload.model_validate(payload()))


def test_sns_config_from_destination_files(tmp_path):
    d = tmp_path / "dest"
    d.mkdir()
    (d / "url").write_text("arn:aws:sns:eu-north-1:123456789012:kubeness\n")
    (d / "accessKeyId").write_text("AKID\n")
    (d / "secretAccessKey").write_text("s3cr3t\n")
    provider, _ = NotifierConfig.model_validate({"provider": "sns", "destinationDir": str(d)}).build()
    assert isinstance(provider, SnsProvider) and provider.region == "eu-north-1"
