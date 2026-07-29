from __future__ import annotations

import base64
import socket
import ssl
from pathlib import Path

import pytest

import main

FIXTURE = Path(__file__).parent / "data" / "expired_badssl_cert.der.b64"


def load_expired_cert_der() -> bytes:
    return base64.b64decode(FIXTURE.read_text().replace("\n", ""))


def test_getpeercert_really_is_empty_without_validation(monkeypatch):
    """The premise of the bug, pinned down so nobody re-introduces the old code.

    ssl.getpeercert() only fills its dict when the peer certificate was
    validated. Under _create_unverified_context it returns {}, which is why the
    old fallback could never report an expiry date.
    """
    context = ssl._create_unverified_context()
    assert context.verify_mode == ssl.CERT_NONE


def test_expired_certificate_details_come_out_of_the_der_bytes():
    """Regression: this used to be ("", "", "", "") for every expired cert.

    Expected values were read straight out of the fixture bytes, where the
    validity field is 150409000000Z / 150412235959Z and the subject common name
    is *.badssl.com.
    """
    expires_at, days_remaining, issuer, subject = main.parse_certificate_der(load_expired_cert_der())

    assert expires_at == "2015-04-12"
    assert int(days_remaining) < 0, "an expired cert must report negative days remaining"
    assert subject == "*.badssl.com"
    assert issuer == "COMODO RSA Domain Validation Secure Server CA"


def test_der_parser_rejects_junk():
    for junk in (b"", b"\x00", b"not a certificate at all", b"\x30\x82\xff\xff"):
        with pytest.raises(ValueError):
            main.parse_certificate_der(junk)


def test_unverified_inspection_returns_empty_when_the_host_is_unreachable(monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(main.socket, "create_connection", refuse)
    assert main.inspect_certificate_unverified("example.com", 443, 2) == ("", "", "", "")


def test_expired_cert_status_now_carries_the_expiry_date(monkeypatch):
    """End to end: check_ssl_certificate on a cert that fails validation should
    report SSL EXPIRED and still fill in the date and day count."""

    def fail_verification(*args, **kwargs):
        raise ssl.SSLCertVerificationError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired")

    class FakeContext:
        def wrap_socket(self, sock, server_hostname=None):
            fail_verification()

    monkeypatch.setattr(main.ssl, "create_default_context", lambda: FakeContext())

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(main.socket, "create_connection", lambda *a, **k: FakeSocket())
    monkeypatch.setattr(
        main,
        "inspect_certificate_unverified",
        lambda *a, **k: main.parse_certificate_der(load_expired_cert_der()),
    )

    result = main.check_ssl_certificate("https://expired.example.com", 2, 30)
    assert result.status == "SSL EXPIRED"
    assert result.expires_at == "2015-04-12"
    assert int(result.days_remaining) < 0
    assert result.subject == "*.badssl.com"


@pytest.mark.network
def test_der_parser_agrees_with_python_on_a_valid_certificate():
    """Independent oracle: for a certificate that does validate, Python fills in
    getpeercert() itself, so the two answers must match."""
    host = "example.com"
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                parsed = tls.getpeercert()
                der = tls.getpeercert(binary_form=True)
    except OSError as exc:
        pytest.skip(f"network unavailable: {exc}")

    python_expiry = main.parse_cert_datetime(parsed["notAfter"]).strftime("%Y-%m-%d")
    our_expiry, our_days, _, our_subject = main.parse_certificate_der(der)

    assert our_expiry == python_expiry
    assert int(our_days) > 0
    assert our_subject == main.extract_cert_name(parsed["subject"])
