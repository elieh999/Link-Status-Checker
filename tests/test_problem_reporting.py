from __future__ import annotations

import socket
import ssl

import pytest

from src.link_status_checker.monitoring.problems import classify_ssl_problem


@pytest.mark.parametrize(
    ("message", "verify_code", "expected"),
    [
        ("certificate has expired", 10, "certificate_expired"),
        ("certificate is not yet valid", 9, "certificate_not_yet_valid"),
        ("hostname mismatch", 62, "certificate_hostname_mismatch"),
        ("self signed certificate", 18, "certificate_self_signed"),
        ("unable to get local issuer certificate", 20, "certificate_chain_untrusted"),
    ],
)
def test_certificate_errors_have_plain_language_categories(message, verify_code, expected):
    error = ssl.SSLCertVerificationError(message)
    error.verify_code = verify_code
    error.verify_message = message
    problem = classify_ssl_problem(error, "portal.example.com")
    assert problem.code == expected
    assert problem.title
    assert problem.explanation
    assert problem.recommended_action
    assert problem.technical_details
    assert "_ssl.c:" not in problem.explanation


def test_timeout_connection_refusal_and_dns_are_separate_problems():
    assert classify_ssl_problem(TimeoutError("timed out")).code == "connection_timeout"
    assert classify_ssl_problem(ConnectionRefusedError("refused")).code == "connection_refused"
    assert classify_ssl_problem(socket.gaierror("not known"), "missing.test").code == "dns_failure"


def test_unknown_ssl_error_keeps_technical_details():
    error = RuntimeError("vendor specific TLS failure")
    problem = classify_ssl_problem(error)
    assert problem.code == "ssl_unknown"
    assert problem.technical_details == str(error)
