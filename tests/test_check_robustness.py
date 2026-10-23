from __future__ import annotations

import socket

import pytest

import main

TOO_LONG_LABEL = "https://" + "a" * 100 + ".com"


def test_dns_lookup_reports_failure_instead_of_raising():
    """Regression: a DNS label over 63 chars makes getaddrinfo raise
    UnicodeError, which is not an OSError, so it escaped lookup_domain_ips."""
    result = main.lookup_domain_ips(TOO_LONG_LABEL)
    assert result.status == "FAILED"
    assert result.error
    assert result.primary_ip == ""


def test_dns_lookup_survives_any_resolver_error(monkeypatch):
    """Whatever the resolver throws, the caller gets a FAILED result."""
    for error in (socket.gaierror("boom"), OSError("boom"), UnicodeError("boom"), ValueError("boom")):

        def explode(*args, _error=error, **kwargs):
            raise _error

        monkeypatch.setattr(main.socket, "getaddrinfo", explode)
        result = main.lookup_domain_ips("https://example.com")
        assert result.status == "FAILED", f"{type(error).__name__} was not handled"


def test_ssl_check_survives_an_unparseable_expiry_date(monkeypatch):
    """parse_cert_datetime raises ValueError on an unexpected notAfter format,
    and ValueError was not caught, so the whole check died."""

    class FakeTls:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def getpeercert(self, binary_form=False):
            if binary_form:
                return b""
            return {"notAfter": "not-a-real-date", "subject": (), "issuer": ()}

    class FakeContext:
        def wrap_socket(self, sock, server_hostname=None):
            return FakeTls()

    monkeypatch.setattr(main.ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(main.socket, "create_connection", lambda *a, **k: FakeTls())

    result = main.check_ssl_certificate("https://example.com", 2, 30)
    assert result.status == "SSL ERROR"
    assert result.message


def test_check_target_returns_a_result_for_a_hopeless_url():
    """The end to end check must not raise, whatever the URL looks like."""
    target = main.LinkTarget("bad", TOO_LONG_LABEL, TOO_LONG_LABEL)
    result = main.check_target(target, 2, 30)
    assert result.availability_status == "INACTIVE"
    assert result.dns_status == "FAILED"


def test_dns_failure_has_a_clear_problem_and_keeps_technical_details(monkeypatch):
    target = main.LinkTarget("missing", "missing.test", "https://missing.test/")
    monkeypatch.setattr(
        main,
        "lookup_domain_ips",
        lambda _url: main.DnsLookupResult("missing.test", "", [], "FAILED", "Name or service not known"),
    )
    monkeypatch.setattr(
        main,
        "check_ssl_certificate",
        lambda *_args: main.SslCheckResult("SSL NOT CHECKED", "", "", "", "", ""),
    )
    monkeypatch.setattr(
        main,
        "check_https_availability",
        lambda *_args: ("INACTIVE", "HTTPS FAILED", "30", "-", "Name or service not known"),
    )
    result = main.check_target(target, 2, 30)
    assert result.problem_code == "dns_failure"
    assert result.problem_title == "Domain name could not be resolved"
    assert result.problem_explanation == "The computer could not find an IP address for missing.test."
    assert result.technical_details == "Name or service not known"


def test_http_failure_says_which_response_was_unexpected(monkeypatch):
    target = main.LinkTarget("api", "api.test", "https://api.test/")
    monkeypatch.setattr(
        main,
        "lookup_domain_ips",
        lambda _url: main.DnsLookupResult("api.test", "203.0.113.2", ["203.0.113.2"], "RESOLVED", ""),
    )
    monkeypatch.setattr(
        main,
        "check_ssl_certificate",
        lambda *_args: main.SslCheckResult("SSL VALID", "2027-01-01", "180", "Test CA", "api.test", "Valid"),
    )
    monkeypatch.setattr(
        main,
        "check_https_availability",
        lambda *_args: ("ACTIVE", "HTTPS OK", "40", "500", "Website responded over HTTPS."),
    )
    result = main.check_target(target, 2, 30)
    assert result.health_status == "DEGRADED"
    assert result.problem_code == "http_error"
    assert "HTTP 500" in result.problem_title
    assert "200 through 399" in result.problem_explanation


def test_worker_emits_a_result_even_when_the_check_explodes(qtbot, monkeypatch):
    """Regression: LinkCheckWorker.run had no guard, so any unexpected
    exception killed the runnable without emitting. MainWindow counts those
    emissions down, so one dead worker left "Check All Now" disabled forever."""

    def explode(*args, **kwargs):
        raise RuntimeError("unexpected failure inside the check")

    monkeypatch.setattr(main, "check_target", explode)

    target = main.LinkTarget("example.com", "example.com", "https://example.com/")
    worker = main.LinkCheckWorker(target, 2, 30)
    received = []
    worker.signals.link_checked.connect(received.append)

    worker.run()

    assert len(received) == 1, "worker did not emit a result"
    assert received[0].availability_status == "INACTIVE"
    assert received[0].normalized_url == "https://example.com/"
    assert "unexpected failure" in received[0].message


def test_check_all_button_recovers_when_every_check_explodes(qtbot, window, monkeypatch):
    """The user visible symptom: the button must come back."""
    monkeypatch.setattr(main.QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(main.QMessageBox, "warning", lambda *a, **k: None)

    def explode(*args, **kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr(main, "check_target", explode)

    window.add_links(["example.com", "example.org"])
    assert len(window.targets) == 2

    window.check_all()
    assert window.check_all_button.isEnabled() is False

    qtbot.waitUntil(lambda: window.pending_checks == 0, timeout=5000)
    assert window.check_all_button.isEnabled() is True
    assert window.history.rowCount() == 2


@pytest.mark.parametrize("status", ["ACTIVE", "INACTIVE"])
def test_cards_accept_results_without_crashing(qtbot, window, status, monkeypatch):
    from conftest import make_result

    monkeypatch.setattr(main.QMessageBox, "information", lambda *a, **k: None)
    window.add_links(["example.com"])
    result = make_result(availability_status=status, normalized_url="https://example.com/")
    window.handle_link_result(result)
    card = window.cards["https://example.com/"]
    assert card.status_label.text() == status
