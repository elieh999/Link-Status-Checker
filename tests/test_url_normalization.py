from __future__ import annotations

import pytest

import main


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("http://example.com", "https://example.com/"),
        ("https://example.com", "https://example.com/"),
        ("HTTP://Example.COM", "https://Example.COM/"),
        ("  example.com  ", "https://example.com/"),
        ("example.com/status", "https://example.com/status"),
        ("example.com/status?deep=1", "https://example.com/status?deep=1"),
        ("https://example.com#anchor", "https://example.com/"),
        ("192.168.1.10:8080", "https://192.168.1.10:8080/"),
    ],
)
def test_normalize_to_https_common_inputs(raw, expected):
    assert main.normalize_to_https(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("localhost:8080", "https://localhost:8080/"),
        ("intranet:9000", "https://intranet:9000/"),
        ("iis-node-1:443", "https://iis-node-1:443/"),
    ],
)
def test_host_and_port_without_a_scheme_is_accepted(raw, expected):
    """Regression: these used to raise "Only HTTP and HTTPS URLs are supported".

    urlparse reads "localhost" in "localhost:8080" as the scheme, so a bare
    internal hostname with a port was rejected outright. That is exactly the
    shape of an internal IIS target this app exists to watch.
    """
    assert main.normalize_to_https(raw) == expected


@pytest.mark.parametrize("raw", ["ftp://example.com", "file:///c:/tmp", "mailto:someone@example.com"])
def test_real_non_http_schemes_are_still_rejected(raw):
    with pytest.raises(ValueError):
        main.normalize_to_https(raw)


@pytest.mark.parametrize("raw", ["", "   ", "https://", "http://"])
def test_empty_or_hostless_input_is_rejected(raw):
    with pytest.raises(ValueError):
        main.normalize_to_https(raw)


def test_trailing_slash_does_not_create_a_second_target():
    """Regression: "example.com" and "example.com/" were two different keys,
    so the same site could occupy two cards and be checked twice."""
    assert main.normalize_to_https("example.com") == main.normalize_to_https("example.com/")
    assert main.normalize_to_https("https://example.com") == main.normalize_to_https("https://example.com/")


def test_normalized_url_keeps_the_host_for_display_and_dns():
    normalized = main.normalize_to_https("localhost:8080")
    assert main.domain_for_url(normalized) == "localhost"
    assert main.display_name_for_url(normalized) == "localhost"
