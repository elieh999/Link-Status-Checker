from __future__ import annotations

import errno
import socket
import ssl
from dataclasses import dataclass


@dataclass(frozen=True)
class CheckProblem:
    code: str
    severity: str
    title: str
    explanation: str
    recommended_action: str
    technical_details: str
    retryable: bool
    component: str


def _problem(
    code: str,
    title: str,
    explanation: str,
    action: str,
    exc: BaseException,
    *,
    retryable: bool = False,
    component: str = "HTTPS",
) -> CheckProblem:
    return CheckProblem(code, "error", title, explanation, action, str(exc), retryable, component)


def classify_ssl_problem(exc: BaseException, hostname: str = "") -> CheckProblem:
    technical = str(exc)
    message = getattr(exc, "verify_message", "") or technical
    lower = message.lower()
    verify_code = getattr(exc, "verify_code", None)

    if isinstance(exc, (TimeoutError, socket.timeout)):
        return _problem(
            "connection_timeout",
            "HTTPS connection timed out",
            "The server did not complete the secure connection before the timeout.",
            "Check the network route, firewall, server availability, and timeout setting.",
            exc,
            retryable=True,
        )
    if isinstance(exc, ConnectionRefusedError) or getattr(exc, "errno", None) == errno.ECONNREFUSED:
        return _problem(
            "connection_refused",
            "HTTPS connection refused",
            "The server rejected the connection on its HTTPS port.",
            "Confirm that the server is running and that HTTPS is bound to the expected port.",
            exc,
            retryable=True,
        )
    if isinstance(exc, socket.gaierror):
        return _problem(
            "dns_failure",
            "Domain name could not be resolved",
            f"The computer could not find an IP address for {hostname or 'this hostname'}.",
            "Check the domain name and its DNS records.",
            exc,
            retryable=True,
            component="DNS",
        )
    if "expired" in lower or verify_code == 10:
        return _problem(
            "certificate_expired",
            "SSL certificate expired",
            "The website responded, but its certificate is past its expiry date.",
            "Renew the certificate and update the server HTTPS binding.",
            exc,
        )
    if "not yet valid" in lower or verify_code == 9:
        return _problem(
            "certificate_not_yet_valid",
            "SSL certificate is not yet valid",
            "The certificate validity period has not started.",
            "Check the certificate dates and the server clock.",
            exc,
        )
    if "hostname" in lower or "doesn't match" in lower or "not valid for" in lower or verify_code == 62:
        return _problem(
            "certificate_hostname_mismatch",
            "Certificate hostname mismatch",
            f"The certificate does not cover {hostname or 'the requested hostname'}.",
            "Install a certificate that includes this hostname in its Subject Alternative Names.",
            exc,
        )
    if "self-signed" in lower or "self signed" in lower or verify_code in {18, 19}:
        return _problem(
            "certificate_self_signed",
            "Self signed certificate is not trusted",
            "The server supplied a self signed certificate that this computer does not trust.",
            "Use a trusted certificate or install the approved internal root certificate.",
            exc,
        )
    if (
        "issuer" in lower
        or "certificate chain" in lower
        or "unable to get local" in lower
        or verify_code in {2, 20, 21}
    ):
        return _problem(
            "certificate_chain_untrusted",
            "Certificate chain could not be verified",
            "The certificate issuer is not trusted or the server did not send the complete chain.",
            "Install the missing intermediate certificate and verify the server sends the complete chain.",
            exc,
        )
    if isinstance(exc, ssl.SSLError):
        return _problem(
            "tls_handshake_failed",
            "Secure connection could not be established",
            "The client and server could not complete the TLS handshake.",
            "Check the server TLS protocols, certificate binding, and cipher configuration.",
            exc,
            retryable=True,
        )
    return _problem(
        "ssl_unknown",
        "SSL check failed",
        "The secure connection failed for a reason the application could not classify.",
        "Open the technical details, then check the certificate and server TLS configuration.",
        exc,
        retryable=True,
    )
