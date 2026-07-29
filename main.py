from __future__ import annotations

import csv
import platform
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, QTimer, Signal, Slot
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractSpinBox,
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

try:
    import mssql_python as MSSQL_PYTHON  # type: ignore[import-not-found]
except Exception:
    MSSQL_PYTHON = None


if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent

LOG_DIR = APP_DIR / "logs"
CHECK_LOG_FILE = LOG_DIR / "checks.csv"
IIS_LOG_FILE = LOG_DIR / "iis_actions.csv"
DATABASE_LOG_FILE = LOG_DIR / "database_metadata.csv"
THEME_FILE = APP_DIR / "theme_light.qss"

SSL_WARNING_DAYS = 30
DEFAULT_TIMEOUT_SECONDS = 8
DEFAULT_INTERVAL_SECONDS = 30
DEFAULT_MAX_CONCURRENT_CHECKS = 10
MAX_LINKS_SOFT_LIMIT = 50

# The dashboard is meant to be left running for days on a 30 second timer, so
# the in memory history has to stop somewhere. logs/checks.csv keeps everything.
MAX_HISTORY_ROWS = 500

TABLE_URL_LIMIT = 72
TABLE_MESSAGE_LIMIT = 90
CARD_URL_LIMIT = 62
CARD_MESSAGE_LIMIT = 78
DETAIL_WRAP_WIDTH = 112

CHECK_LOG_COLUMNS = [
    "checked_at",
    "name",
    "input_url",
    "normalized_https_url",
    "domain",
    "primary_ip",
    "all_resolved_ips",
    "dns_status",
    "dns_error",
    "availability_status",
    "https_status",
    "ssl_status",
    "certificate_expires_at",
    "certificate_days_remaining",
    "response_time_ms",
    "http_code",
    "message",
]

IIS_LOG_COLUMNS = ["timestamp", "action", "service_name", "result", "message"]

DATABASE_LOG_COLUMNS = [
    "timestamp",
    "auth_method",
    "database_name",
    "table_count",
    "schema_count",
    "database_size_mb",
    "result",
    "message",
]

IIS_SERVICES = {
    "IIS Web Service (W3SVC)": "W3SVC",
    "Windows Process Activation Service (WAS)": "WAS",
}

DB_SERVER_PATTERN = re.compile(r"^[A-Za-z0-9_.\\,: -]{1,160}$")
DB_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.$ -]{1,128}$")

SCHEME_PREFIX_PATTERN = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
HOST_PORT_PATTERN = re.compile(r"^[A-Za-z0-9._\-]+:\d+(?:[/?#].*)?$")

# Just enough DER to read validity dates and common names out of a certificate
# that openssl would not validate. 2.5.4.3 is id-at-commonName.
COMMON_NAME_OID = b"\x55\x04\x03"
DER_UTC_TIME = 0x17
DER_GENERALIZED_TIME = 0x18
DER_EXPLICIT_VERSION = 0xA0


@dataclass(frozen=True)
class LinkTarget:
    name: str
    input_url: str
    normalized_url: str


@dataclass(frozen=True)
class SslCheckResult:
    status: str
    expires_at: str
    days_remaining: str
    issuer: str
    subject: str
    message: str


@dataclass(frozen=True)
class DnsLookupResult:
    domain: str
    primary_ip: str
    all_resolved_ips: list[str]
    status: str
    error: str


@dataclass(frozen=True)
class LinkCheckResult:
    name: str
    input_url: str
    normalized_url: str
    domain: str
    primary_ip: str
    all_resolved_ips: list[str]
    dns_status: str
    dns_error: str
    availability_status: str
    https_status: str
    ssl_status: str
    certificate_expires_at: str
    certificate_days_remaining: str
    response_time_ms: str
    http_code: str
    checked_at: str
    message: str
    issuer: str
    subject: str


@dataclass(frozen=True)
class IisActionResult:
    timestamp: str
    action: str
    service_name: str
    success: bool
    message: str


@dataclass(frozen=True)
class DatabaseConnectionSettings:
    server: str
    database: str
    trust_server_certificate: bool = False


@dataclass(frozen=True)
class DatabaseTableMetadata:
    schema_name: str
    table_name: str
    row_count: int
    column_count: int
    reserved_mb: float


@dataclass(frozen=True)
class DatabaseColumnMetadata:
    schema_name: str
    table_name: str
    column_name: str
    data_type: str
    max_length: str
    nullable: str


@dataclass(frozen=True)
class DatabaseMetadataResult:
    timestamp: str
    success: bool
    auth_method: str
    database_name: str
    server_name: str
    database_size_mb: str
    schemas: list[str]
    tables: list[DatabaseTableMetadata]
    columns: list[DatabaseColumnMetadata]
    last_read_at: str
    message: str


class WorkerSignals(QObject):
    link_checked = Signal(object)
    iis_finished = Signal(object)
    database_finished = Signal(object)


class LinkCheckWorker(QRunnable):
    def __init__(self, target: LinkTarget, timeout_seconds: int, warning_days: int) -> None:
        super().__init__()
        self.target = target
        self.timeout_seconds = timeout_seconds
        self.warning_days = warning_days
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        try:
            result = check_target(self.target, self.timeout_seconds, self.warning_days)
        except Exception as exc:
            # MainWindow counts these emissions down to decide when a round is
            # over. A worker that dies without emitting leaves the count above
            # zero forever, which keeps Check All Now disabled for the rest of
            # the session, so every failure has to come back as a result.
            result = failed_check_result(self.target, f"Check failed unexpectedly: {exc}")
        self.signals.link_checked.emit(result)


class IisActionWorker(QRunnable):
    def __init__(self, action: str, service_name: str) -> None:
        super().__init__()
        self.action = action
        self.service_name = service_name
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        self.signals.iis_finished.emit(run_iis_action(self.action, self.service_name))


class DatabaseMetadataWorker(QRunnable):
    def __init__(self, settings: DatabaseConnectionSettings) -> None:
        super().__init__()
        self.settings = settings
        self.signals = WorkerSignals()

    @Slot()
    def run(self) -> None:
        self.signals.database_finished.emit(read_sql_server_metadata(self.settings))


class NumberStepper(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("NumberStepper")

        self.spin = QSpinBox()
        self.spin.setObjectName("StepperSpin")
        self.spin.setButtonSymbols(QAbstractSpinBox.ButtonSymbols.NoButtons)
        self.spin.setFrame(False)

        self.minus_button = QPushButton("-")
        self.minus_button.setObjectName("StepperMinus")
        self.minus_button.setFixedSize(34, 42)
        self.minus_button.clicked.connect(self.spin.stepDown)

        self.plus_button = QPushButton("+")
        self.plus_button.setObjectName("StepperPlus")
        self.plus_button.setFixedSize(34, 42)
        self.plus_button.clicked.connect(self.spin.stepUp)

        buttons = QVBoxLayout()
        buttons.setContentsMargins(0, 0, 0, 0)
        buttons.setSpacing(0)
        buttons.addWidget(self.plus_button)
        buttons.addWidget(self.minus_button)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.spin, 1)
        layout.addLayout(buttons)

    def setRange(self, minimum: int, maximum: int) -> None:
        self.spin.setRange(minimum, maximum)

    def setValue(self, value: int) -> None:
        self.spin.setValue(value)

    def value(self) -> int:
        return self.spin.value()

    def setSuffix(self, suffix: str) -> None:
        self.spin.setSuffix(suffix)


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def shorten_middle(text: str, max_chars: int) -> str:
    if max_chars <= 0:
        return ""
    if len(text) <= max_chars:
        return text
    if max_chars <= 8:
        return text[:max_chars]
    # front + back must add up to keep exactly. Clamping either side with a
    # minimum blows the budget and returns a string longer than max_chars,
    # which is how this used to widen table columns past their set width.
    keep = max_chars - 3
    front = max(1, int(keep * 0.62))
    back = keep - front
    return f"{text[:front]}...{text[-back:]}"


def wrap_long_text(text: str, width: int = DETAIL_WRAP_WIDTH) -> str:
    if len(text) <= width:
        return text
    chunks: list[str] = []
    current = text
    while len(current) > width:
        chunks.append(current[:width])
        current = current[width:]
    if current:
        chunks.append(current)
    return "\n".join(chunks)


def normalize_to_https(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError("URL is empty.")

    scheme_match = SCHEME_PREFIX_PATTERN.match(url)
    if scheme_match:
        if scheme_match.group(1).lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported.")
        parsed = urlparse(url)
    elif HOST_PORT_PATTERN.match(url):
        # urlparse reads "localhost:8080" as scheme "localhost" with path
        # "8080", so a bare internal host with a port has to get the scheme
        # attached before it is parsed at all.
        parsed = urlparse("https://" + url)
    elif ":" in url.split("/", 1)[0]:
        # Something like "mailto:someone@example.com": a scheme we do not want.
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    else:
        parsed = urlparse("https://" + url)

    if not parsed.hostname:
        raise ValueError("URL must include a host.")

    # An empty path and "/" address the same page. Normalizing to "/" keeps the
    # dashboard from showing the same site on two cards.
    parsed = parsed._replace(scheme="https", path=parsed.path or "/", fragment="")
    return urlunparse(parsed)


def display_name_for_url(normalized_url: str) -> str:
    host = urlparse(normalized_url).hostname or normalized_url
    return host.replace("www.", "", 1)


def domain_for_url(normalized_url: str) -> str:
    return urlparse(normalized_url).hostname or ""


def lookup_domain_ips(normalized_url: str) -> DnsLookupResult:
    domain = domain_for_url(normalized_url)
    if not domain:
        return DnsLookupResult("", "", [], "FAILED", "Missing domain.")

    try:
        resolved: list[str] = []
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            ip = str(sockaddr[0])
            if ip not in resolved:
                resolved.append(ip)
        if not resolved:
            return DnsLookupResult(domain, "", [], "FAILED", "DNS lookup returned no IP addresses.")
        return DnsLookupResult(domain, resolved[0], resolved, "RESOLVED", "")
    except socket.gaierror as exc:
        return DnsLookupResult(domain, "", [], "FAILED", str(exc))
    except OSError as exc:
        return DnsLookupResult(domain, "", [], "FAILED", str(exc))
    except (UnicodeError, ValueError) as exc:
        # A DNS label longer than 63 characters makes getaddrinfo raise
        # UnicodeError, which is a ValueError and not an OSError, so it used to
        # escape this function and kill the worker thread running the check.
        return DnsLookupResult(domain, "", [], "FAILED", f"Invalid host name: {exc}")


def extract_cert_name(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str:
    for item in parts:
        for key, value in item:
            if key == "commonName":
                return value
    return ""


def parse_cert_datetime(value: str) -> datetime:
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER tag/length/value triple, returning the tag, the value and
    the offset just past it."""
    if offset + 2 > len(data):
        raise ValueError("Truncated certificate structure.")
    tag = data[offset]
    length_byte = data[offset + 1]
    offset += 2
    if length_byte < 0x80:
        length = length_byte
    else:
        count = length_byte & 0x7F
        if count == 0 or offset + count > len(data):
            raise ValueError("Unsupported certificate length encoding.")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise ValueError("Truncated certificate value.")
    return tag, data[offset : offset + length], offset + length


def der_children(contents: bytes) -> list[tuple[int, bytes]]:
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(contents):
        tag, value, offset = read_der_tlv(contents, offset)
        children.append((tag, value))
    return children


def der_common_name(name_der: bytes) -> str:
    """Pull the commonName out of an X.501 Name (a sequence of sets of pairs)."""
    for _, relative_name in der_children(name_der):
        for _, attribute in der_children(relative_name):
            parts = der_children(attribute)
            if len(parts) == 2 and parts[0][1] == COMMON_NAME_OID:
                return parts[1][1].decode("utf-8", "replace")
    return ""


def der_time_to_datetime(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii", "replace").strip()
    if tag == DER_UTC_TIME:
        stamp = datetime.strptime(text[:12], "%y%m%d%H%M%S")
    elif tag == DER_GENERALIZED_TIME:
        stamp = datetime.strptime(text[:14], "%Y%m%d%H%M%S")
    else:
        raise ValueError("Unsupported certificate time encoding.")
    return stamp.replace(tzinfo=timezone.utc)


def parse_certificate_der(der: bytes) -> tuple[str, str, str, str]:
    """Read expiry date, days remaining, issuer CN and subject CN from raw DER.

    ssl.getpeercert() returns an empty dict whenever the peer certificate was
    not validated, so for an expired or self signed certificate the only way to
    show its expiry date is to read the bytes directly.
    """
    _, certificate, _ = read_der_tlv(der, 0)
    _, tbs_certificate, _ = read_der_tlv(certificate, 0)
    fields = der_children(tbs_certificate)
    if fields and fields[0][0] == DER_EXPLICIT_VERSION:
        fields = fields[1:]
    if len(fields) < 5:
        raise ValueError("Certificate is missing expected fields.")

    # serial, signature algorithm, issuer, validity, subject
    issuer = der_common_name(fields[2][1])
    subject = der_common_name(fields[4][1])

    validity = der_children(fields[3][1])
    if len(validity) < 2:
        raise ValueError("Certificate validity is missing notAfter.")
    not_after = der_time_to_datetime(validity[1][0], validity[1][1])
    days = (not_after - datetime.now(timezone.utc)).days
    return not_after.strftime("%Y-%m-%d"), str(days), issuer, subject


def inspect_certificate_unverified(host: str, port: int, timeout_seconds: int) -> tuple[str, str, str, str]:
    try:
        context = ssl._create_unverified_context()
        with (
            socket.create_connection((host, port), timeout=timeout_seconds) as sock,
            context.wrap_socket(sock, server_hostname=host) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
        if not der:
            return "", "", "", ""
        return parse_certificate_der(der)
    except Exception:
        return "", "", "", ""


def check_ssl_certificate(normalized_url: str, timeout_seconds: int, warning_days: int) -> SslCheckResult:
    parsed = urlparse(normalized_url)
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return SslCheckResult("SSL ERROR", "", "", "", "", "Missing host.")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()

        expires_raw = cert.get("notAfter", "")
        expires_at = ""
        days_remaining = ""
        status = "SSL VALID"
        if expires_raw:
            expires_dt = parse_cert_datetime(expires_raw)
            expires_at = expires_dt.strftime("%Y-%m-%d")
            days = (expires_dt - datetime.now(timezone.utc)).days
            days_remaining = str(days)
            if days < 0:
                status = "SSL EXPIRED"
            elif days <= warning_days:
                status = "SSL EXPIRES SOON"

        issuer = extract_cert_name(cert.get("issuer", ()))
        subject = extract_cert_name(cert.get("subject", ()))
        return SslCheckResult(status, expires_at, days_remaining, issuer, subject, "Certificate verified.")
    except ssl.SSLCertVerificationError as exc:
        lower = str(exc).lower()
        expires, days, issuer, subject = inspect_certificate_unverified(host, port, timeout_seconds)
        status = "SSL ERROR"
        if "expired" in lower:
            status = "SSL EXPIRED"
        elif "not yet valid" in lower:
            status = "SSL NOT YET VALID"
        return SslCheckResult(status, expires, days, issuer, subject, str(exc))
    except ssl.SSLError as exc:
        return SslCheckResult("SSL ERROR", "", "", "", "", str(exc))
    except OSError as exc:
        return SslCheckResult("SSL ERROR", "", "", "", "", str(exc))
    except (UnicodeError, ValueError) as exc:
        # Covers an over long host name and a notAfter field that does not match
        # the expected certificate date format.
        return SslCheckResult("SSL ERROR", "", "", "", "", f"Certificate could not be read: {exc}")


def availability_from_http_code(code: int) -> tuple[str, str, str]:
    if 100 <= code < 600:
        return "ACTIVE", "HTTPS OK", "Website responded over HTTPS."
    return "INACTIVE", "HTTPS FAILED", "Server did not return a valid HTTP response."


def check_https_availability(normalized_url: str, timeout_seconds: int) -> tuple[str, str, str, str, str]:
    start = time.perf_counter()
    request = urllib.request.Request(
        normalized_url,
        headers={"User-Agent": "LinkStatusChecker/2.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            code = int(response.getcode())
            response.read(1024)
        response_ms = str(int((time.perf_counter() - start) * 1000))
        availability, https_status, message = availability_from_http_code(code)
        return availability, https_status, response_ms, str(code), message
    except urllib.error.HTTPError as exc:
        response_ms = str(int((time.perf_counter() - start) * 1000))
        availability, https_status, message = availability_from_http_code(exc.code)
        return availability, https_status, response_ms, str(exc.code), message
    except TimeoutError:
        response_ms = str(int((time.perf_counter() - start) * 1000))
        return "INACTIVE", "HTTPS FAILED", response_ms, "-", "Request timed out."
    except urllib.error.URLError as exc:
        response_ms = str(int((time.perf_counter() - start) * 1000))
        reason = getattr(exc, "reason", exc)
        return "INACTIVE", "HTTPS FAILED", response_ms, "-", str(reason)
    except OSError as exc:
        response_ms = str(int((time.perf_counter() - start) * 1000))
        return "INACTIVE", "HTTPS FAILED", response_ms, "-", str(exc)
    except (UnicodeError, ValueError) as exc:
        response_ms = str(int((time.perf_counter() - start) * 1000))
        return "INACTIVE", "HTTPS FAILED", response_ms, "-", f"Invalid URL: {exc}"


def check_target(target: LinkTarget, timeout_seconds: int, warning_days: int) -> LinkCheckResult:
    checked_at = now_text()
    dns_result = lookup_domain_ips(target.normalized_url)
    ssl_result = check_ssl_certificate(target.normalized_url, timeout_seconds, warning_days)
    availability, https_status, response_ms, http_code, availability_message = check_https_availability(
        target.normalized_url,
        timeout_seconds,
    )

    if dns_result.status == "FAILED":
        availability = "INACTIVE"
        message_parts = [f"DNS lookup failed: {dns_result.error}"]
    else:
        message_parts = [availability_message]
        if ssl_result.status not in {"SSL VALID", "SSL EXPIRES SOON"}:
            message_parts.append(ssl_result.message)
        elif ssl_result.status == "SSL EXPIRES SOON":
            message_parts.append("Certificate expires soon.")

    return LinkCheckResult(
        name=target.name,
        input_url=target.input_url,
        normalized_url=target.normalized_url,
        domain=dns_result.domain,
        primary_ip=dns_result.primary_ip,
        all_resolved_ips=dns_result.all_resolved_ips,
        dns_status=dns_result.status,
        dns_error=dns_result.error,
        availability_status=availability,
        https_status=https_status,
        ssl_status=ssl_result.status,
        certificate_expires_at=ssl_result.expires_at,
        certificate_days_remaining=ssl_result.days_remaining,
        response_time_ms=response_ms,
        http_code=http_code,
        checked_at=checked_at,
        message=" ".join(part for part in message_parts if part),
        issuer=ssl_result.issuer,
        subject=ssl_result.subject,
    )


def failed_check_result(target: LinkTarget, message: str) -> LinkCheckResult:
    """A complete INACTIVE result, for when a check cannot be completed at all."""
    return LinkCheckResult(
        name=target.name,
        input_url=target.input_url,
        normalized_url=target.normalized_url,
        domain=domain_for_url(target.normalized_url),
        primary_ip="",
        all_resolved_ips=[],
        dns_status="FAILED",
        dns_error=message,
        availability_status="INACTIVE",
        https_status="HTTPS FAILED",
        ssl_status="SSL NOT CHECKED",
        certificate_expires_at="",
        certificate_days_remaining="",
        response_time_ms="-",
        http_code="-",
        checked_at=now_text(),
        message=message,
        issuer="",
        subject="",
    )


def ensure_csv_header(path: Path, columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        with path.open("w", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow(columns)
        return

    try:
        with path.open("r", newline="", encoding="utf-8") as file:
            existing_header = next(csv.reader(file), [])
    except Exception:
        existing_header = []

    if existing_header == columns:
        return

    legacy = path.with_name(f"{path.stem}_legacy_{datetime.now().strftime('%Y%m%d_%H%M%S')}{path.suffix}")
    path.rename(legacy)
    with path.open("w", newline="", encoding="utf-8") as file:
        csv.writer(file).writerow(columns)


def append_check_log(result: LinkCheckResult) -> None:
    ensure_csv_header(CHECK_LOG_FILE, CHECK_LOG_COLUMNS)
    with CHECK_LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        csv.writer(file).writerow(
            [
                result.checked_at,
                result.name,
                result.input_url,
                result.normalized_url,
                result.domain,
                result.primary_ip,
                "; ".join(result.all_resolved_ips),
                result.dns_status,
                result.dns_error,
                result.availability_status,
                result.https_status,
                result.ssl_status,
                result.certificate_expires_at,
                result.certificate_days_remaining,
                result.response_time_ms,
                result.http_code,
                result.message,
            ]
        )


def append_iis_log(result: IisActionResult) -> None:
    ensure_csv_header(IIS_LOG_FILE, IIS_LOG_COLUMNS)
    with IIS_LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        csv.writer(file).writerow(
            [
                result.timestamp,
                result.action,
                result.service_name,
                "success" if result.success else "failure",
                result.message,
            ]
        )


def append_database_log(result: DatabaseMetadataResult) -> None:
    ensure_csv_header(DATABASE_LOG_FILE, DATABASE_LOG_COLUMNS)
    with DATABASE_LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        csv.writer(file).writerow(
            [
                result.timestamp,
                result.auth_method,
                result.database_name,
                len(result.tables),
                len(result.schemas),
                result.database_size_mb,
                "success" if result.success else "failure",
                result.message,
            ]
        )


def run_sc_command(args: list[str], timeout_seconds: int = 20) -> subprocess.CompletedProcess[str]:
    # Security-sensitive: args must be fixed by caller from the IIS_SERVICES allowlist.
    # Do not invoke a command shell or pass raw user text into this function.
    return subprocess.run(
        ["sc", *args],
        capture_output=True,
        text=True,
        timeout=timeout_seconds,
        check=False,
        shell=False,
    )


def import_mssql_python():
    return MSSQL_PYTHON


def validate_database_settings(settings: DatabaseConnectionSettings) -> str:
    if not settings.server or not DB_SERVER_PATTERN.fullmatch(settings.server):
        return "Invalid server name. Use only normal server, instance, host, comma-port, or domain characters."
    if not settings.database or not DB_NAME_PATTERN.fullmatch(settings.database):
        return "Invalid database name. Use only normal database-name characters."
    return ""


def build_integrated_sql_server_connection_string(settings: DatabaseConnectionSettings) -> str:
    validation_error = validate_database_settings(settings)
    if validation_error:
        raise ValueError(validation_error)
    return (
        f"Server={settings.server};"
        f"Database={settings.database};"
        "Trusted_Connection=Yes;"
        "Encrypt=Yes;"
        f"TrustServerCertificate={'Yes' if settings.trust_server_certificate else 'No'};"
        "ApplicationIntent=ReadOnly;"
    )


def safe_database_error(exc: Exception) -> str:
    text = str(exc).replace("\r", " ").replace("\n", " ")
    text = re.sub(
        r"(Driver=|SERVER=|Server=|DATABASE=|Database=|UID=|PWD=|User ID=|Password=)[^;]+",
        r"\1[hidden]",
        text,
        flags=re.IGNORECASE,
    )
    return shorten_middle(text, 220)


def database_row_value(row, key: str, index: int = 0):
    if row is None:
        return None
    if hasattr(row, key):
        return getattr(row, key)
    try:
        return row[key]
    except Exception:
        try:
            return row[index]
        except Exception:
            return None


def read_sql_server_metadata(settings: DatabaseConnectionSettings) -> DatabaseMetadataResult:
    timestamp = now_text()
    auth_method = "SQL Server 2025 / Windows Integrated Authentication / mssql-python"
    validation_error = validate_database_settings(settings)
    if validation_error:
        return DatabaseMetadataResult(timestamp, False, auth_method, "", "", "", [], [], [], "", validation_error)

    mssql_python = import_mssql_python()
    if mssql_python is None:
        return DatabaseMetadataResult(
            timestamp,
            False,
            auth_method,
            settings.database,
            "",
            "",
            [],
            [],
            [],
            "",
            "mssql-python is not installed. Install requirements.txt or use the packaged executable.",
        )

    try:
        connection_string = build_integrated_sql_server_connection_string(settings)
        connection = mssql_python.connect(connection_string, autocommit=True, timeout=8)
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT DB_NAME() AS database_name, @@SERVERNAME AS server_name;")
            row = cursor.fetchone()
            database_name_value = database_row_value(row, "database_name", 0)
            server_name_value = database_row_value(row, "server_name", 1)
            database_name = str(database_name_value or settings.database)
            server_name = str(server_name_value or "Connected")

            cursor.execute(
                """
                SELECT CAST(SUM(size) * 8.0 / 1024 AS decimal(18,2)) AS database_size_mb
                FROM sys.database_files;
                """
            )
            size_row = cursor.fetchone()
            database_size_value = database_row_value(size_row, "database_size_mb", 0)
            database_size_mb = "" if database_size_value is None else str(database_size_value)

            cursor.execute(
                """
                SELECT name
                FROM sys.schemas
                WHERE name NOT IN ('sys', 'INFORMATION_SCHEMA')
                ORDER BY name;
                """
            )
            schemas = [str(database_row_value(item, "name", 0)) for item in cursor.fetchall()]

            cursor.execute(
                """
                SELECT TOP (250)
                    s.name AS schema_name,
                    t.name AS table_name,
                    COALESCE(rc.row_count, 0) AS row_count,
                    COALESCE(cc.column_count, 0) AS column_count,
                    COALESCE(sz.reserved_mb, 0) AS reserved_mb
                FROM sys.tables AS t
                INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
                OUTER APPLY (
                    SELECT SUM(p.rows) AS row_count
                    FROM sys.partitions AS p
                    WHERE p.object_id = t.object_id AND p.index_id IN (0, 1)
                ) AS rc
                OUTER APPLY (
                    SELECT COUNT(*) AS column_count
                    FROM sys.columns AS c
                    WHERE c.object_id = t.object_id
                ) AS cc
                OUTER APPLY (
                    SELECT CAST(SUM(a.total_pages) * 8.0 / 1024 AS decimal(18,2)) AS reserved_mb
                    FROM sys.indexes AS i
                    INNER JOIN sys.partitions AS p
                        ON p.object_id = i.object_id AND p.index_id = i.index_id
                    INNER JOIN sys.allocation_units AS a
                        ON a.container_id = p.partition_id
                    WHERE i.object_id = t.object_id
                ) AS sz
                ORDER BY s.name, t.name;
                """
            )
            tables = [
                DatabaseTableMetadata(
                    str(database_row_value(item, "schema_name", 0)),
                    str(database_row_value(item, "table_name", 1)),
                    int(database_row_value(item, "row_count", 2) or 0),
                    int(database_row_value(item, "column_count", 3) or 0),
                    float(database_row_value(item, "reserved_mb", 4) or 0),
                )
                for item in cursor.fetchall()
            ]

            cursor.execute(
                """
                SELECT TOP (600)
                    s.name AS schema_name,
                    t.name AS table_name,
                    c.name AS column_name,
                    TYPE_NAME(c.user_type_id) AS data_type,
                    CASE
                        WHEN c.max_length = -1 THEN 'MAX'
                        WHEN TYPE_NAME(c.user_type_id) IN ('nvarchar', 'nchar') THEN CONVERT(varchar(20), c.max_length / 2)
                        ELSE CONVERT(varchar(20), c.max_length)
                    END AS max_length,
                    CASE WHEN c.is_nullable = 1 THEN 'YES' ELSE 'NO' END AS nullable
                FROM sys.columns AS c
                INNER JOIN sys.tables AS t ON t.object_id = c.object_id
                INNER JOIN sys.schemas AS s ON s.schema_id = t.schema_id
                ORDER BY s.name, t.name, c.column_id;
                """
            )
            columns = [
                DatabaseColumnMetadata(
                    str(database_row_value(item, "schema_name", 0)),
                    str(database_row_value(item, "table_name", 1)),
                    str(database_row_value(item, "column_name", 2)),
                    str(database_row_value(item, "data_type", 3)),
                    str(database_row_value(item, "max_length", 4)),
                    str(database_row_value(item, "nullable", 5)),
                )
                for item in cursor.fetchall()
            ]

            return DatabaseMetadataResult(
                timestamp,
                True,
                auth_method,
                database_name,
                server_name,
                database_size_mb,
                schemas,
                tables,
                columns,
                timestamp,
                "Read-only metadata loaded successfully.",
            )
        finally:
            connection.close()
    except Exception as exc:
        return DatabaseMetadataResult(
            timestamp,
            False,
            auth_method,
            settings.database,
            "",
            "",
            [],
            [],
            [],
            "",
            f"Database metadata read failed: {safe_database_error(exc)}",
        )


def parse_sc_state(output: str) -> str:
    for line in output.splitlines():
        if "STATE" in line and ":" in line:
            return line.split(":", 1)[1].strip()
    return "Unknown state"


def wait_for_service_state(service_name: str, expected: str, timeout_seconds: int = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        completed = run_sc_command(["query", service_name], timeout_seconds=10)
        if expected.lower() in completed.stdout.lower():
            return True
        time.sleep(1)
    return False


def friendly_service_error(text: str) -> str:
    lower = text.lower()
    if "access is denied" in lower or "access denied" in lower:
        return "Access denied. Start the app as administrator to control IIS services."
    if "does not exist" in lower:
        return "Service was not found. IIS may not be installed on this machine."
    return text.strip() or "Command failed."


def run_iis_action(action: str, service_name: str) -> IisActionResult:
    timestamp = now_text()
    if platform.system().lower() != "windows":
        return IisActionResult(timestamp, action, service_name, False, "IIS control is only available on Windows.")
    if service_name not in IIS_SERVICES.values():
        return IisActionResult(timestamp, action, service_name, False, "Service is not in the allowlist.")

    try:
        if action == "status":
            completed = run_sc_command(["query", service_name])
            output = completed.stdout or completed.stderr
            success = completed.returncode == 0
            message = parse_sc_state(output) if success else friendly_service_error(output)
            return IisActionResult(timestamp, action, service_name, success, message)

        if action == "start":
            completed = run_sc_command(["start", service_name])
            output = completed.stdout or completed.stderr
            if completed.returncode not in {0, 1056}:
                return IisActionResult(timestamp, action, service_name, False, friendly_service_error(output))
            if not wait_for_service_state(service_name, "RUNNING"):
                return IisActionResult(
                    timestamp,
                    action,
                    service_name,
                    False,
                    "Start was accepted but the service did not reach RUNNING in time.",
                )
            return IisActionResult(timestamp, action, service_name, True, "Service is running.")

        if action == "restart":
            stop_result = run_sc_command(["stop", service_name])
            stop_output = stop_result.stdout or stop_result.stderr
            if stop_result.returncode not in {0, 1062}:
                return IisActionResult(timestamp, action, service_name, False, friendly_service_error(stop_output))
            if not wait_for_service_state(service_name, "STOPPED"):
                return IisActionResult(
                    timestamp,
                    action,
                    service_name,
                    False,
                    "Stop was accepted but the service did not reach STOPPED in time. It was not restarted.",
                )
            start_result = run_sc_command(["start", service_name])
            start_output = start_result.stdout or start_result.stderr
            if start_result.returncode not in {0, 1056}:
                return IisActionResult(timestamp, action, service_name, False, friendly_service_error(start_output))
            if not wait_for_service_state(service_name, "RUNNING"):
                return IisActionResult(
                    timestamp,
                    action,
                    service_name,
                    False,
                    "Service was stopped but did not come back to RUNNING in time.",
                )
            return IisActionResult(timestamp, action, service_name, True, "Service restarted and running.")

        return IisActionResult(timestamp, action, service_name, False, "Unsupported IIS action.")
    except FileNotFoundError:
        return IisActionResult(timestamp, action, service_name, False, "The Windows sc command was not found.")
    except subprocess.TimeoutExpired:
        return IisActionResult(timestamp, action, service_name, False, "Service command timed out.")
    except Exception as exc:
        return IisActionResult(timestamp, action, service_name, False, str(exc))


class LinkCard(QFrame):
    selected = Signal(str)

    def __init__(self, key: str, target: LinkTarget) -> None:
        super().__init__()
        self.key = key
        self.target = target
        self.setObjectName("LinkCard")
        self.setProperty("selected", False)
        self.setProperty("status", "UNKNOWN")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(190)
        self.setMaximumHeight(210)

        self.name_label = QLabel(target.name)
        self.name_label.setObjectName("CardTitle")
        self.url_label = QLabel(shorten_middle(target.normalized_url, CARD_URL_LIMIT))
        self.url_label.setObjectName("CardUrl")
        self.url_label.setToolTip(target.normalized_url)

        self.status_label = QLabel("UNKNOWN")
        self.status_label.setObjectName("CardStatusBadge")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.ip_label = QLabel("IP: -")
        self.dns_label = QLabel("DNS: UNKNOWN")
        self.https_label = QLabel("HTTPS: -")
        self.response_label = QLabel("Response: -")
        self.ssl_label = QLabel("SSL: -")
        self.expiry_label = QLabel("Expires: -")
        self.checked_label = QLabel("Checked: -")
        self.message_label = QLabel("Message: -")
        self.message_label.setObjectName("CardMessage")
        self.message_label.setWordWrap(False)

        for label in (
            self.ip_label,
            self.dns_label,
            self.https_label,
            self.response_label,
            self.ssl_label,
            self.expiry_label,
            self.checked_label,
        ):
            label.setObjectName("CardMeta")
            label.setMinimumHeight(22)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(10)
        top.addWidget(self.name_label, 1)
        top.addWidget(self.status_label)
        layout.addLayout(top)
        layout.addWidget(self.url_label)

        metrics = QGridLayout()
        metrics.setContentsMargins(0, 4, 0, 0)
        metrics.setHorizontalSpacing(18)
        metrics.setVerticalSpacing(4)
        metrics.addWidget(self.ip_label, 0, 0)
        metrics.addWidget(self.dns_label, 0, 1)
        metrics.addWidget(self.https_label, 1, 0)
        metrics.addWidget(self.response_label, 1, 1)
        metrics.addWidget(self.ssl_label, 2, 0)
        metrics.addWidget(self.expiry_label, 2, 1)
        metrics.addWidget(self.checked_label, 3, 0, 1, 2)
        metrics.setColumnStretch(0, 1)
        metrics.setColumnStretch(1, 1)
        layout.addLayout(metrics)
        layout.addWidget(self.message_label)
        self._set_badge("UNKNOWN")

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        self.selected.emit(self.key)
        super().mousePressEvent(event)

    def set_selected(self, selected: bool) -> None:
        self.setProperty("selected", selected)
        self.style().unpolish(self)
        self.style().polish(self)

    def set_checking(self) -> None:
        self._set_badge("CHECKING")
        self.ip_label.setText("IP: -")
        self.dns_label.setText("DNS: CHECKING")
        self.https_label.setText("HTTPS: CHECKING")
        self.response_label.setText("Response: -")
        self.message_label.setText("Message: Checking...")
        self.dns_label.setStyleSheet("")
        self.ssl_label.setStyleSheet("")

    def update_result(self, result: LinkCheckResult) -> None:
        self._set_badge(result.availability_status)
        self.name_label.setText(result.domain or result.name)
        self.ip_label.setText(f"IP: {shorten_middle(result.primary_ip or '-', 32)}")
        self.dns_label.setText(f"DNS: {result.dns_status}")
        self.https_label.setText(f"HTTPS: {result.https_status}")
        self.ssl_label.setText(f"SSL: {result.ssl_status}")
        expiry = result.certificate_days_remaining or "-"
        date = result.certificate_expires_at or "-"
        self.expiry_label.setText(f"Expires: {expiry} days" if expiry != "-" else "Expires: -")
        self.expiry_label.setToolTip(date)
        response = f"{result.response_time_ms} ms" if result.response_time_ms and result.response_time_ms != "-" else "-"
        self.response_label.setText(f"Response: {response}")
        self.checked_label.setText(f"Checked: {result.checked_at.split(' ')[-1]}")
        self.message_label.setText(f"Message: {shorten_middle(result.message, CARD_MESSAGE_LIMIT)}")
        self.message_label.setToolTip(result.message)
        self.ip_label.setToolTip("; ".join(result.all_resolved_ips) or result.dns_error or "-")
        self.dns_label.setToolTip(result.dns_error or result.dns_status)
        self._set_dns_tone(result.dns_status)
        self._set_ssl_tone(result.ssl_status)

    def _set_badge(self, status: str) -> None:
        color = {
            "ACTIVE": "#10a875",
            "INACTIVE": "#e1435a",
            "CHECKING": "#1478ff",
            "UNKNOWN": "#7d8ba0",
        }.get(status, "#7d8ba0")
        self.status_label.setText(status)
        self.setProperty("status", status)
        self.style().unpolish(self)
        self.style().polish(self)
        self.status_label.setStyleSheet(
            f"""
            QLabel#CardStatusBadge {{
                background: {color};
                color: white;
                border-radius: 9px;
                padding: 5px 9px;
                font-weight: bold;
            }}
            """
        )

    def _set_dns_tone(self, status: str) -> None:
        color = "#10a875" if status == "RESOLVED" else "#e1435a" if status == "FAILED" else "#64748b"
        self.dns_label.setStyleSheet(f"QLabel#CardMeta {{ color: {color}; font-weight: 800; }}")

    def _set_ssl_tone(self, status: str) -> None:
        if status == "SSL VALID":
            color = "#10a875"
        elif status == "SSL EXPIRES SOON":
            color = "#d97706"
        elif status in {"SSL EXPIRED", "SSL NOT YET VALID", "SSL ERROR"}:
            color = "#e1435a"
        else:
            color = "#64748b"
        self.ssl_label.setStyleSheet(f"QLabel#CardMeta {{ color: {color}; font-weight: 800; }}")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Link Status Checker")
        self.setMinimumSize(1180, 760)
        self.resize(1320, 840)

        self.thread_pool = QThreadPool.globalInstance()
        self.thread_pool.setMaxThreadCount(DEFAULT_MAX_CONCURRENT_CHECKS)
        self.targets: dict[str, LinkTarget] = {}
        self.cards: dict[str, LinkCard] = {}
        self.results: list[LinkCheckResult] = []
        self.selected_key: str | None = None
        self.pending_checks = 0

        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self.check_all)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        self.url_input.setMinimumHeight(44)
        self.url_input.setMinimumWidth(420)
        self.url_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self.bulk_input = QPlainTextEdit()
        self.bulk_input.setPlaceholderText("Paste multiple URLs here, one per line")
        self.bulk_input.setMinimumHeight(92)
        self.bulk_input.setMaximumHeight(110)
        self.bulk_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self.timeout_input = NumberStepper()
        self.timeout_input.setRange(1, 60)
        self.timeout_input.setValue(DEFAULT_TIMEOUT_SECONDS)
        self.timeout_input.setSuffix(" sec")
        self.timeout_input.setMinimumSize(170, 42)

        self.interval_input = NumberStepper()
        self.interval_input.setRange(5, 3600)
        self.interval_input.setValue(DEFAULT_INTERVAL_SECONDS)
        self.interval_input.setSuffix(" sec")
        self.interval_input.setMinimumSize(170, 42)

        self.concurrent_input = NumberStepper()
        self.concurrent_input.setRange(1, 20)
        self.concurrent_input.setValue(DEFAULT_MAX_CONCURRENT_CHECKS)
        self.concurrent_input.setMinimumSize(170, 42)

        self.monitor_state = QLabel("Monitoring stopped")
        self.monitor_state.setObjectName("MonitorPill")
        self.monitor_state.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.card_grid_container = QWidget()
        self.card_grid = QGridLayout(self.card_grid_container)
        self.card_grid.setContentsMargins(0, 0, 0, 0)
        self.card_grid.setSpacing(12)

        self.history = QTableWidget(0, 10)
        self.history.setHorizontalHeaderLabels(
            [
                "Checked At",
                "Domain",
                "IP",
                "DNS",
                "Status",
                "HTTPS",
                "SSL",
                "Expires In",
                "Response",
                "Message",
            ]
        )
        self._configure_history_table()

        self.iis_service_combo = QComboBox()
        for display_name in IIS_SERVICES:
            self.iis_service_combo.addItem(display_name)
        self.iis_service_combo.setMinimumSize(360, 42)
        self.iis_result_label = QLabel("No IIS action yet.")
        self.iis_result_label.setObjectName("IisResult")
        self.iis_result_label.setWordWrap(True)
        self.iis_result_label.setMinimumHeight(48)

        self.db_provider_label = QLabel("SQL Server 2025 / mssql-python")
        self.db_provider_label.setObjectName("DatabaseProvider")
        self.db_provider_label.setMinimumHeight(42)

        self.db_server_input = QLineEdit()
        self.db_server_input.setPlaceholderText(r"SERVER\INSTANCE or server.domain.com")
        self.db_server_input.setMinimumHeight(42)

        self.db_database_input = QLineEdit()
        self.db_database_input.setPlaceholderText("Database name")
        self.db_database_input.setMinimumHeight(42)

        self.db_trust_cert_checkbox = QCheckBox("Trust server certificate for local test")
        self.db_trust_cert_checkbox.setObjectName("DatabaseTrustCheckbox")
        self.db_trust_cert_checkbox.setToolTip(
            "Use this only for local or test SQL Server certificates. Leave it off for production."
        )

        self.db_status_label = QLabel("No database read yet. Windows Integrated Authentication only.")
        self.db_status_label.setObjectName("DatabaseStatus")
        self.db_status_label.setWordWrap(True)
        self.db_status_label.setMinimumHeight(48)

        self.db_summary_label = QLabel("Database: -    Size: -    Schemas: -    Tables: -    Last read: -")
        self.db_summary_label.setObjectName("DatabaseSummary")
        self.db_summary_label.setWordWrap(True)

        self.db_tables = QTableWidget(0, 5)
        self.db_tables.setHorizontalHeaderLabels(["Schema", "Table", "Rows", "Columns", "Reserved MB"])
        self._configure_database_table(self.db_tables)

        self.db_columns = QTableWidget(0, 6)
        self.db_columns.setHorizontalHeaderLabels(["Schema", "Table", "Column", "Type", "Length", "Nullable"])
        self._configure_database_table(self.db_columns)

        self._build_ui()
        self._apply_styles()
        self._set_monitoring_state(False)
        self._set_iis_controls_enabled(platform.system().lower() == "windows")
        ensure_csv_header(CHECK_LOG_FILE, CHECK_LOG_COLUMNS)
        ensure_csv_header(IIS_LOG_FILE, IIS_LOG_COLUMNS)
        ensure_csv_header(DATABASE_LOG_FILE, DATABASE_LOG_COLUMNS)

    def _build_ui(self) -> None:
        content = QWidget()
        content.setMinimumWidth(1080)
        root = QVBoxLayout(content)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(14)

        header = QFrame()
        header.setObjectName("Hero")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(24, 18, 24, 18)

        title = QLabel("Link Status Checker")
        title.setObjectName("Title")
        subtitle = QLabel("Monitor HTTPS availability, SSL certificate health, and IIS service status.")
        subtitle.setObjectName("Subtitle")
        hint = QLabel("Add links manually, paste a list, or load URLs from CSV.")
        hint.setObjectName("HeroHint")
        title_box = QVBoxLayout()
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        title_box.addWidget(hint)
        header_layout.addLayout(title_box, 1)
        header_layout.addWidget(self.monitor_state)
        root.addWidget(header)

        input_group = QGroupBox("Links")
        input_group.setObjectName("ControlPanel")
        input_group.setMinimumHeight(330)
        input_layout = QVBoxLayout(input_group)
        input_layout.setContentsMargins(22, 28, 22, 20)
        input_layout.setSpacing(14)

        label_width = 132
        add_link_button = QPushButton("Add Link")
        add_link_button.setObjectName("PrimaryButton")
        add_link_button.setMinimumWidth(160)
        add_link_button.clicked.connect(self.add_single_link)

        url_label = QLabel("URL")
        url_label.setMinimumWidth(label_width)
        url_row = QHBoxLayout()
        url_row.setSpacing(14)
        url_row.addWidget(url_label)
        url_row.addWidget(self.url_input, 1)
        url_row.addWidget(add_link_button)
        input_layout.addLayout(url_row)

        add_bulk_button = QPushButton("Add Pasted")
        add_bulk_button.setObjectName("PrimaryButton")
        add_bulk_button.clicked.connect(self.add_bulk_links)
        load_csv_button = QPushButton("Load CSV")
        load_csv_button.setObjectName("SoftButton")
        load_csv_button.clicked.connect(self.load_links_from_csv)
        for button in (add_bulk_button, load_csv_button):
            button.setMinimumWidth(160)

        bulk_label = QLabel("Paste URLs")
        bulk_label.setMinimumWidth(label_width)
        bulk_buttons = QVBoxLayout()
        bulk_buttons.setSpacing(10)
        bulk_buttons.addWidget(add_bulk_button)
        bulk_buttons.addWidget(load_csv_button)
        bulk_buttons.addStretch(1)
        bulk_row = QHBoxLayout()
        bulk_row.setSpacing(14)
        bulk_row.addWidget(bulk_label)
        bulk_row.addWidget(self.bulk_input, 1)
        bulk_row.addLayout(bulk_buttons)
        input_layout.addLayout(bulk_row)

        remove_button = QPushButton("Remove Selected")
        remove_button.setObjectName("SoftButton")
        remove_button.clicked.connect(self.remove_selected_link)
        clear_links_button = QPushButton("Clear All")
        clear_links_button.setObjectName("DangerButton")
        clear_links_button.clicked.connect(self.clear_all)
        for button in (remove_button, clear_links_button):
            button.setMinimumWidth(160)

        settings_row = QHBoxLayout()
        settings_row.setSpacing(14)
        for label_text, field in (
            ("Timeout", self.timeout_input),
            ("Monitor every", self.interval_input),
            ("Concurrent checks", self.concurrent_input),
        ):
            label = QLabel(label_text)
            label.setMinimumWidth(108)
            settings_row.addWidget(label)
            settings_row.addWidget(field)
        settings_row.addStretch(1)
        input_layout.addLayout(settings_row)

        link_actions_row = QHBoxLayout()
        link_actions_row.addStretch(1)
        link_actions_row.setSpacing(12)
        link_actions_row.addWidget(remove_button)
        link_actions_row.addWidget(clear_links_button)
        input_layout.addLayout(link_actions_row)
        root.addWidget(input_group)

        controls = QHBoxLayout()
        self.check_all_button = QPushButton("Check All Now")
        self.check_all_button.setObjectName("PrimaryButton")
        self.check_all_button.clicked.connect(self.check_all)
        self.start_monitoring_button = QPushButton("Start Monitoring All")
        self.start_monitoring_button.setObjectName("SuccessButton")
        self.start_monitoring_button.clicked.connect(self.start_monitoring)
        self.stop_monitoring_button = QPushButton("Stop Monitoring")
        self.stop_monitoring_button.setObjectName("DangerButton")
        self.stop_monitoring_button.clicked.connect(self.stop_monitoring)
        self.stop_monitoring_button.setEnabled(False)
        export_button = QPushButton("Export History")
        export_button.setObjectName("SoftButton")
        export_button.clicked.connect(self.export_history)
        for button in (self.check_all_button, self.start_monitoring_button, self.stop_monitoring_button, export_button):
            controls.addWidget(button)
        controls.addStretch(1)
        root.addLayout(controls)

        dashboard_group = QGroupBox("Website Dashboard")
        dashboard_group.setObjectName("DashboardPanel")
        dashboard_group.setMinimumHeight(260)
        dashboard_layout = QVBoxLayout(dashboard_group)
        dashboard_layout.setContentsMargins(18, 24, 18, 18)
        dashboard_layout.addWidget(self.card_grid_container)
        root.addWidget(dashboard_group, 3)

        lower = QVBoxLayout()
        lower.setSpacing(14)
        lower.addWidget(self._build_iis_group())
        lower.addWidget(self._build_database_group())
        lower.addWidget(self._build_history_group())
        root.addLayout(lower, 2)

        main_scroll = QScrollArea()
        main_scroll.setWidgetResizable(True)
        main_scroll.setFrameShape(QFrame.Shape.NoFrame)
        main_scroll.setWidget(content)
        self.setCentralWidget(main_scroll)

    def _build_iis_group(self) -> QGroupBox:
        group = QGroupBox("IIS Service Control")
        group.setObjectName("IisPanel")
        group.setMinimumWidth(540)
        group.setMinimumHeight(230)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(22, 28, 22, 20)
        layout.setSpacing(12)

        service_row = QHBoxLayout()
        service_row.setSpacing(14)
        service_label = QLabel("Service")
        service_label.setMinimumWidth(82)
        service_row.addWidget(service_label)
        service_row.addWidget(self.iis_service_combo, 1)
        layout.addLayout(service_row)

        self.iis_status_button = QPushButton("Status")
        self.iis_status_button.setObjectName("SoftButton")
        self.iis_status_button.clicked.connect(lambda: self.run_iis_action_from_gui("status"))
        self.iis_start_button = QPushButton("Start")
        self.iis_start_button.setObjectName("SuccessButton")
        self.iis_start_button.clicked.connect(lambda: self.run_iis_action_from_gui("start"))
        self.iis_restart_button = QPushButton("Restart")
        self.iis_restart_button.setObjectName("DangerButton")
        self.iis_restart_button.clicked.connect(lambda: self.run_iis_action_from_gui("restart"))

        button_row = QHBoxLayout()
        button_row.setSpacing(10)
        for button in (self.iis_status_button, self.iis_start_button, self.iis_restart_button):
            button.setMinimumWidth(120)
            button_row.addWidget(button)
        button_row.addStretch(1)
        layout.addLayout(button_row)
        layout.addWidget(self.iis_result_label)
        layout.addStretch(1)
        return group

    def _build_database_group(self) -> QGroupBox:
        group = QGroupBox("Database Metadata (Read-Only)")
        group.setObjectName("DatabasePanel")
        group.setMinimumHeight(470)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(22, 28, 22, 20)
        layout.setSpacing(12)

        auth_note = QLabel(
            "Secure mode: SQL Server 2025 with Windows Integrated Authentication. SSMS 22 is used for setup; the app never accepts usernames or passwords."
        )
        auth_note.setObjectName("DatabaseNote")
        auth_note.setWordWrap(True)
        layout.addWidget(auth_note)

        first_row = QHBoxLayout()
        first_row.setSpacing(12)
        first_row.addWidget(QLabel("Provider"))
        first_row.addWidget(self.db_provider_label, 1)
        first_row.addWidget(QLabel("Server"))
        first_row.addWidget(self.db_server_input, 2)
        first_row.addWidget(QLabel("Database"))
        first_row.addWidget(self.db_database_input, 1)
        layout.addLayout(first_row)

        cert_row = QHBoxLayout()
        cert_row.addSpacing(74)
        cert_row.addWidget(self.db_trust_cert_checkbox)
        cert_row.addStretch(1)
        layout.addLayout(cert_row)

        actions = QHBoxLayout()
        self.db_read_button = QPushButton("Read Metadata")
        self.db_read_button.setObjectName("PrimaryButton")
        self.db_read_button.clicked.connect(self.read_database_metadata_from_gui)
        actions.addWidget(self.db_read_button)
        actions.addWidget(self.db_status_label, 1)
        layout.addLayout(actions)

        layout.addWidget(self.db_summary_label)

        tables_row = QHBoxLayout()
        tables_row.setSpacing(14)

        tables_box = QGroupBox("Tables")
        tables_box.setObjectName("DatabaseSubPanel")
        tables_layout = QVBoxLayout(tables_box)
        tables_layout.setContentsMargins(12, 22, 12, 12)
        tables_layout.addWidget(self.db_tables)

        columns_box = QGroupBox("Columns")
        columns_box.setObjectName("DatabaseSubPanel")
        columns_layout = QVBoxLayout(columns_box)
        columns_layout.setContentsMargins(12, 22, 12, 12)
        columns_layout.addWidget(self.db_columns)

        tables_row.addWidget(tables_box, 1)
        tables_row.addWidget(columns_box, 1)
        layout.addLayout(tables_row)
        return group

    def _build_history_group(self) -> QGroupBox:
        group = QGroupBox("History")
        group.setObjectName("HistoryPanel")
        group.setMinimumHeight(250)
        layout = QVBoxLayout(group)
        layout.setContentsMargins(18, 24, 18, 18)
        layout.addWidget(self.history)
        return group

    def _configure_history_table(self) -> None:
        self.history.verticalHeader().setVisible(False)
        self.history.verticalHeader().setDefaultSectionSize(34)
        self.history.setAlternatingRowColors(True)
        self.history.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.history.setWordWrap(False)
        header = self.history.horizontalHeader()
        header.setStretchLastSection(True)
        for column in range(self.history.columnCount()):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.Interactive)
        self.history.setColumnWidth(0, 136)
        self.history.setColumnWidth(2, 124)
        self.history.setColumnWidth(3, 148)
        self.history.setColumnWidth(4, 80)
        self.history.setColumnWidth(5, 82)
        self.history.setColumnWidth(6, 98)
        self.history.setColumnWidth(7, 82)
        self.history.setColumnWidth(8, 78)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(9, QHeaderView.ResizeMode.Stretch)

    def _configure_database_table(self, table: QTableWidget) -> None:
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(30)
        table.setAlternatingRowColors(True)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setWordWrap(False)
        table.setMinimumHeight(175)
        header = table.horizontalHeader()
        header.setStretchLastSection(True)
        for column in range(table.columnCount()):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        if table.columnCount() >= 2:
            header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)

    def _apply_styles(self) -> None:
        if THEME_FILE.exists():
            self.setStyleSheet(THEME_FILE.read_text(encoding="utf-8"))

    def _set_iis_controls_enabled(self, enabled: bool) -> None:
        for widget in (self.iis_service_combo, self.iis_status_button, self.iis_start_button, self.iis_restart_button):
            widget.setEnabled(enabled)
        if not enabled:
            self.iis_result_label.setText("IIS control is only available on Windows.")

    def add_single_link(self) -> None:
        self.add_links([self.url_input.text()])
        self.url_input.clear()

    def add_bulk_links(self) -> None:
        self.add_links(self.bulk_input.toPlainText().splitlines())
        self.bulk_input.clear()

    def add_links(self, raw_urls: list[str]) -> None:
        added = 0
        errors: list[str] = []
        for raw in raw_urls:
            raw = raw.strip()
            if not raw:
                continue
            try:
                normalized = normalize_to_https(raw)
            except ValueError as exc:
                errors.append(f"{raw}: {exc}")
                continue
            if normalized in self.targets:
                continue
            if len(self.targets) >= MAX_LINKS_SOFT_LIMIT:
                errors.append(f"Limit reached: {MAX_LINKS_SOFT_LIMIT} links.")
                break
            target = LinkTarget(display_name_for_url(normalized), raw, normalized)
            self.targets[normalized] = target
            self._add_card(normalized, target)
            added += 1
        self._relayout_cards()
        if errors:
            QMessageBox.warning(self, "Some URLs Were Skipped", "\n".join(errors[:8]))
        if added == 0 and not errors:
            QMessageBox.information(self, "No New Links", "No new links were added.")

    def _add_card(self, key: str, target: LinkTarget) -> None:
        card = LinkCard(key, target)
        card.selected.connect(self.select_card)
        self.cards[key] = card

    def _relayout_cards(self) -> None:
        while self.card_grid.count():
            item = self.card_grid.takeAt(0)
            if item.widget():
                item.widget().setParent(None)
        for index, card in enumerate(self.cards.values()):
            row = index // 2
            column = index % 2
            self.card_grid.addWidget(card, row, column)
        self.card_grid.setColumnStretch(0, 1)
        self.card_grid.setColumnStretch(1, 1)

    def select_card(self, key: str) -> None:
        self.selected_key = key
        for card_key, card in self.cards.items():
            card.set_selected(card_key == key)

    def remove_selected_link(self) -> None:
        if not self.selected_key:
            QMessageBox.information(self, "No Selection", "Select a card first.")
            return
        card = self.cards.pop(self.selected_key, None)
        self.targets.pop(self.selected_key, None)
        if card:
            card.setParent(None)
            card.deleteLater()
        self.selected_key = None
        self._relayout_cards()

    def clear_all(self) -> None:
        self.stop_monitoring()
        self.targets.clear()
        for card in self.cards.values():
            card.setParent(None)
            card.deleteLater()
        self.cards.clear()
        self.selected_key = None
        self.history.setRowCount(0)
        self.results.clear()
        self._relayout_cards()

    def load_links_from_csv(self) -> None:
        selected, _ = QFileDialog.getOpenFileName(self, "Load links from CSV", str(APP_DIR), "CSV files (*.csv)")
        if not selected:
            return
        links: list[str] = []
        try:
            with Path(selected).open("r", newline="", encoding="utf-8-sig") as file:
                for row in csv.reader(file):
                    if not row:
                        continue
                    value = row[0].strip()
                    if value.lower() in {"url", "link", "website"}:
                        continue
                    links.append(value)
        except OSError as exc:
            # Missing file, no permission, or the file is locked by Excel.
            QMessageBox.warning(self, "Could Not Read CSV", f"{Path(selected).name} could not be read.\n\n{exc}")
            return
        except (UnicodeDecodeError, csv.Error) as exc:
            QMessageBox.warning(
                self,
                "Could Not Read CSV",
                f"{Path(selected).name} does not look like a text CSV file.\n\n{exc}",
            )
            return
        self.add_links(links)

    def check_all(self) -> None:
        if self.pending_checks > 0:
            return
        if not self.targets:
            QMessageBox.information(self, "No Links", "Add at least one link first.")
            return
        self.thread_pool.setMaxThreadCount(self.concurrent_input.value())
        self.pending_checks = len(self.targets)
        self.check_all_button.setEnabled(False)
        for key, target in self.targets.items():
            self.cards[key].set_checking()
            worker = LinkCheckWorker(target, self.timeout_input.value(), SSL_WARNING_DAYS)
            worker.signals.link_checked.connect(self.handle_link_result)
            self.thread_pool.start(worker)

    def handle_link_result(self, result: LinkCheckResult) -> None:
        card = self.cards.get(result.normalized_url)
        if card:
            card.update_result(result)
        self.results.insert(0, result)
        self._add_history_row(result)
        self._trim_history()
        append_check_log(result)
        self.pending_checks = max(0, self.pending_checks - 1)
        if self.pending_checks == 0:
            self.check_all_button.setEnabled(True)

    def start_monitoring(self) -> None:
        if not self.targets:
            QMessageBox.information(self, "No Links", "Add at least one link first.")
            return
        self.monitor_timer.start(self.interval_input.value() * 1000)
        self.start_monitoring_button.setEnabled(False)
        self.stop_monitoring_button.setEnabled(True)
        self._set_monitoring_state(True)
        self.check_all()

    def stop_monitoring(self) -> None:
        self.monitor_timer.stop()
        self.start_monitoring_button.setEnabled(True)
        self.stop_monitoring_button.setEnabled(False)
        self._set_monitoring_state(False)

    def _set_monitoring_state(self, active: bool) -> None:
        if active:
            self.monitor_state.setText("Monitoring active")
            background = "#e0f8ea"
            color = "#11643a"
            border = "#8ed9ad"
        else:
            self.monitor_state.setText("Monitoring stopped")
            background = "#fff3d6"
            color = "#8a5a05"
            border = "#f2c766"
        self.monitor_state.setStyleSheet(
            f"""
            QLabel#MonitorPill {{
                background: {background};
                color: {color};
                border: 1px solid {border};
                border-radius: 16px;
                padding: 8px 14px;
                font-weight: bold;
            }}
            """
        )

    def _add_history_row(self, result: LinkCheckResult) -> None:
        self.history.insertRow(0)
        values = [
            result.checked_at,
            result.domain or result.name,
            shorten_middle(result.primary_ip or "-", 34),
            result.dns_status,
            result.availability_status,
            result.https_status,
            result.ssl_status,
            f"{result.certificate_days_remaining} days" if result.certificate_days_remaining else "-",
            f"{result.response_time_ms} ms" if result.response_time_ms and result.response_time_ms != "-" else "-",
            shorten_middle(result.message, TABLE_MESSAGE_LIMIT),
        ]
        full_values = [
            result.checked_at,
            result.domain or result.name,
            "; ".join(result.all_resolved_ips) or result.dns_error or "-",
            result.dns_error or result.dns_status,
            result.availability_status,
            result.https_status,
            result.ssl_status,
            result.certificate_expires_at,
            result.response_time_ms,
            result.message,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            item.setToolTip(full_values[column])
            item.setData(Qt.ItemDataRole.UserRole, full_values[column])
            if column == 3:
                item.setForeground(QColor(self._dns_color(result.dns_status)))
            if column == 4:
                item.setForeground(QColor(self._availability_color(result.availability_status)))
            if column == 6:
                item.setForeground(QColor(self._ssl_color(result.ssl_status)))
            self.history.setItem(0, column, item)

    def _trim_history(self) -> None:
        """Drop the oldest rows once the display cap is reached.

        Newest rows are inserted at index 0, so the tail is the oldest. Only the
        on screen table and the in memory list are trimmed; logs/checks.csv is
        the durable record and keeps every check.
        """
        del self.results[MAX_HISTORY_ROWS:]
        while self.history.rowCount() > MAX_HISTORY_ROWS:
            self.history.removeRow(self.history.rowCount() - 1)

    def _dns_color(self, status: str) -> str:
        return {
            "RESOLVED": "#10a875",
            "FAILED": "#e1435a",
            "UNKNOWN": "#7d8ba0",
        }.get(status, "#7d8ba0")

    def _availability_color(self, status: str) -> str:
        return {
            "ACTIVE": "#10a875",
            "INACTIVE": "#e1435a",
            "UNKNOWN": "#7d8ba0",
        }.get(status, "#7d8ba0")

    def _ssl_color(self, status: str) -> str:
        return {
            "SSL VALID": "#10a875",
            "SSL EXPIRES SOON": "#f39b20",
            "SSL EXPIRED": "#e1435a",
            "SSL NOT YET VALID": "#e1435a",
            "SSL ERROR": "#e1435a",
            "NO SSL": "#7d8ba0",
        }.get(status, "#7d8ba0")

    def export_history(self) -> None:
        if not self.results:
            QMessageBox.information(self, "No History", "There is no history to export.")
            return
        selected, _ = QFileDialog.getSaveFileName(
            self,
            "Export history",
            str(APP_DIR / "link_status_history.csv"),
            "CSV files (*.csv)",
        )
        if not selected:
            return
        with Path(selected).open("w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow(CHECK_LOG_COLUMNS)
            for result in self.results:
                writer.writerow(
                    [
                        result.checked_at,
                        result.name,
                        result.input_url,
                        result.normalized_url,
                        result.domain,
                        result.primary_ip,
                        "; ".join(result.all_resolved_ips),
                        result.dns_status,
                        result.dns_error,
                        result.availability_status,
                        result.https_status,
                        result.ssl_status,
                        result.certificate_expires_at,
                        result.certificate_days_remaining,
                        result.response_time_ms,
                        result.http_code,
                        result.message,
                    ]
                )
        QMessageBox.information(self, "Export Complete", "History exported.")

    def run_iis_action_from_gui(self, action: str) -> None:
        display_name = self.iis_service_combo.currentText()
        service_name = IIS_SERVICES.get(display_name)
        if not service_name:
            QMessageBox.warning(self, "Invalid Service", "Selected service is not allowed.")
            return
        if action in {"start", "restart"}:
            answer = QMessageBox.question(
                self,
                "Confirm IIS Action",
                f"{action.title()} {display_name}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.iis_result_label.setText(f"Running {action} for {service_name}...")
        for widget in (self.iis_status_button, self.iis_start_button, self.iis_restart_button):
            widget.setEnabled(False)
        worker = IisActionWorker(action, service_name)
        worker.signals.iis_finished.connect(self.handle_iis_result)
        self.thread_pool.start(worker)

    def handle_iis_result(self, result: IisActionResult) -> None:
        append_iis_log(result)
        state = "OK" if result.success else "FAILED"
        self.iis_result_label.setText(f"{result.timestamp} | {result.service_name} | {state}: {result.message}")
        if platform.system().lower() == "windows":
            for widget in (self.iis_status_button, self.iis_start_button, self.iis_restart_button):
                widget.setEnabled(True)

    def read_database_metadata_from_gui(self) -> None:
        settings = DatabaseConnectionSettings(
            server=self.db_server_input.text().strip(),
            database=self.db_database_input.text().strip(),
            trust_server_certificate=self.db_trust_cert_checkbox.isChecked(),
        )
        validation_error = validate_database_settings(settings)
        if validation_error:
            QMessageBox.warning(self, "Invalid Database Settings", validation_error)
            return

        self.db_read_button.setEnabled(False)
        self.db_status_label.setText("Reading database metadata with Windows Integrated Authentication...")
        self.db_summary_label.setText("Database: -    Size: -    Schemas: -    Tables: -    Last read: -")
        self.db_tables.setRowCount(0)
        self.db_columns.setRowCount(0)
        worker = DatabaseMetadataWorker(settings)
        worker.signals.database_finished.connect(self.handle_database_result)
        self.thread_pool.start(worker)

    def handle_database_result(self, result: DatabaseMetadataResult) -> None:
        append_database_log(result)
        self.db_read_button.setEnabled(True)
        status_text = "OK" if result.success else "FAILED"
        self.db_status_label.setText(f"{result.timestamp} | {status_text}: {result.message}")
        self.db_summary_label.setText(
            "Database: {database}    Size: {size} MB    Schemas: {schemas}    Tables: {tables}    Last read: {last_read}".format(
                database=result.database_name or "-",
                size=result.database_size_mb or "-",
                schemas=len(result.schemas),
                tables=len(result.tables),
                last_read=result.last_read_at or "-",
            )
        )
        self.populate_database_tables(result)

    def populate_database_tables(self, result: DatabaseMetadataResult) -> None:
        self.db_tables.setRowCount(0)
        for metadata in result.tables:
            row = self.db_tables.rowCount()
            self.db_tables.insertRow(row)
            values = [
                metadata.schema_name,
                metadata.table_name,
                str(metadata.row_count),
                str(metadata.column_count),
                f"{metadata.reserved_mb:.2f}",
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.db_tables.setItem(row, column, item)

        self.db_columns.setRowCount(0)
        for metadata in result.columns:
            row = self.db_columns.rowCount()
            self.db_columns.insertRow(row)
            values = [
                metadata.schema_name,
                metadata.table_name,
                metadata.column_name,
                metadata.data_type,
                metadata.max_length,
                metadata.nullable,
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.db_columns.setItem(row, column, item)

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self.monitor_timer.stop()
        self.thread_pool.waitForDone(3000)
        super().closeEvent(event)


def main() -> int:
    if "--db-self-test" in sys.argv:
        server = sys.argv[sys.argv.index("--server") + 1] if "--server" in sys.argv else r".\test"
        database = sys.argv[sys.argv.index("--database") + 1] if "--database" in sys.argv else "test"
        trust = "--trust-server-certificate" in sys.argv
        result = read_sql_server_metadata(DatabaseConnectionSettings(server, database, trust))
        output = APP_DIR / "db_self_test_result.txt"
        output.write_text(
            "\n".join(
                [
                    f"success={result.success}",
                    f"database={result.database_name}",
                    f"server={result.server_name}",
                    f"tables={len(result.tables)}",
                    f"columns={len(result.columns)}",
                    f"size_mb={result.database_size_mb}",
                    f"message={result.message}",
                ]
            ),
            encoding="utf-8",
        )
        return 0 if result.success else 2

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
