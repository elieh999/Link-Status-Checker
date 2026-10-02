from __future__ import annotations

import os
import sys
from pathlib import Path

# Qt needs a platform plugin before the first QApplication is built. Offscreen
# keeps the suite runnable over SSH and in CI where there is no desktop.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

import main  # noqa: E402


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    """Point every CSV log at a temp dir so tests never touch the real logs."""
    monkeypatch.setattr(main, "LOG_DIR", tmp_path)
    monkeypatch.setattr(main, "CHECK_LOG_FILE", tmp_path / "checks.csv")
    monkeypatch.setattr(main, "IIS_LOG_FILE", tmp_path / "iis_actions.csv")
    monkeypatch.setattr(main, "DATABASE_LOG_FILE", tmp_path / "database_metadata.csv")
    monkeypatch.setattr(main, "HISTORY_DB_FILE", tmp_path / "monitoring.db")
    monkeypatch.setattr(main, "SETTINGS_FILE", tmp_path / "settings.ini")
    return tmp_path


@pytest.fixture
def window(qtbot, log_dir):
    """A real MainWindow with logging redirected to a temp dir."""
    win = main.MainWindow()
    qtbot.addWidget(win)
    return win


def make_result(**overrides):
    """A LinkCheckResult with sane defaults, so tests only state what matters."""
    values = {
        "name": "example.com",
        "input_url": "example.com",
        "normalized_url": "https://example.com",
        "domain": "example.com",
        "primary_ip": "93.184.216.34",
        "all_resolved_ips": ["93.184.216.34"],
        "dns_status": "RESOLVED",
        "dns_error": "",
        "availability_status": "ACTIVE",
        "https_status": "HTTPS OK",
        "ssl_status": "SSL VALID",
        "certificate_expires_at": "2027-01-01",
        "certificate_days_remaining": "200",
        "response_time_ms": "120",
        "http_code": "200",
        "checked_at": "2026-07-29 10:00:00",
        "message": "Website responded over HTTPS.",
        "issuer": "Test CA",
        "subject": "example.com",
    }
    values.update(overrides)
    return main.LinkCheckResult(**values)
