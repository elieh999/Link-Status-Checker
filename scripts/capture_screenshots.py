from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "windows")

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from src.link_status_checker import application as module  # noqa: E402


def result(url: str, *, response: int, health: str = "", ssl_status: str = "SSL VALID"):
    domain = module.domain_for_url(url)
    return module.LinkCheckResult(
        name=domain,
        input_url=url,
        normalized_url=url,
        domain=domain,
        primary_ip="203.0.113.20",
        all_resolved_ips=["203.0.113.20", "2001:db8::20"],
        dns_status="RESOLVED",
        dns_error="",
        availability_status="ACTIVE",
        https_status="HTTPS OK",
        ssl_status=ssl_status,
        certificate_expires_at="2026-12-18",
        certificate_days_remaining="141",
        response_time_ms=str(response),
        http_code="200",
        checked_at="2026-07-30 14:20:00",
        message="Website responded over HTTPS.",
        issuer="Example Internal CA",
        subject=domain,
        health_status=health,
    )


def main() -> int:
    output = ROOT / "docs" / "screenshots"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="link-status-screenshots-") as temp:
        data = Path(temp)
        module.DATA_DIR = data
        module.LOG_DIR = data / "logs"
        module.CHECK_LOG_FILE = module.LOG_DIR / "checks.csv"
        module.IIS_LOG_FILE = module.LOG_DIR / "iis_actions.csv"
        module.DATABASE_LOG_FILE = module.LOG_DIR / "database_metadata.csv"
        module.HISTORY_DB_FILE = data / "monitoring.db"
        module.SETTINGS_FILE = data / "settings.ini"

        app = QApplication.instance() or QApplication([])
        window = module.MainWindow()
        window.resize(1366, 768)
        urls = [
            "https://portal.example.com/",
            "https://api.example.com/health",
            "https://checkout.example.com/",
            "https://intranet.example.com/",
            "https://reports.example.com/",
        ]
        window.add_links(urls)
        window.handle_link_result(result(urls[0], response=214))
        window.handle_link_result(result(urls[1], response=1475))
        window.handle_link_result(result(urls[2], response=380, ssl_status="SSL UNTRUSTED"))
        window.handle_link_result(result(urls[3], response=291))
        window.handle_status_request(urls[3], "MAINTENANCE")
        window.show()
        app.processEvents()

        window.show_page(0)
        app.processEvents()
        window.grab().save(str(output / "overview.png"))
        window.show_page(1)
        app.processEvents()
        window.grab().save(str(output / "websites.png"))
        window.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
