from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from PySide6.QtWidgets import QApplication  # noqa: E402

from src.link_status_checker import application as application_module  # noqa: E402
from src.link_status_checker.storage.database import MonitoringStore  # noqa: E402


def elapsed(started: float) -> float:
    return round(time.perf_counter() - started, 4)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=PROJECT_ROOT / "docs" / "benchmark_results.json")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="link-status-benchmark-") as temp:
        temp_path = Path(temp)
        appdata = temp_path / "appdata"
        application_module.DATA_DIR = appdata
        application_module.LOG_DIR = appdata / "logs"
        application_module.CHECK_LOG_FILE = application_module.LOG_DIR / "checks.csv"
        application_module.IIS_LOG_FILE = application_module.LOG_DIR / "iis_actions.csv"
        application_module.DATABASE_LOG_FILE = application_module.LOG_DIR / "database_metadata.csv"
        application_module.HISTORY_DB_FILE = appdata / "monitoring.db"
        application_module.SETTINGS_FILE = appdata / "settings.ini"
        store = MonitoringStore(temp_path / "benchmark.db")

        started = time.perf_counter()
        website_ids = store.upsert_websites(
            (f"https://site-{index}.example.test/", f"site-{index}.example.test") for index in range(2000)
        )
        save_2000_seconds = elapsed(started)

        first_id = next(iter(website_ids.values()))
        base_time = datetime.now(timezone.utc) - timedelta(days=1)
        rows = [
            (
                first_id,
                (base_time + timedelta(seconds=index)).isoformat(),
                "HEALTHY" if index % 20 else "DEGRADED",
                "Synthetic benchmark row",
                200,
                100 + index % 900,
                "RESOLVED",
                "SSL VALID",
                "2027-01-01",
                None,
                None,
                1,
                1,
            )
            for index in range(100_000)
        ]
        started = time.perf_counter()
        with store.connect() as connection:
            connection.executemany(
                """
                INSERT INTO check_results(
                    website_id, checked_at, status, reason, http_code,
                    response_time_ms, dns_status, ssl_status, ssl_expiry,
                    problem_code, technical_error, included_in_uptime, available
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
        write_100k_seconds = elapsed(started)

        started = time.perf_counter()
        summary = store.analytics(base_time - timedelta(seconds=1))
        analytics_100k_seconds = elapsed(started)
        store.close()

        app = QApplication.instance() or QApplication([])
        started = time.perf_counter()
        window = application_module.MainWindow()
        window.add_links([f"ui-{index}.example.test" for index in range(1000)])
        app.processEvents()
        load_1000_ui_seconds = elapsed(started)
        visible_cards = len(window.cards)

        started = time.perf_counter()
        window.search_input.setText("ui-99")
        app.processEvents()
        filter_1000_seconds = elapsed(started)
        filtered_cards = len(window.cards)
        window.close()

    results = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "machine": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python": platform.python_version(),
        },
        "save_2000_websites_seconds": save_2000_seconds,
        "write_100000_checks_seconds": write_100k_seconds,
        "analytics_100000_checks_seconds": analytics_100k_seconds,
        "load_and_render_1000_websites_seconds": load_1000_ui_seconds,
        "filter_1000_websites_seconds": filter_1000_seconds,
        "visible_card_limit": visible_cards,
        "filtered_visible_cards": filtered_cards,
        "analytics_total_checks": summary.total_checks,
        "analytics_uptime_percent": summary.uptime_percent,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(json.dumps(results, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
