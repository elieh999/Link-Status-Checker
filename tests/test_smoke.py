from __future__ import annotations

import main


def test_main_window_builds_and_shows(window):
    """The whole widget tree must construct without raising."""
    window.show()
    assert window.windowTitle() == "Link Status Checker"
    assert window.centralWidget() is not None
    assert window.history.columnCount() == 10


def test_logs_start_with_the_expected_headers(window, log_dir):
    """MainWindow creates its three CSV logs with the documented columns."""
    import csv

    for path, columns in (
        (log_dir / "checks.csv", main.CHECK_LOG_COLUMNS),
        (log_dir / "iis_actions.csv", main.IIS_LOG_COLUMNS),
        (log_dir / "database_metadata.csv", main.DATABASE_LOG_COLUMNS),
    ):
        assert path.exists(), f"{path.name} was not created"
        with path.open(newline="", encoding="utf-8") as file:
            assert next(csv.reader(file)) == columns
