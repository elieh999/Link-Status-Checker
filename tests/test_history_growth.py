from __future__ import annotations

import pytest

import main
from conftest import make_result


@pytest.fixture(autouse=True)
def quiet_dialogs(monkeypatch):
    monkeypatch.setattr(main.QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(main.QMessageBox, "warning", lambda *a, **k: None)


def test_history_is_capped_during_long_monitoring(window):
    """Regression: nothing trimmed self.results or the table, so an overnight
    run at the default 30 second interval piled up tens of thousands of rows
    and grew memory until the app was killed.
    """
    cap = main.MAX_HISTORY_ROWS
    for index in range(cap + 250):
        window.handle_link_result(make_result(checked_at=f"row-{index}"))

    assert window.history.rowCount() == cap
    assert len(window.results) == cap


def test_the_newest_result_stays_on_top_after_trimming(window):
    for index in range(main.MAX_HISTORY_ROWS + 50):
        window.handle_link_result(make_result(checked_at=f"row-{index}"))

    newest = f"row-{main.MAX_HISTORY_ROWS + 49}"
    assert window.results[0].checked_at == newest
    assert window.history.item(0, 0).text() == newest


def test_the_oldest_results_are_the_ones_dropped(window):
    for index in range(main.MAX_HISTORY_ROWS + 10):
        window.handle_link_result(make_result(checked_at=f"row-{index}"))

    kept = {result.checked_at for result in window.results}
    assert "row-0" not in kept, "the oldest row should have been trimmed"
    assert f"row-{main.MAX_HISTORY_ROWS + 9}" in kept


def test_short_runs_are_untouched(window):
    for index in range(25):
        window.handle_link_result(make_result(checked_at=f"row-{index}"))
    assert window.history.rowCount() == 25
    assert len(window.results) == 25


def test_export_still_writes_every_retained_row(window, tmp_path, monkeypatch):
    for index in range(30):
        window.handle_link_result(make_result(checked_at=f"row-{index}"))

    target = tmp_path / "exported.csv"
    monkeypatch.setattr(main.QFileDialog, "getSaveFileName", lambda *a, **k: (str(target), "CSV files (*.csv)"))
    window.export_history()

    lines = target.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 31  # header plus 30 rows


def test_the_check_log_on_disk_still_gets_every_row(window, log_dir):
    """Trimming is a display and memory concern. The CSV log is the durable
    record and must not lose rows."""
    for index in range(main.MAX_HISTORY_ROWS + 5):
        window.handle_link_result(make_result(checked_at=f"row-{index}"))

    written = (log_dir / "checks.csv").read_text(encoding="utf-8").strip().splitlines()
    assert len(written) == main.MAX_HISTORY_ROWS + 5 + 1  # header plus every result
