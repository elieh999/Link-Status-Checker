from __future__ import annotations

import pytest

import main


@pytest.fixture
def quiet_dialogs(monkeypatch):
    """Capture the message boxes instead of blocking the suite on a modal."""
    shown = []
    monkeypatch.setattr(main.QMessageBox, "information", lambda *a, **k: shown.append(("info", a[1:3])))
    monkeypatch.setattr(main.QMessageBox, "warning", lambda *a, **k: shown.append(("warning", a[1:3])))
    monkeypatch.setattr(main.QMessageBox, "critical", lambda *a, **k: shown.append(("critical", a[1:3])))
    return shown


def choose(monkeypatch, path):
    monkeypatch.setattr(main.QFileDialog, "getOpenFileName", lambda *a, **k: (str(path), "CSV files (*.csv)"))


def test_loads_urls_and_skips_the_header(window, tmp_path, monkeypatch, quiet_dialogs):
    csv_file = tmp_path / "links.csv"
    csv_file.write_text("url\nexample.com\nhttp://example.org\n", encoding="utf-8")
    choose(monkeypatch, csv_file)

    window.load_links_from_csv()

    assert set(window.targets) == {"https://example.com/", "https://example.org/"}


def test_a_missing_file_reports_an_error_instead_of_raising(window, tmp_path, monkeypatch, quiet_dialogs):
    """Regression: load_links_from_csv opened the file with no try/except, so
    anything unreadable raised straight out of a Qt slot."""
    choose(monkeypatch, tmp_path / "definitely-not-here.csv")

    window.load_links_from_csv()  # must not raise

    assert any(kind in {"warning", "critical"} for kind, _ in quiet_dialogs)
    assert window.targets == {}


def test_an_unreadable_file_reports_an_error_instead_of_raising(window, tmp_path, monkeypatch, quiet_dialogs):
    csv_file = tmp_path / "locked.csv"
    csv_file.write_text("example.com\n", encoding="utf-8")
    choose(monkeypatch, csv_file)

    def refuse(*args, **kwargs):
        raise PermissionError("file is open in another program")

    monkeypatch.setattr(main.Path, "open", refuse)

    window.load_links_from_csv()  # must not raise

    assert any(kind in {"warning", "critical"} for kind, _ in quiet_dialogs)


def test_binary_junk_reports_an_error_instead_of_raising(window, tmp_path, monkeypatch, quiet_dialogs):
    csv_file = tmp_path / "junk.csv"
    csv_file.write_bytes(b"\x80\x81\x82\xfe\xff\x00binary\x00nonsense")
    choose(monkeypatch, csv_file)

    window.load_links_from_csv()  # must not raise

    assert any(kind in {"warning", "critical"} for kind, _ in quiet_dialogs)


def test_a_csv_with_no_usable_rows_says_so(window, tmp_path, monkeypatch, quiet_dialogs):
    csv_file = tmp_path / "empty.csv"
    csv_file.write_text("url\n\n\n", encoding="utf-8")
    choose(monkeypatch, csv_file)

    window.load_links_from_csv()

    assert window.targets == {}
    assert quiet_dialogs, "the user should be told nothing was loaded"


def test_cancelling_the_dialog_changes_nothing(window, monkeypatch, quiet_dialogs):
    monkeypatch.setattr(main.QFileDialog, "getOpenFileName", lambda *a, **k: ("", ""))
    window.load_links_from_csv()
    assert window.targets == {}
    assert quiet_dialogs == []


def test_a_utf8_bom_and_extra_columns_are_tolerated(window, tmp_path, monkeypatch, quiet_dialogs):
    csv_file = tmp_path / "bom.csv"
    csv_file.write_text("﻿url,owner\nexample.com,ops\nexample.net,web\n", encoding="utf-8")
    choose(monkeypatch, csv_file)

    window.load_links_from_csv()

    assert set(window.targets) == {"https://example.com/", "https://example.net/"}
