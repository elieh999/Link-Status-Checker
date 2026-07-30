from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices

from src.link_status_checker.domain.statuses import HealthStatus
from src.link_status_checker.ui.widgets import ClickableUrlLabel, SparklineWidget, StatusStrip


def test_clickable_url_accepts_only_http_and_https(qtbot, monkeypatch):
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: opened.append(url.toString()) or True)
    label = ClickableUrlLabel("https://example.com/path")
    qtbot.addWidget(label)
    assert label.open_url() is True
    assert opened == ["https://example.com/path"]

    for value in ("", "file:///C:/Windows", "javascript:alert(1)", "ftp://example.com"):
        label.set_url(value)
        assert label.open_url() is False
    assert opened == ["https://example.com/path"]


def test_clickable_url_supports_keyboard_activation(qtbot, monkeypatch):
    opened = []
    monkeypatch.setattr(QDesktopServices, "openUrl", lambda url: opened.append(url.toString()) or True)
    label = ClickableUrlLabel("http://localhost:8080/health")
    qtbot.addWidget(label)
    label.show()
    label.setFocus()
    qtbot.keyClick(label, Qt.Key.Key_Return)
    assert opened == ["http://localhost:8080/health"]


def test_only_current_status_is_active(qtbot):
    strip = StatusStrip()
    qtbot.addWidget(strip)
    strip.set_status(HealthStatus.DEGRADED)
    buttons = strip.findChildren(type(next(iter(strip._buttons.values()))))
    assert sum(bool(button.property("active")) for button in buttons) == 1
    assert strip._buttons[HealthStatus.DEGRADED].property("active") is True


def test_sparkline_handles_empty_and_large_samples(qtbot):
    widget = SparklineWidget()
    qtbot.addWidget(widget)
    widget.set_values([])
    widget.set_values(range(500))
    assert len(widget._values) == 60
