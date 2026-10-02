from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import QPointF, QRectF, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QKeyEvent, QMouseEvent, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from ..domain.statuses import STATUS_LABELS, HealthStatus


class ClickableUrlLabel(QLabel):
    open_failed = Signal(str)

    def __init__(self, url: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._url = ""
        self.setObjectName("CardUrl")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAccessibleName("Open monitored website")
        self.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.set_url(url)

    def set_url(self, url: str) -> None:
        self._url = url.strip()
        self.setText(self._url)
        self.setToolTip(f"Open this website in your default browser\n{self._url}")
        self.setAccessibleDescription(self._url)

    def validated_url(self) -> QUrl | None:
        url = QUrl(self._url)
        if not url.isValid() or url.scheme().lower() not in {"http", "https"} or not url.host():
            return None
        return url

    def open_url(self) -> bool:
        url = self.validated_url()
        if url is None:
            self.open_failed.emit("Only valid HTTP and HTTPS website links can be opened.")
            return False
        if not QDesktopServices.openUrl(url):
            self.open_failed.emit("Windows could not open this website in the default browser.")
            return False
        return True

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # type: ignore[override]
        if event.button() == Qt.MouseButton.LeftButton:
            self.open_url()
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # type: ignore[override]
        if event.key() in {Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space}:
            self.open_url()
            event.accept()
            return
        super().keyPressEvent(event)


class StatusStrip(QWidget):
    changed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("StatusStrip")
        self._buttons: dict[HealthStatus, QToolButton] = {}
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(5)
        for status in HealthStatus:
            icon, label, explanation = STATUS_LABELS[status]
            button = QToolButton()
            button.setObjectName("StatusChoice")
            button.setText(f"{icon}  {label}")
            button.setToolTip(explanation)
            button.setAccessibleName(f"Website status: {label}")
            button.setProperty("healthStatus", status.value)
            button.setProperty("active", False)
            button.setAutoRaise(False)
            button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
            button.clicked.connect(lambda _checked=False, value=status.value: self.changed.emit(value))
            self._buttons[status] = button
            layout.addWidget(button)
        self.set_status(HealthStatus.UNKNOWN)

    def set_status(self, status: HealthStatus | str) -> None:
        try:
            current = HealthStatus(status)
        except ValueError:
            current = HealthStatus.UNKNOWN
        for value, button in self._buttons.items():
            button.setProperty("active", value == current)
            button.style().unpolish(button)
            button.style().polish(button)


class SparklineWidget(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._values: list[int] = []
        self.setObjectName("Sparkline")
        self.setFixedHeight(46)
        self.setMinimumWidth(130)
        self.setToolTip("Recent response times")

    def set_values(self, values: Iterable[int]) -> None:
        self._values = [max(0, int(value)) for value in values][-60:]
        if self._values:
            self.setToolTip(
                f"Recent latency: {self._values[-1]} ms\n"
                f"Minimum: {min(self._values)} ms  Maximum: {max(self._values)} ms"
            )
        else:
            self.setToolTip("No latency samples are available yet.")
        self.update()

    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        area = QRectF(self.rect()).adjusted(5, 6, -5, -6)
        painter.setPen(QPen(QColor("#d8e4f2"), 1))
        painter.drawLine(area.bottomLeft(), area.bottomRight())
        if not self._values:
            painter.setPen(QColor("#73839a"))
            painter.drawText(area, Qt.AlignmentFlag.AlignCenter, "Waiting for data")
            return

        high = max(max(self._values), 1)
        low = min(self._values)
        span = max(high - low, 1)
        step = area.width() / max(len(self._values) - 1, 1)
        path = QPainterPath()
        points: list[QPointF] = []
        for index, value in enumerate(self._values):
            x = area.left() + index * step
            y = area.bottom() - ((value - low) / span) * area.height()
            points.append(QPointF(x, y))
        path.moveTo(points[0])
        for point in points[1:]:
            path.lineTo(point)
        painter.setPen(QPen(QColor("#1677d2"), 2.2))
        painter.drawPath(path)
        painter.setBrush(QColor("#1677d2"))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(points[-1], 3.5, 3.5)


class MetricCard(QFrame):
    def __init__(self, title: str, accent: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("MetricCard")
        self.setProperty("accent", accent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 13, 15, 13)
        layout.setSpacing(3)
        self.title_label = QLabel(title)
        self.title_label.setObjectName("MetricTitle")
        self.value_label = QLabel("0")
        self.value_label.setObjectName("MetricValue")
        self.note_label = QLabel("No checks yet")
        self.note_label.setObjectName("MetricNote")
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.note_label)

    def set_value(self, value: str, note: str = "") -> None:
        self.value_label.setText(value)
        self.note_label.setText(note)


def show_link_error(parent: QWidget, message: str) -> None:
    QMessageBox.warning(parent, "Could Not Open Website", message)
