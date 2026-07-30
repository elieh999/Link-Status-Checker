from __future__ import annotations

import io
from pathlib import Path

from PIL import Image
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QSize
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "assets" / "app_icon.svg"
OUTPUT = ROOT / "assets" / "app_icon.ico"


def render(size: int) -> Image.Image:
    renderer = QSvgRenderer(str(SOURCE))
    image = QImage(QSize(size, size), QImage.Format.Format_ARGB32)
    image.fill(0)
    painter = QPainter(image)
    renderer.render(painter)
    painter.end()
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    return Image.open(io.BytesIO(bytes(data))).convert("RGBA")


def main() -> int:
    app = QGuiApplication.instance() or QGuiApplication([])
    sizes = [16, 24, 32, 48, 64, 128, 256]
    images = [render(size) for size in sizes]
    images[-1].save(OUTPUT, format="ICO", append_images=images[:-1], sizes=[(size, size) for size in sizes])
    app.quit()
    print(OUTPUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
