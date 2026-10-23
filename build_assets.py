"""生成应用图标与 PyInstaller 版本信息。

图标用 PyQt6 现画一张（不依赖任何设计资源），再手工封装成 .ico；
Windows 资源版本信息同样在此生成，避免仓库里出现二进制资源缺失。

用法: .venv\\Scripts\\python.exe build_exe.py --assets-only
"""
import struct
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
ASSETS = PROJECT_ROOT / "assets"

VERSION = "2.0.0"
VERSION_TUPLE = (2, 0, 0, 0)


def _png_bytes(size: int = 256) -> bytes:
    """用 Qt 画一张图标并导出 PNG 字节。"""
    from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
    from PyQt6.QtGui import QColor, QImage, QLinearGradient, QPainter, QPen
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)

    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    # 圆角渐变底
    grad = QLinearGradient(0, 0, size, size)
    grad.setColorAt(0.0, QColor("#3b82f6"))
    grad.setColorAt(1.0, QColor("#1e3a8a"))
    p.setBrush(grad)
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(4, 4, size - 8, size - 8), size * 0.22, size * 0.22)

    # 扫帚/刷子造型：一道斜杆 + 刷头
    p.setPen(QPen(QColor("#ffffff"), size * 0.075, Qt.PenStyle.SolidLine,
                  Qt.PenCapStyle.RoundCap))
    p.drawLine(int(size * 0.30), int(size * 0.72), int(size * 0.66), int(size * 0.36))

    p.setBrush(QColor("#ffffff"))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(size * 0.18, size * 0.66, size * 0.30, size * 0.13),
                      size * 0.05, size * 0.05)

    # 右上角对勾
    pen = QPen(QColor("#a7f3d0"), size * 0.085, Qt.PenStyle.SolidLine,
               Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPolyline([
        QPointF(size * 0.60, size * 0.22),
        QPointF(size * 0.68, size * 0.30),
        QPointF(size * 0.82, size * 0.14),
    ])
    p.end()

    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    buf.close()
    return bytes(ba)


def _build_ico(png: bytes, size: int = 256) -> bytes:
    """把 PNG 封装成 ICO（Vista+ 支持 PNG 负载）。"""
    header = struct.pack("<HHH", 0, 1, 1)
    entry = struct.pack("<BBBBHHII",
                         0 if size >= 256 else size,
                         0 if size >= 256 else size,
                         0, 0, 1, 32, len(png), 6 + 16)
    return header + entry + png


def make_icon() -> Path:
    ASSETS.mkdir(parents=True, exist_ok=True)
    path = ASSETS / "icon.ico"
    path.write_bytes(_build_ico(_png_bytes(256)))
    print(f"图标已生成: {path}")
    return path


VERSION_INFO = f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={VERSION_TUPLE},
    prodvers={VERSION_TUPLE},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          '080404b0',
          [StringStruct('CompanyName', 'WinCleaner'),
           StringStruct('FileDescription', 'WinCleaner - Windows 系统清理助手'),
           StringStruct('FileVersion', '{VERSION}'),
           StringStruct('InternalName', 'WinCleaner'),
           StringStruct('LegalCopyright', ''),
           StringStruct('OriginalFilename', 'WinCleaner.exe'),
           StringStruct('ProductName', 'WinCleaner'),
           StringStruct('ProductVersion', '{VERSION}')])
      ]),
    VarFileInfo([VarStruct('Translation', [2052, 1200])])
  ]
)
"""


def make_version_info() -> Path:
    path = PROJECT_ROOT / "version_info.txt"
    path.write_text(VERSION_INFO, encoding="utf-8")
    print(f"版本信息已生成: {path}")
    return path


if __name__ == "__main__":
    make_icon()
    make_version_info()
