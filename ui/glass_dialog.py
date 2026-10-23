"""液态玻璃风格自定义消息框。

在原有提示/询问之外补充了两类界面真正需要的能力：

* :meth:`GlassDialog.confirm_danger` —— 危险操作的"输入确认"，必须键入指定
  关键字才能继续（清空回收站这类不可逆动作）。
* :meth:`GlassDialog.detail` —— 可滚动的详情窗口，用来展示扫描清单、
  清理结果明细这类长文本。
"""
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
)


class GlassDialog(QDialog):
    """自定义毛玻璃消息对话框。"""

    def __init__(self, parent=None, title: str = "提示", message: str = "",
                 buttons=None, default_button=None, detail: str = "",
                 input_hint: str = "", danger: bool = False):
        super().__init__(parent)
        self.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Dialog)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setObjectName("glassDialog")
        self.setMinimumWidth(460)

        self.result_button = None
        self.buttons = {}
        self.input_text = ""
        self._danger = danger
        self._title = title

        shadow = QGraphicsDropShadowEffect(self)
        shadow.setBlurRadius(30)
        shadow.setColor(QColor(0, 0, 0, 80))
        shadow.setOffset(0, 8)
        self.setGraphicsEffect(shadow)

        self._build_ui(title, message, buttons, default_button, detail, input_hint)

    def _build_ui(self, title, message, buttons, default_button, detail, input_hint):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 18, 18, 18)

        frame = QFrame(objectName="glassDialog")
        frame.setObjectName("dangerDialog" if self._danger else "glassDialog")
        outer.addWidget(frame)

        inner = QVBoxLayout(frame)
        inner.setContentsMargins(24, 22, 24, 22)
        inner.setSpacing(14)

        title_label = QLabel(title, objectName="dialogTitle")
        inner.addWidget(title_label)

        if message:
            msg_label = QLabel(message, objectName="dialogMessage")
            msg_label.setWordWrap(True)
            msg_label.setTextFormat(Qt.TextFormat.PlainText)
            inner.addWidget(msg_label)

        if detail:
            area = QScrollArea(objectName="dialogScroll")
            area.setWidgetResizable(True)
            area.setMinimumHeight(180)
            area.setMaximumHeight(320)
            text = QTextEdit()
            text.setReadOnly(True)
            text.setPlainText(detail)
            text.setObjectName("dialogDetail")
            area.setWidget(text)
            inner.addWidget(area, 1)

        if input_hint:
            hint = QLabel(input_hint, objectName="dialogHint")
            hint.setWordWrap(True)
            inner.addWidget(hint)
            self.input_edit = QLineEdit()
            self.input_edit.setPlaceholderText("在此输入确认文字")
            self.input_edit.textChanged.connect(self._on_input_changed)
            inner.addWidget(self.input_edit)
        else:
            self.input_edit = None

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        if buttons is None:
            buttons = [("确定", "ok")]

        for label, key in buttons:
            btn = QPushButton(label)
            if key == default_button:
                btn.setObjectName("dangerButton" if self._danger else "primaryButton")
            elif key == "no":
                btn.setObjectName("secondaryButton")
            btn.clicked.connect(lambda checked, k=key: self._on_click(k))
            btn_layout.addWidget(btn)
            self.buttons[key] = btn

        inner.addLayout(btn_layout)

        if input_hint:
            self._on_input_changed()

    def _on_input_changed(self, *_):
        expected = getattr(self, "_expected", "")
        if self.input_edit is None:
            return
        ok = (self.input_edit.text().strip() == expected)
        btn = self.buttons.get("yes")
        if btn is not None:
            btn.setEnabled(ok)

    def _on_click(self, key: str):
        if self.input_edit is not None:
            self.input_text = self.input_edit.text().strip()
        self.result_button = key
        self.accept()

    def keyPressEvent(self, event):
        if event.key() == Qt.Key.Key_Escape:
            self.result_button = "no"
            self.reject()
            return
        super().keyPressEvent(event)

    # -- 静态工厂 ---------------------------------------------------------

    @staticmethod
    def question(parent, title: str, message: str) -> str:
        dialog = GlassDialog(
            parent, title, message,
            buttons=[("取消", "no"), ("确定", "yes")],
            default_button="yes",
        )
        dialog.exec()
        return dialog.result_button or "no"

    @staticmethod
    def information(parent, title: str, message: str, detail: str = ""):
        dialog = GlassDialog(
            parent, title, message,
            buttons=[("确定", "ok")], default_button="ok", detail=detail,
        )
        dialog.exec()

    @staticmethod
    def warning(parent, title: str, message: str, detail: str = ""):
        dialog = GlassDialog(
            parent, title, message,
            buttons=[("确定", "ok")], default_button="ok", detail=detail,
        )
        dialog.exec()

    @staticmethod
    def error(parent, title: str, message: str, detail: str = ""):
        dialog = GlassDialog(
            parent, title, message,
            buttons=[("关闭", "ok")], default_button="ok", detail=detail,
        )
        dialog.exec()

    @staticmethod
    def confirm_danger(parent, title: str, message: str, keyword: str,
                       detail: str = "") -> str:
        """危险操作确认：必须键入 ``keyword`` 才能继续。"""
        dialog = GlassDialog(
            parent, title, message,
            buttons=[("取消", "no"), ("确认执行", "yes")],
            default_button="yes", detail=detail, danger=True,
            input_hint=f"此操作不可撤销。请输入「{keyword}」以确认：",
        )
        dialog._expected = keyword
        dialog._on_input_changed()
        dialog.exec()
        if dialog.result_button == "yes" and dialog.input_text == keyword:
            return "yes"
        return "no"

    @staticmethod
    def detail(parent, title: str, message: str, text: str) -> str:
        """只读详情窗口。"""
        dialog = GlassDialog(
            parent, title, message,
            buttons=[("关闭", "ok")], default_button="ok", detail=text,
        )
        dialog.exec()
        return dialog.result_button or "no"
