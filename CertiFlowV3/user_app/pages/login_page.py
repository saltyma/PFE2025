# user_app/pages/login_page.py
# CertiFlow V3 — Signer login experience

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
)
from PySide6.QtCore import Qt, Signal

from utils import email_verifier, login_handler


class LoginPage(QWidget):
    navigate_to_hsm_wait = Signal(str)
    navigate_to_registration = Signal()
    navigate_to_pending = Signal(str)
    navigate_to_rejection = Signal(str)

    def __init__(self):
        super().__init__()

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.setContentsMargins(40, 40, 40, 40)

        form_container = QWidget()
        form_container.setMaximumWidth(420)
        form_layout = QVBoxLayout(form_container)
        form_layout.setContentsMargins(0, 0, 0, 0)
        form_layout.setSpacing(18)

        logo_label = QLabel("Certi<span style='color:#5294e2;'>Flow.</span>")
        logo_label.setObjectName("Logo")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_label.setTextFormat(Qt.TextFormat.RichText)

        tagline_label = QLabel("Secure Digital Signing, Simplified.")
        tagline_label.setObjectName("Tagline")
        tagline_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tagline_label.setWordWrap(True)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Institutional email (@uit.ac.ma)")
        self.email_input.setClearButtonEnabled(True)

        self.pin_input = QLineEdit()
        self.pin_input.setPlaceholderText("HSM PIN")
        self.pin_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.error_label = QLabel("")
        self.error_label.setObjectName("error_text")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setWordWrap(True)
        self.error_label.setVisible(False)

        self.login_button = QPushButton("Login")
        self.login_button.setObjectName("primary")
        self.login_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self.register_button = QPushButton("Register")
        self.register_button.setObjectName("secondary")
        self.register_button.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        button_row = QHBoxLayout()
        button_row.setSpacing(12)
        button_row.addWidget(self.login_button)
        button_row.addWidget(self.register_button)

        form_layout.addWidget(logo_label)
        form_layout.addWidget(tagline_label)

        form_layout.addSpacing(20)
        form_layout.addWidget(self.email_input)
        form_layout.addWidget(self.pin_input)
        form_layout.addSpacing(12)
        form_layout.addWidget(self.error_label)
        form_layout.addLayout(button_row)

        main_layout.addWidget(form_container)

        self.login_button.clicked.connect(self.handle_login)
        self.register_button.clicked.connect(self.handle_go_to_register)
        self.email_input.returnPressed.connect(self._focus_pin)
        self.pin_input.returnPressed.connect(self.handle_login)

    # ---------------- Handlers ----------------

    def _focus_pin(self):
        self.pin_input.setFocus()

    def handle_login(self):
        email = self.email_input.text().strip()
        pin = self.pin_input.text().strip()

        is_valid, msg = email_verifier.is_valid_institutional_email(email)
        if not is_valid:
            self.show_error(msg)
            return

        if not pin:
            self.show_error("Please enter your HSM PIN.")
            return

        status, message, user_data = login_handler.authenticate_user_with_pin(email, pin)
        if status == 'success':
            self.error_label.setVisible(False)
            self.navigate_to_hsm_wait.emit(email)
            return

        if status == 'pending':
            self.error_label.setVisible(False)
            self.navigate_to_pending.emit(email)
            return

        if status == 'rejected':
            self.error_label.setVisible(False)
            self.navigate_to_rejection.emit(email)
            return

        self.show_error(message)

    def handle_go_to_register(self):
        self.navigate_to_registration.emit()

    def show_error(self, message):
        self.error_label.setText(message or "")
        self.error_label.setVisible(bool(message))
