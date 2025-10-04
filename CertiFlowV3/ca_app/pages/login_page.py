# ca_app/pages/login_page.py

import sys
import os
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QLineEdit,
                               QPushButton, QFrame)
from PySide6.QtCore import Qt, Signal

class LoginPage(QWidget):
    """CA Administrator Login."""
    navigate_to_hsm_wait = Signal(str, str)  # email, password

    def __init__(self):
        super().__init__()

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        frame = QFrame()
        frame.setObjectName("ContentFrame")
        frame.setMaximumWidth(400)
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(40, 40, 40, 40)
        frame_layout.setSpacing(15)

        logo_text = "Certi<span style='color:#9B2335;'>Flow.</span>"
        logo_label = QLabel(logo_text)
        logo_label.setObjectName("Logo")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title_label = QLabel("CA Administrator Login")
        title_label.setObjectName("h2")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Administrator Email")

        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("HSM Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_button = QPushButton("Authenticate")
        self.login_button.setObjectName("primary")

        self.error_label = QLabel("")
        self.error_label.setObjectName("error_text")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.error_label.setVisible(False)

        frame_layout.addWidget(logo_label)
        frame_layout.addSpacing(10)
        frame_layout.addWidget(title_label)
        frame_layout.addSpacing(25)
        frame_layout.addWidget(self.email_input)
        frame_layout.addWidget(self.password_input)
        frame_layout.addSpacing(15)
        frame_layout.addWidget(self.login_button)
        frame_layout.addWidget(self.error_label)

        main_layout.addWidget(frame)

        # Connections
        self.login_button.clicked.connect(self._handle_login_click)
        self.password_input.returnPressed.connect(self._handle_login_click)

    def _handle_login_click(self):
        email = self.email_input.text().strip()
        password = self.password_input.text()
        if not email or not password:
            self.show_error("Email and password are required.")
            return
        self.show_error("")  # clear any old errors
        self.navigate_to_hsm_wait.emit(email, password)

    # Exposed method for the main window to show the exact failure message from HSM wait page
    def show_error(self, message: str):
        self.error_label.setText(message or "")
        self.error_label.setVisible(bool(message))

    def clear_form(self):
        self.email_input.clear()
        self.password_input.clear()
        self.error_label.setVisible(False)
