# user_app/pages/renew_certificate_page.py
# CertiFlow V3 — Same-key renewal (COM HSM + PIN)
#
# UI text now refers to "HSM PIN" instead of password.
# Logic: kicks off RenewalWorker, which calls utils.renewal_handler.request_certificate_renewal(...)
# The handler handles: UNLOCK -> ensure key -> PUBKEY -> CSR build -> CA submit.

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton
from PySide6.QtCore import Qt, Signal, QThread, QObject

# --- App Imports ---
from utils import renewal_handler

class RenewalWorker(QObject):
    finished = Signal(bool, str)

    def __init__(self, user_data: dict, pin: str):
        super().__init__()
        self.user_data = user_data
        self.pin = pin

    def run(self):
        success, message = renewal_handler.request_certificate_renewal(
            self.user_data, self.pin  # handler treats this as the HSM PIN
        )
        self.finished.emit(success, message)


class RenewCertificatePage(QWidget):
    # Emits user's email on success; error message on failure
    renewal_request_submitted = Signal(str)
    renewal_failed = Signal(str)

    def __init__(self):
        super().__init__()
        self.current_user_data = {}
        self.worker_thread = None
        self.worker = None

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(50, 50, 50, 50)

        form_container = QWidget()
        form_container.setMaximumWidth(500)
        form_layout = QVBoxLayout(form_container)
        form_layout.setSpacing(15)

        title = QLabel("Renew Your Certificate")
        title.setObjectName("h2")
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel(
            "To request a new certificate with an updated validity period, "
            "please enter your HSM PIN to authorize the request."
        )
        subtitle.setObjectName("secondary_text")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)

        # Input labeled as HSM PIN (text change only; variable kept for compatibility)
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Enter your HSM PIN")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.handle_renewal_request)

        self.renew_button = QPushButton("Submit Renewal Request")
        self.renew_button.setObjectName("primary")
        self.renew_button.clicked.connect(self.handle_renewal_request)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setVisible(False)

        form_layout.addWidget(title)
        form_layout.addWidget(subtitle)
        form_layout.addSpacing(20)
        form_layout.addWidget(QLabel("HSM PIN"))
        form_layout.addWidget(self.password_input)
        form_layout.addSpacing(20)
        form_layout.addWidget(self.renew_button)
        form_layout.addWidget(self.status_label)

        main_layout.addWidget(form_container)

    def set_current_user(self, user_data: dict):
        """Receives user data from main window when this page is shown."""
        self.current_user_data = user_data
        # Reset the form when a new user context is set
        self.password_input.clear()
        self.status_label.setVisible(False)

    def handle_renewal_request(self):
        pin = self.password_input.text().strip()
        if not pin:
            self.show_status("Please enter your HSM PIN.", is_error=True)
            return

        self.renew_button.setEnabled(False)
        self.renew_button.setText("Submitting...")
        self.status_label.setVisible(False)

        self.worker_thread = QThread()
        self.worker = RenewalWorker(self.current_user_data, pin)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_renewal_finished)

        self.worker_thread.start()

    def on_renewal_finished(self, success, message):
        self.renew_button.setEnabled(True)
        self.renew_button.setText("Submit Renewal Request")

        if success:
            # Surface a success line and emit the standard signal with email
            self.show_status("Renewal request submitted. Please wait for CA approval.", is_error=False)
            self.renewal_request_submitted.emit(self.current_user_data.get('email', ''))
        else:
            self.show_status(message, is_error=True)
            self.renewal_failed.emit(message)

        self.worker_thread.quit()
        self.worker_thread.wait()
        self.worker_thread = None
        self.worker = None

    def show_status(self, message: str, is_error: bool = False):
        if is_error:
            self.status_label.setText(f"<font color='#dc3545'>{message}</font>")
        else:
            self.status_label.setText(f"<font color='#28a745'>{message}</font>")
        self.status_label.setVisible(True)
