# user_app/pages/sign_document_page.py
# CertiFlow V3 — Sign Document Page (COM HSM + PIN, no mount points)

import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QFileDialog
)
from PySide6.QtCore import Qt, Signal, QThread, QObject

from utils import document_handler, logging_handler
from utils.logging_handler import LogAction


class SigningWorker(QObject):
    finished = Signal(bool, str)

    def __init__(self, file_path: str, pin: str, user_email: str):
        super().__init__()
        self.file_path = file_path
        self.pin = pin
        self.user_email = user_email

    def run(self):
        try:
            # V3: mount-point is obsolete; pass empty string. hsm_password is treated as HSM PIN.
            success, message = document_handler.sign_document(
                file_path=self.file_path,
                hsm_mount_point="",
                hsm_password=self.pin,
                user_email=self.user_email
            )

            if success:
                logging_handler.log(
                    LogAction.SIGN_DOCUMENT_SUCCESS,
                    {"file": os.path.basename(self.file_path)}
                )
            else:
                logging_handler.log(
                    LogAction.SIGN_DOCUMENT_FAILURE,
                    {"file": os.path.basename(self.file_path), "reason": message}
                )

            self.finished.emit(success, message)

        except Exception as e:
            err = f"An unexpected error occurred while signing: {e}"
            logging_handler.log(LogAction.APPLICATION_ERROR, {"context": "SigningWorker", "error": str(e)})
            self.finished.emit(False, err)


class SignDocumentPage(QWidget):
    def __init__(self):
        super().__init__()
        self.selected_file_path = None
        self.current_user_email = None
        self.current_user_hsm_id = None  # kept for consistency with other pages, not used directly here
        self.worker_thread = None
        self.worker = None

        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(50, 50, 50, 50)

        form_container = QWidget()
        form_container.setMaximumWidth(500)
        form_layout = QVBoxLayout(form_container)
        form_layout.setSpacing(15)

        title = QLabel("Sign a Document")
        title.setObjectName("h2")
        title.setAlignment(Qt.AlignCenter)

        subtitle = QLabel("Select a document and enter your HSM PIN to create a secure digital signature.")
        subtitle.setObjectName("secondary_text")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)

        self.select_file_button = QPushButton("Select File...")
        self.select_file_button.setObjectName("secondary")
        self.select_file_button.clicked.connect(self.open_file_dialog)

        self.selected_file_label = QLabel("No file selected.")
        self.selected_file_label.setObjectName("secondary_text")
        self.selected_file_label.setAlignment(Qt.AlignCenter)
        self.selected_file_label.setWordWrap(True)

        # V3: label and placeholder now refer to HSM PIN
        self.pin_input = QLineEdit()
        self.pin_input.setPlaceholderText("Enter your HSM PIN")
        self.pin_input.setEchoMode(QLineEdit.Password)
        self.pin_input.returnPressed.connect(self.handle_sign_document)

        buttons_layout = QHBoxLayout()
        self.sign_button = QPushButton("Sign Document")
        self.sign_button.setObjectName("primary")
        self.sign_button.clicked.connect(self.handle_sign_document)

        self.clear_button = QPushButton("Clear")
        self.clear_button.setObjectName("secondary")
        self.clear_button.clicked.connect(self.clear_form)

        buttons_layout.addWidget(self.clear_button)
        buttons_layout.addWidget(self.sign_button)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setVisible(False)

        form_layout.addWidget(title)
        form_layout.addWidget(subtitle)
        form_layout.addSpacing(20)
        form_layout.addWidget(self.select_file_button)
        form_layout.addWidget(self.selected_file_label)
        form_layout.addSpacing(10)
        form_layout.addWidget(QLabel("HSM PIN"))
        form_layout.addWidget(self.pin_input)
        form_layout.addSpacing(20)
        form_layout.addLayout(buttons_layout)
        form_layout.addWidget(self.status_label)

        main_layout.addWidget(form_container)

    def set_current_user(self, user_data: dict):
        """Receives user data from main window upon login."""
        self.current_user_email = user_data.get('email')
        self.current_user_hsm_id = user_data.get('hsm_id')  # not used here, but kept for consistency

    def open_file_dialog(self):
        """Opens a dialog for the user to select a file to sign."""
        self.clear_status()
        file_filter = "PDF Documents (*.pdf);;All Files (*)"
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select a Document to Sign",
            os.path.expanduser("~"),
            file_filter
        )
        if file_path:
            self.selected_file_path = file_path
            self.selected_file_label.setText(f"Selected: <b>{os.path.basename(file_path)}</b>")

    def handle_sign_document(self):
        if not self.selected_file_path:
            self.show_status("Please select a file to sign.", is_error=True)
            return

        pin = self.pin_input.text().strip()
        if not pin:
            self.show_status("Please enter your HSM PIN.", is_error=True)
            return

        self.sign_button.setEnabled(False)
        self.sign_button.setText("Signing...")
        self.clear_button.setEnabled(False)
        self.clear_status()

        self.worker_thread = QThread()
        self.worker = SigningWorker(self.selected_file_path, pin, self.current_user_email)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_signing_finished)

        self.worker_thread.start()

    def on_signing_finished(self, success, message):
        self.show_status(message, is_error=not success)
        if success:
            self.clear_form(clear_status_label=False)

        self.sign_button.setEnabled(True)
        self.sign_button.setText("Sign Document")
        self.clear_button.setEnabled(True)

        self.worker_thread.quit()
        self.worker_thread.wait()
        self.worker_thread = None
        self.worker = None

    def show_status(self, message, is_error=False):
        if is_error:
            self.status_label.setText(f"<font color='#dc3545'>{message}</font>")
        else:
            self.status_label.setText(f"<font color='#28a745'>{message}</font>")
        self.status_label.setVisible(True)

    def clear_status(self):
        self.status_label.setVisible(False)

    def clear_form(self, clear_status_label=True):
        self.selected_file_path = None
        self.selected_file_label.setText("No file selected.")
        self.pin_input.clear()
        if clear_status_label:
            self.clear_status()
