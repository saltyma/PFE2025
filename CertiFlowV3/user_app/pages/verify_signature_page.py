# user_app/pages/verify_signature_page.py

import os
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                               QLineEdit, QPushButton, QFileDialog)
from PySide6.QtCore import Qt, Signal, QThread, QObject

from utils import verification_handler, logging_handler
from utils.logging_handler import LogAction
# --- 1. IMPORT THE NEW DIALOG ---
from .verification_result_dialog import VerificationResultDialog

class VerificationWorker(QObject):
    finished = Signal(bool, str)
    def __init__(self, signed_file_path, signer_email):
        super().__init__()
        self.signed_file_path = signed_file_path
        self.signer_email = signer_email
    def run(self):
        try:
            if self.signed_file_path.lower().endswith('.pdf'):
                success, message = verification_handler.verify_pdf_signature(
                    self.signed_file_path, self.signer_email
                )
            else:
                success = False
                message = "This verification workflow only supports signed PDF files."
            log_action = LogAction.VERIFY_SIGNATURE_SUCCESS if success else LogAction.VERIFY_SIGNATURE_FAILURE
            details = { "signed_file": os.path.basename(self.signed_file_path), "signer_email": self.signer_email, "result": message }
            logging_handler.log(log_action, details)
            self.finished.emit(success, message)
        except Exception as e:
            error_message = f"An unexpected error occurred: {e}"
            logging_handler.log(LogAction.APPLICATION_ERROR, {"context": "VerificationWorker", "error": str(e)})
            self.finished.emit(False, error_message)

class VerifySignaturePage(QWidget):
    def __init__(self):
        super().__init__()
        # ... (rest of __init__ is the same until the status label)
        self.signed_file_path = None
        self.worker_thread = None
        self.worker = None
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(50, 50, 50, 50)
        form_container = QWidget()
        form_container.setMaximumWidth(550)
        form_layout = QVBoxLayout(form_container)
        form_layout.setSpacing(15)
        title = QLabel("Verify a Signature")
        title.setObjectName("h2")
        title.setAlignment(Qt.AlignCenter)
        subtitle = QLabel("Select the signed PDF file and enter the signer's email to verify the signature's authenticity.")
        subtitle.setObjectName("secondary_text")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setWordWrap(True)
        self.signed_file_button = QPushButton("1. Select Signed PDF File...")
        self.signed_file_button.setObjectName("secondary")
        self.signed_file_button.clicked.connect(self.select_signed_file)
        self.signed_file_label = QLabel("No file selected.")
        self.signed_file_label.setObjectName("secondary_text")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("2. Enter signer's institutional email")
        buttons_layout = QHBoxLayout()
        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.setObjectName("primary")
        self.verify_button.clicked.connect(self.handle_verification)
        self.clear_button = QPushButton("Clear")
        self.clear_button.setObjectName("secondary")
        self.clear_button.clicked.connect(self.clear_form)
        buttons_layout.addWidget(self.clear_button)
        buttons_layout.addWidget(self.verify_button)
        
        # --- 2. REMOVE THE OLD STATUS LABEL ---
        # self.status_label = QLabel("") ... (delete all status_label lines)

        form_layout.addWidget(title)
        form_layout.addWidget(subtitle)
        form_layout.addSpacing(20)
        form_layout.addWidget(self.signed_file_button)
        form_layout.addWidget(self.signed_file_label)
        form_layout.addSpacing(10)
        form_layout.addWidget(self.email_input)
        form_layout.addSpacing(20)
        form_layout.addLayout(buttons_layout)
        # ... (no status label here)
        main_layout.addWidget(form_container)

    def select_signed_file(self):
        file_filter = "Signed PDF (*-signed.pdf)"
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Signed PDF File", filter=file_filter)
        if file_path:
            self.signed_file_path = file_path
            self.signed_file_label.setText(f"Selected: <b>{os.path.basename(file_path)}</b>")

    def handle_verification(self):
        signer_email = self.email_input.text().strip()
        if not self.signed_file_path or not signer_email:
            # We can use the dialog for errors too
            error_dialog = VerificationResultDialog(self)
            error_dialog.set_result(False, "Input Error\n\nPlease select the signed PDF and enter the signer's email.")
            error_dialog.exec()
            return

        self.verify_button.setEnabled(False)
        self.verify_button.setText("Verifying...")
        self.clear_button.setEnabled(False)

        self.worker_thread = QThread()
        self.worker = VerificationWorker(self.signed_file_path, signer_email)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.on_verification_finished)
        self.worker_thread.start()

    def on_verification_finished(self, success, message):
        # --- 3. SHOW THE NEW DIALOG ---
        result_dialog = VerificationResultDialog(self)
        result_dialog.set_result(success, message)
        result_dialog.exec()
        # --- END OF CHANGE ---

        self.verify_button.setEnabled(True)
        self.verify_button.setText("Verify Signature")
        self.clear_button.setEnabled(True)

        self.worker_thread.quit()
        self.worker_thread.wait()
        self.worker_thread = None
        self.worker = None

    def clear_form(self):
        self.signed_file_path = None
        self.signed_file_label.setText("No file selected.")
        self.email_input.clear()