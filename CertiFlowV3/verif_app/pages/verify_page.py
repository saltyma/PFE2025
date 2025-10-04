# pages/verify_page.py

from __future__ import annotations
import os
import sys
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QFileDialog, QFrame)
from PySide6.QtCore import Qt, Signal, QThread, QObject

# --- Path Setup ---
APP_PATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_PATH)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from utils.verification import verify_and_log_signature
from pages.verification_result_dialog import VerificationResultDialog

class VerificationWorker(QObject):
    finished = Signal(dict)
    def __init__(self, signed_file_path, signer_email):
        super().__init__()
        self.signed_file_path = signed_file_path
        self.signer_email = signer_email

    def run(self):
        result_dict = verify_and_log_signature(self.signed_file_path, self.signer_email)
        self.finished.emit(result_dict)

class VerifyPage(QWidget):
    def __init__(self):
        super().__init__()
        self.signed_file_path = None
        self.worker_thread = None
        self.worker = None
        self._build_ui()

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.setContentsMargins(50, 50, 50, 50)

        card = QFrame()
        card.setObjectName("ContentCard")
        card.setMaximumWidth(600)
        layout = QVBoxLayout(card)
        layout.setSpacing(15)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QLabel("Verify Document Signature")
        title.setObjectName("h1")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)

        subtitle = QLabel("Select a signed PDF and provide the signer's institutional email to verify the document's authenticity and integrity.")
        subtitle.setObjectName("secondary_text")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setWordWrap(True)

        self.file_button = QPushButton("Select Signed PDF File...")
        self.file_button.setObjectName("secondary")
        self.file_button.clicked.connect(self._select_file)

        self.file_label = QLabel("No file selected.")
        self.file_label.setObjectName("secondary_text")
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter signer's institutional email (e.g., name@uit.ac.ma)")

        self.verify_button = QPushButton("Verify Signature")
        self.verify_button.setObjectName("primary")
        self.verify_button.clicked.connect(self._run_verification)
        self.email_input.returnPressed.connect(self._run_verification)

        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(25)
        layout.addWidget(self.file_button)
        layout.addWidget(self.file_label)
        layout.addSpacing(10)
        layout.addWidget(self.email_input)
        layout.addSpacing(25)
        layout.addWidget(self.verify_button)

        main_layout.addWidget(card)

    def _select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Signed PDF", "", "PDF Files (*.pdf)")
        if file_path:
            self.signed_file_path = file_path
            self.file_label.setText(f"Selected: <b>{os.path.basename(file_path)}</b>")

    def _run_verification(self):
        signer_email = self.email_input.text().strip()
        if not self.signed_file_path or not signer_email:
            dialog = VerificationResultDialog(self)
            dialog.show_result({"result": "invalid", "reason": "Please select a file and enter an email address before verifying."})
            dialog.exec()
            return

        self.verify_button.setEnabled(False)
        self.verify_button.setText("Verifying...")

        self.worker_thread = QThread()
        self.worker = VerificationWorker(self.signed_file_path, signer_email)
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_verification_finished)
        self.worker_thread.start()

    def _on_verification_finished(self, result_dict):
        dialog = VerificationResultDialog(self, result_dict)
        dialog.exec()

        self.verify_button.setEnabled(True)
        self.verify_button.setText("Verify Signature")
        self.worker_thread.quit()
        self.worker_thread.wait()
