# ca_app/pages/hsm_wait_page.py

import os
import sys
import time
import psutil
from PySide6.QtCore import QThread, Signal, Qt
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PySide6.QtGui import QMovie

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import auth_handler

class HsmLoginWorker(QThread):
    """Worker thread to handle HSM detection and login attempts."""
    login_attempt_finished = Signal(bool, str, object, str)  # success, message, admin_data, hsm_path

    def __init__(self, email, password):
        super().__init__()
        self.email = email
        self.password = password
        self._is_running = True

    def run(self):
        """
        Continuously scan all removable drives and attempt to log in.
        Iterates through all drives before failing, and preserves precise error messages.
        """
        while self._is_running:
            last_hsm_related_error = ""
            try:
                current_drives = {p.mountpoint for p in psutil.disk_partitions() if 'removable' in p.opts}
                if not current_drives:
                    time.sleep(1)
                    continue

                for drive_path in current_drives:
                    if not self._is_running:
                        return
                    success, message, admin_data = auth_handler.admin_login(self.email, drive_path, self.password)
                    if success:
                        if self._is_running:
                            self.login_attempt_finished.emit(True, message, admin_data, drive_path)
                        return
                    if "Incorrect password" in message:
                        if self._is_running:
                            self.login_attempt_finished.emit(False, message, None, "")
                        return
                    if "HSM ID mismatch" in message or "missing" in message:
                        last_hsm_related_error = message

                if last_hsm_related_error and self._is_running:
                    self.login_attempt_finished.emit(False, last_hsm_related_error, None, "")
                    return

                time.sleep(1)
            except Exception as e:
                if self._is_running:
                    self.login_attempt_finished.emit(False, f"An error occurred during HSM scan: {e}", None, "")
                return

    def stop(self):
        self._is_running = False


class HsmWaitPage(QWidget):
    """Page that waits for an admin HSM to be connected and forwards exact errors to the caller."""
    login_success = Signal(dict, str)  # admin_data, hsm_path
    login_failure = Signal(str)
    navigate_to_login = Signal()

    def __init__(self):
        super().__init__()
        self.current_email = ""
        self.current_password = ""
        self.worker = None
        self._last_error_message = ""

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        self.icon_label = QLabel("🔑")
        self.icon_label.setObjectName("wait_icon")
        self.icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.status_label = QLabel("Waiting for Admin HSM")
        self.status_label.setObjectName("h2")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.instruction_label = QLabel("Please insert your secure USB drive to log in.")
        self.instruction_label.setObjectName("secondary_text")
        self.instruction_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("secondary")
        self.cancel_button.setFixedWidth(120)

        layout.addWidget(self.icon_label)
        layout.addWidget(self.status_label)
        layout.addWidget(self.instruction_label)
        layout.addSpacing(20)
        layout.addWidget(self.cancel_button, alignment=Qt.AlignmentFlag.AlignCenter)

        self.cancel_button.clicked.connect(self._on_cancel)

    def start_login_process(self, email, password):
        self.current_email = email
        self.current_password = password
        self._last_error_message = ""
        self.status_label.setText("Scanning removable drives...")
        self.instruction_label.setText(f"Please insert the secure USB drive for\n{email}")

        self.worker = HsmLoginWorker(email, password)
        self.worker.login_attempt_finished.connect(self._on_login_finished)
        self.worker.start()

    def _on_login_finished(self, success, message, admin_data, hsm_path):
        self.stop_worker()
        if success:
            self.status_label.setText("HSM found. Authenticating...")
            self.login_success.emit(admin_data, hsm_path)
        else:
            self._last_error_message = message or "Login failed."
            # Keep UI informative here; the main window will also display the same exact text.
            self.status_label.setText("Login failed.")
            self.instruction_label.setText(self._last_error_message)
            self.login_failure.emit(self._last_error_message)

    def _on_cancel(self):
        self.stop_worker()
        self.navigate_to_login.emit()

    def stop_worker(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
        self.worker = None

    def last_error_message(self) -> str:
        """Allows the main window to query the last exact error, if needed."""
        return self._last_error_message
