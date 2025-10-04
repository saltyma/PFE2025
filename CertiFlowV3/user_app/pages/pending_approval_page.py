# user_app/pages/pending_approval_page.py

import time
import os
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PySide6.QtGui import QMovie
from PySide6.QtCore import Qt, Signal, QThread, QObject

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import ca_sync_handler  # V3: no auto-login from here

class ApprovalStatusWorker(QObject):
    """
    Worker thread to periodically check the user's approval status with the CA.
    """
    # Signals to emit based on approval status
    request_approved = Signal(object)  # Emit minimal data on approval (no auto-login in V3)
    request_rejected = Signal(str)     # Emit email on rejection
    check_failed = Signal(str)         # Emit error message if check itself fails
    finished = Signal()                # Signal to indicate the worker has completed its task

    def __init__(self, email: str):
        super().__init__()
        self.email = email
        self._is_running = True
        self.check_interval_seconds = 5  # Check every 5 seconds

    def run(self):
        try:
            while self._is_running:
                # Query CA for current status
                status_payload, error = ca_sync_handler.get_user_status_from_ca(self.email)

                if error:
                    self.check_failed.emit(f"Failed to check status: {error}. Please try again later.")
                    self._is_running = False
                    break

                status = (status_payload or {}).get("status")

                if status == "verified":
                    # V3 change: do NOT attempt auto-login here (login now requires HSM PIN).
                    # Instead, notify the page to route the user back to the login screen.
                    self.request_approved.emit({"email": self.email})
                    self._is_running = False
                    break
                elif status == "rejected":
                    self.request_rejected.emit(self.email)
                    self._is_running = False
                    break
                # else: still pending or unknown; keep waiting

                time.sleep(self.check_interval_seconds)
        finally:
            self.finished.emit()

    def stop(self):
        self._is_running = False


class PendingApprovalPage(QWidget):
    # Signals for navigation
    request_approved = Signal(object)  # kept for backward compatibility (not used to auto-login anymore)
    request_rejected = Signal(str)
    navigate_to_login = Signal()

    def __init__(self):
        super().__init__()
        self.current_email = None
        self.worker_thread = None
        self.worker = None

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(50, 50, 50, 50)
        layout.setSpacing(20)

        # Logo
        title_text = "Certi<span style='color:#5294e2;'>Flow.</span>"
        logo = QLabel(title_text)
        logo.setObjectName("h1")
        logo.setAlignment(Qt.AlignCenter)

        # Loading Animation
        self.loading_label = QLabel()
        loading_gif_path = os.path.join(os.path.dirname(__file__), "..", "resources", "loading1.gif")
        if os.path.exists(loading_gif_path):
            self.movie = QMovie(loading_gif_path)
            self.loading_label.setMovie(self.movie)
        else:
            self.movie = None
            self.loading_label.setText("(loading animation)")

        # Main Message
        self.message_title = QLabel("Awaiting CA approval")
        self.message_title.setObjectName("h2")
        self.message_title.setAlignment(Qt.AlignCenter)
        self.message_title.setWordWrap(True)

        # Subtitle/Instructions (per V3 requirements)
        self.message_body = QLabel("Please verify your email via the link sent to your inbox.")
        self.message_body.setObjectName("secondary_text")
        self.message_body.setAlignment(Qt.AlignCenter)
        self.message_body.setWordWrap(True)

        # Back to Login Button
        self.back_button = QPushButton("Back to Login")
        self.back_button.setObjectName("secondary")
        self.back_button.clicked.connect(self.cancel_check_and_navigate_to_login)
        self.back_button.setFixedWidth(200)

        layout.addWidget(logo)
        layout.addSpacing(30)
        layout.addWidget(self.loading_label, alignment=Qt.AlignCenter)
        layout.addWidget(self.message_title)
        layout.addWidget(self.message_body)
        layout.addSpacing(30)
        layout.addWidget(self.back_button, alignment=Qt.AlignCenter)

    def start_status_check(self, email: str):
        """
        Starts the worker thread to monitor the approval status.
        Call this when navigating to this page.
        """
        self.current_email = email
        self.stop_worker()

        if self.movie:
            self.movie.start()

        self.worker_thread = QThread()
        self.worker = ApprovalStatusWorker(self.current_email)
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.request_approved.connect(self.on_request_approved)
        self.worker.request_rejected.connect(self.on_request_rejected)
        self.worker.check_failed.connect(self.on_status_check_failed)
        self.worker.finished.connect(self.worker_thread.quit)
        self.worker.finished.connect(self.worker_thread.wait)
        self.worker.finished.connect(self.clean_up_worker)

        self.worker_thread.start()

    def stop_worker(self):
        """Stops the worker thread and cleans up."""
        if self.worker:
            self.worker.stop()
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()
        self.clean_up_worker()

    def clean_up_worker(self):
        """Resets worker and thread references."""
        self.worker = None
        self.worker_thread = None
        if self.movie:
            self.movie.stop()

    def on_request_approved(self, _payload: object):
        """
        V3: once approved, send the user back to Login so they can unlock their HSM with PIN.
        """
        self.stop_worker()
        self.navigate_to_login.emit()

    def on_request_rejected(self, email: str):
        """Handles the signal when the request is rejected."""
        self.stop_worker()
        self.request_rejected.emit(email)

    def on_status_check_failed(self, error_message: str):
        """Handles errors during the status check."""
        self.message_title.setText("Error Checking Status")
        self.message_body.setText(
            f"There was an error communicating with the CA: {error_message}\n"
            "Please try again by going back to login, or contact support."
        )
        self.loading_label.setVisible(False)
        self.stop_worker()

    def cancel_check_and_navigate_to_login(self):
        """Stops the worker and navigates back to the login page."""
        self.stop_worker()
        self.navigate_to_login.emit()
