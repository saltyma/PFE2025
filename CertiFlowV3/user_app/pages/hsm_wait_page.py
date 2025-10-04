# user_app/pages/hsm_wait_page.py
# CertiFlow V3 — HSM Wait Page (COM-port scan + HSMID display)

import time
import os
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PySide6.QtGui import QMovie
from PySide6.QtCore import Qt, Signal, QThread, QObject

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils import hsm_handler

# Worker scans COM ports for an HSM and reports the first detected HSMID.
class HSMScanWorker(QObject):
    detected = Signal(str)          # emits hsm_id
    finished = Signal(str)          # emits reason string (for logging/UI)

    def __init__(self):
        super().__init__()
        self._is_running = True

    def run(self):
        """
        Continuously scan for an HSM on COM ports. When found, emit HSMID and exit.
        """
        client = hsm_handler.HSMClient()
        try:
            while self._is_running:
                # scan_and_detect returns list of (port, hsm_id)
                found = client.scan_and_detect()
                if found:
                    _, hid = found[0]
                    self.detected.emit(hid)
                    self.finished.emit("HSM detected")
                    return
                time.sleep(1)
        except Exception as e:
            self.finished.emit(f"scan_error:{e}")
        finally:
            client.close()

    def stop(self):
        self._is_running = False


class HSMWaitPage(QWidget):
    # Keep existing signals for compatibility with app navigation
    login_attempt_finished = Signal(str, str, object)  # unused in V3 scanning mode, preserved for backwards compat
    navigate_to_login = Signal()

    # New signal to proceed in the registration flow once an HSM is detected.
    hsm_detected = Signal(str)  # hsm_id

    def __init__(self):
        super().__init__()
        self.worker_thread = None
        self.worker = None
        self._hsm_id = None

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setSpacing(20)

        self.loading_label = QLabel()
        loading_gif_path = os.path.join(os.path.dirname(__file__), "..", "resources", "loading.gif")
        if os.path.exists(loading_gif_path):
            self.movie = QMovie(loading_gif_path)
            self.loading_label.setMovie(self.movie)
        else:
            self.movie = None
            self.loading_label.setText("(loading)")

        title = QLabel("Scanning COM Ports for HSM")
        title.setObjectName("h2")
        title.setAlignment(Qt.AlignCenter)

        # Updated subtitle copy per V3
        subtitle = QLabel("Searching for a connected HSM and reading its HSMID…")
        subtitle.setObjectName("secondary_text")
        subtitle.setAlignment(Qt.AlignCenter)

        self.hsmid_label = QLabel("")
        self.hsmid_label.setAlignment(Qt.AlignCenter)
        self.hsmid_label.setObjectName("secondary_text")

        self.proceed_button = QPushButton("Continue")
        self.proceed_button.setEnabled(False)
        self.proceed_button.clicked.connect(self._proceed)

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("secondary")
        self.cancel_button.setFixedWidth(120)
        self.cancel_button.clicked.connect(self.cancel)

        layout.addWidget(self.loading_label, alignment=Qt.AlignCenter)
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addWidget(self.hsmid_label)
        layout.addWidget(self.proceed_button, alignment=Qt.AlignCenter)
        layout.addWidget(self.cancel_button, alignment=Qt.AlignCenter)

    # Public entrypoint used by the app to start scanning
    def start_scan(self):
        self.stop_worker()
        if self.movie:
            self.movie.start()

        self.worker_thread = QThread()
        self.worker = HSMScanWorker()
        self.worker.moveToThread(self.worker_thread)

        self.worker_thread.started.connect(self.worker.run)
        self.worker.detected.connect(self._on_detected)
        self.worker.finished.connect(self._on_finished)

        self.worker_thread.start()

    # Backwards-compat method name (if the app previously called start_login_process)
    def start_login_process(self, email):
        # In V3, this page is responsible only for scanning. Ignore email and scan.
        self.start_scan()

    def _on_detected(self, hsm_id: str):
        self._hsm_id = hsm_id
        self.hsmid_label.setText(f"HSMID: {hsm_id}")
        self.proceed_button.setEnabled(True)

    def _on_finished(self, reason: str):
        # Stop spinner once we have a result or an error
        if self.movie:
            self.movie.stop()
        # For legacy wiring that expects login_attempt_finished, emit a neutral success path when HSM is found.
        if reason == "HSM detected":
            # status='success' is not appropriate here; keep legacy signal quiet to avoid misrouting.
            # We only rely on hsm_detected in V3 registration flow.
            pass

    def _proceed(self):
        if self._hsm_id:
            self.hsm_detected.emit(self._hsm_id)

    def cancel(self):
        self.stop_worker()
        self.navigate_to_login.emit()

    def stop_worker(self):
        if self.movie:
            self.movie.stop()
        if self.worker:
            self.worker.stop()
        if self.worker_thread:
            self.worker_thread.quit()
            self.worker_thread.wait()
        self.worker_thread = None
        self.worker = None
