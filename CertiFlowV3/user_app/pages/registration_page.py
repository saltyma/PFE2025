# user_app/pages/registration_page.py
# CertiFlow V3 — Registration Page (COM HSM + Activation Code + ECC CSR)
#
# Modernized UI:
#   - Welcome header + logo stays
#   - Uses global QSS for a consistent, modern look.
#   - Clean device picker (combo + custom view) sized consistently.
#   - Consistent button sizing; clear footer with Back to Login.
#
# Non-blocking & Responsive:
#   - Scan / Activate / Register run in QThread workers.
#   - Scanning provides real-time progress updates to the UI.
#
from __future__ import annotations

import os
from typing import Optional, List, Tuple

from PySide6 import QtCore, QtGui, QtWidgets

from utils import registration_handler, hsm_handler, logging_handler, ca_sync_handler
from utils.logging_handler import LogAction


# ---------------------------
# Worker infrastructure
# ---------------------------

class _HSMScanWorker(QtCore.QObject):
    """A dedicated worker for scanning COM ports with progress updates."""
    scan_progress = QtCore.Signal(str)          # Reports which port is being scanned
    device_found = QtCore.Signal(str, str)      # Reports a found device (port, hsm_id)
    finished = QtCore.Signal()                  # Reports completion of the scan
    failed = QtCore.Signal(str)                 # Reports a critical failure

    def __init__(self):
        super().__init__()
        self._client = hsm_handler.HSMClient()

    @QtCore.Slot()
    def run(self):
        try:
            ports = self._client.list_ports()
            if not ports:
                self.scan_progress.emit("No COM ports found.")
                self.finished.emit()
                return

            for port in ports:
                self.scan_progress.emit(f"Scanning {port}...")
                hid, err = self._client._probe_port_hsmid(port)
                if hid and not err:
                    self.device_found.emit(port, hid)
            
            self.finished.emit()
        except Exception as e:
            self.failed.emit(str(e))


class _SimpleWorker(QtCore.QObject):
    """Generic worker for single-shot functions (activate, register)."""
    finished = QtCore.Signal(object)
    failed = QtCore.Signal(str)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self._func = func
        self._args = args
        self._kwargs = kwargs

    @QtCore.Slot()
    def run(self):
        try:
            res = self._func(*self._args, **self._kwargs)
            self.finished.emit(res)
        except Exception as e:
            self.failed.emit(str(e))


def _safe_quit_thread(thread: Optional[QtCore.QThread], timeout_ms: int = 2000) -> None:
    """Gracefully stop a QThread and fall back to terminate if needed."""
    if thread is None:
        return
    if thread.isRunning():
        thread.requestInterruption()
        thread.quit()
        if not thread.wait(timeout_ms):
            thread.terminate()
            thread.wait(timeout_ms)


class RegistrationPage(QtWidgets.QWidget):
    registration_completed = QtCore.Signal(str)
    navigate_to_login = QtCore.Signal()

    def __init__(self, parent: Optional[QtWidgets.QWidget] = None):
        super().__init__(parent)

        self._auto_scanned = False
        self._busy = False
        self._found_devices = 0
        self._selected_hsm_id: Optional[str] = None
        self._selected_port: Optional[str] = None
        self._background_tasks: List[Tuple[QtCore.QThread, _SimpleWorker]] = []
        self._scan_thread: Optional[QtCore.QThread] = None
        self._scan_worker: Optional[_HSMScanWorker] = None
        self._activation_verified = False

        self._build_ui()
        self._wire_events()

    # ---------------- UI ----------------
    def _build_ui(self):
        self.setObjectName("RegistrationPage")

        root = QtWidgets.QVBoxLayout(self)
        root.setAlignment(QtCore.Qt.AlignTop)
        root.setContentsMargins(40, 20, 40, 20)
        root.setSpacing(20)

        # Header area: logo + welcome
        header = QtWidgets.QVBoxLayout()
        header.setSpacing(6)

        welcome = QtWidgets.QLabel("Create your <b>Certi<span style='color:#5294e2;'>Flow</span></b> account")
        welcome.setObjectName("h1")
        welcome.setAlignment(QtCore.Qt.AlignHCenter)

        sub = QtWidgets.QLabel("Follow the steps to activate your hardware device and register.")
        sub.setObjectName("secondary_text")
        sub.setAlignment(QtCore.Qt.AlignHCenter)
        sub.setWordWrap(True)

        header.addWidget(welcome)
        header.addWidget(sub)
        root.addLayout(header)

        # Steps container - uses the info_card style from main_style.qss
        self.card = QtWidgets.QFrame()
        self.card.setObjectName("info_card") # Use global style for cards
        self.card.setMinimumWidth(580)
        card_layout = QtWidgets.QVBoxLayout(self.card)
        card_layout.setContentsMargins(25, 25, 25, 25)
        card_layout.setSpacing(15)

        self.stack = QtWidgets.QStackedWidget()
        card_layout.addWidget(self.stack)
        
        # Center the card horizontally
        h_box = QtWidgets.QHBoxLayout()
        h_box.addStretch()
        h_box.addWidget(self.card)
        h_box.addStretch()
        root.addLayout(h_box)

        # Footer with Back to Login
        footer = QtWidgets.QHBoxLayout()
        self.btn_back_login = QtWidgets.QPushButton("Back to Login")
        self.btn_back_login.setObjectName("secondary")
        footer.addStretch(1)
        footer.addWidget(self.btn_back_login)
        root.addLayout(footer)

        # -------- Step 1: Detect HSM(s)
        self.step1 = QtWidgets.QWidget()
        s1 = QtWidgets.QVBoxLayout(self.step1)
        s1.setSpacing(15)

        s1_head = QtWidgets.QLabel("Step 1 of 3 — Select Device")
        s1_head.setObjectName("h2")
        s1_head.setAlignment(QtCore.Qt.AlignCenter)

        # Use a standard QLineEdit for status feedback
        self.scan_status_label = QtWidgets.QLineEdit()
        self.scan_status_label.setPlaceholderText("HSM scan status will appear here...")
        self.scan_status_label.setReadOnly(True)
        
        self.cmb_devices = QtWidgets.QComboBox()
        self.cmb_devices.setPlaceholderText("Select a detected HSM device")

        self.btn_rescan = QtWidgets.QPushButton("Rescan")
        self.btn_rescan.setObjectName("secondary")
        
        h_layout_scan = QtWidgets.QHBoxLayout()
        h_layout_scan.addWidget(self.cmb_devices, 1)
        h_layout_scan.addWidget(self.btn_rescan)
        
        nav1 = QtWidgets.QHBoxLayout()
        nav1.addStretch(1)
        self.btn_s1_next = QtWidgets.QPushButton("Next")
        self.btn_s1_next.setObjectName("primary")
        self.btn_s1_next.setEnabled(False)
        nav1.addWidget(self.btn_s1_next)

        s1.addWidget(s1_head)
        s1.addLayout(h_layout_scan)
        s1.addWidget(self.scan_status_label)
        s1.addStretch(1)
        s1.addLayout(nav1)
        self.stack.addWidget(self.step1)
        
        # -------- Step 2: Activation
        self.step2 = QtWidgets.QWidget()
        s2 = QtWidgets.QVBoxLayout(self.step2)
        s2.setSpacing(15)

        s2_head = QtWidgets.QLabel("Step 2 of 3 — Activation")
        s2_head.setObjectName("h2")
        s2_head.setAlignment(QtCore.Qt.AlignCenter)

        s2_sub = QtWidgets.QLabel("Enter the one-time activation code for your device.")
        s2_sub.setObjectName("secondary_text")
        s2_sub.setAlignment(QtCore.Qt.AlignCenter)

        self.inp_activation = QtWidgets.QLineEdit()
        self.inp_activation.setPlaceholderText("Paste activation code here")

        nav2 = QtWidgets.QHBoxLayout()
        self.btn_s2_back = QtWidgets.QPushButton("Back")
        self.btn_s2_back.setObjectName("secondary")
        nav2.addWidget(self.btn_s2_back)
        nav2.addStretch(1)
        self.btn_s2_next = QtWidgets.QPushButton("Next")
        self.btn_s2_next.setObjectName("primary")
        nav2.addWidget(self.btn_s2_next)

        s2.addWidget(s2_head)
        s2.addWidget(s2_sub)
        s2.addWidget(self.inp_activation)
        s2.addStretch(1)
        s2.addLayout(nav2)
        self.stack.addWidget(self.step2)

        # -------- Step 3: Account details
        self.step3 = QtWidgets.QWidget()
        s3 = QtWidgets.QVBoxLayout(self.step3)
        s3.setSpacing(15)

        s3_head = QtWidgets.QLabel("Step 3 of 3 — Account Details")
        s3_head.setObjectName("h2")
        s3_head.setAlignment(QtCore.Qt.AlignCenter)

        form_layout = QtWidgets.QFormLayout()
        form_layout.setSpacing(10)
        
        self.inp_email = QtWidgets.QLineEdit()
        self.inp_email.setPlaceholderText("your.name@uit.ac.ma")
        self.inp_name = QtWidgets.QLineEdit()
        self.inp_name.setPlaceholderText("Your Full Name")
        self.inp_pin = QtWidgets.QLineEdit()
        self.inp_pin.setEchoMode(QtWidgets.QLineEdit.Password)
        self.inp_pin.setPlaceholderText("Choose a 4-8 digit PIN for the HSM")

        form_layout.addRow("Institutional Email:", self.inp_email)
        form_layout.addRow("Full Name:", self.inp_name)
        form_layout.addRow("HSM PIN:", self.inp_pin)

        nav3 = QtWidgets.QHBoxLayout()
        self.btn_s3_back = QtWidgets.QPushButton("Back")
        self.btn_s3_back.setObjectName("secondary")
        nav3.addWidget(self.btn_s3_back)
        nav3.addStretch(1)
        self.btn_register = QtWidgets.QPushButton("Submit Registration")
        self.btn_register.setObjectName("primary")
        nav3.addWidget(self.btn_register)

        s3.addWidget(s3_head)
        s3.addLayout(form_layout)
        s3.addStretch(1)
        s3.addLayout(nav3)
        self.stack.addWidget(self.step3)

    def _wire_events(self):
        # Global nav
        self.btn_back_login.clicked.connect(self.navigate_to_login.emit)

        # Step 1
        self.btn_rescan.clicked.connect(self._start_scan_thread)
        self.cmb_devices.currentIndexChanged.connect(self._on_device_changed)
        self.btn_s1_next.clicked.connect(self._handle_step1_next)

        # Step 2
        self.btn_s2_back.clicked.connect(self._handle_step2_back)
        # Validate activation with CA before allowing Step 3
        self.btn_s2_next.clicked.connect(self._handle_step2_next)

        # Step 3
        self.btn_s3_back.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        self.btn_register.clicked.connect(self._start_register_thread)
        self.inp_pin.returnPressed.connect(self._start_register_thread)

    def showEvent(self, e: QtGui.QShowEvent) -> None:
        super().showEvent(e)
        if not self._auto_scanned:
            self._auto_scanned = True
            QtCore.QTimer.singleShot(200, self._start_scan_thread)

    def hideEvent(self, e: QtGui.QHideEvent) -> None:
        self._finalize_scan_worker()
        self._stop_scan_thread()
        super().hideEvent(e)

    def _set_busy(self, busy: bool, message: str = ""):
        self._busy = busy
        self.card.setDisabled(busy)
        self.btn_back_login.setDisabled(busy)
        if busy:
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.WaitCursor)
            self.scan_status_label.setText(message)
        else:
            QtWidgets.QApplication.restoreOverrideCursor()

    def _on_device_changed(self, idx: int):
        self._activation_verified = False
        if idx < 0:
            self._selected_hsm_id = None
            self._selected_port = None
            self.btn_s1_next.setEnabled(False)
            return
        data = self.cmb_devices.itemData(idx)
        if isinstance(data, tuple) and len(data) == 2:
            self._selected_port, self._selected_hsm_id = data
            self.btn_s1_next.setEnabled(True)
        else:
            self._selected_hsm_id = None
            self._selected_port = None
            self.btn_s1_next.setEnabled(False)
        self._activation_verified = False

    def _start_scan_thread(self):
        if self._busy:
            return
        
        self._set_busy(True, "Starting HSM scan...")
        self._activation_verified = False
        self.cmb_devices.clear()
        self.btn_s1_next.setEnabled(False)
        self._found_devices = 0
        self._activation_verified = False

        self._finalize_scan_worker()
        self._stop_scan_thread()

        self._scan_thread = QtCore.QThread(self)
        self._scan_worker = _HSMScanWorker()
        self._scan_worker.moveToThread(self._scan_thread)

        self._scan_worker.scan_progress.connect(self._scan_progress_update)
        self._scan_worker.device_found.connect(self._scan_device_found)
        self._scan_worker.finished.connect(self._scan_finished)
        self._scan_worker.failed.connect(self._scan_fail)

        self._scan_thread.started.connect(self._scan_worker.run)
        self._scan_thread.start()

    def _scan_progress_update(self, message: str):
        self.scan_status_label.setText(message)

    def _scan_device_found(self, port: str, hsm_id: str):
        self._found_devices += 1
        label = f"{hsm_id}  (@ {port})"
        self.cmb_devices.addItem(label, (port, hsm_id))

    def _scan_finished(self):
        self._finalize_scan_worker()
        self._stop_scan_thread()
        self._set_busy(False)
        
        if self._found_devices == 0:
            self.scan_status_label.setText("Scan complete: No HSM devices were found.")
            logging_handler.log(LogAction.HSM_NOT_FOUND, {"reason": "Scan found no devices"})
        else:
            self.scan_status_label.setText(f"Scan complete: Found {self._found_devices} device(s).")
            self.cmb_devices.setCurrentIndex(0)
            self._on_device_changed(0)
    
    def _scan_fail(self, err: str):
        self._finalize_scan_worker()
        self._stop_scan_thread()
        self._set_busy(False)
        self.scan_status_label.setText(f"Scan error: {err}")
        logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"Scan failed: {err}"})

    def _start_register_thread(self):
        if self._busy:
            return
        email = self.inp_email.text().strip()
        name = self.inp_name.text().strip()
        pin = self.inp_pin.text().strip()
        code = self.inp_activation.text().strip()

        if not all([self._selected_hsm_id, self._selected_port, code, email, name, pin]):
            self._toast("Please complete all fields on all steps.")
            return

        if not self._activation_verified:
            self._toast("Activate your HSM before submitting the registration.")
            return

        self._set_busy(True, "Submitting registration...")

        def _register():
            ok, msg = registration_handler.register_new_user(
                email=email,
                full_name=name,
                activation_code=code,
                pin=pin,
                expected_hsm_id=self._selected_hsm_id,
            )
            if not ok:
                raise RuntimeError(msg or "Registration failed.")
            return email
        
        self._run_simple_worker(_register, self._register_done, self._register_fail)

    def _register_done(self, email: str):
        self._set_busy(False)
        self.registration_completed.emit(email)

    def _register_fail(self, err: str):
        self._set_busy(False)
        self._toast(f"Registration Error: {err}")
        logging_handler.log(LogAction.APPLICATION_ERROR, {"reason": f"Registration error: {err}"})
        
    def _run_simple_worker(self, func, on_ok, on_fail):
        thread = QtCore.QThread(self)
        worker = _SimpleWorker(func)
        worker.moveToThread(thread)

        self._background_tasks.append((thread, worker))

        def _cleanup():
            try:
                self._background_tasks.remove((thread, worker))
            except ValueError:
                pass
            _safe_quit_thread(thread)
            worker.deleteLater()
            thread.deleteLater()

        thread.started.connect(worker.run)
        worker.finished.connect(on_ok)
        worker.failed.connect(on_fail)

        worker.finished.connect(thread.quit)
        worker.failed.connect(thread.quit)

        thread.finished.connect(_cleanup)

        thread.start()

    def closeEvent(self, event: QtGui.QCloseEvent) -> None:
        self._finalize_scan_worker()
        self._stop_scan_thread()
        self._stop_background_tasks()
        super().closeEvent(event)

    def _stop_background_tasks(self):
        for thread, worker in list(self._background_tasks):
            _safe_quit_thread(thread)
            worker.deleteLater()
            thread.deleteLater()
        self._background_tasks.clear()

    def _stop_scan_thread(self):
        thread = self._scan_thread
        if thread is not None:
            _safe_quit_thread(thread)
            thread.deleteLater()
        self._scan_thread = None

    def _finalize_scan_worker(self):
        if self._scan_worker is not None:
            self._scan_worker.deleteLater()
        self._scan_worker = None

    def _handle_step2_next(self):
        if self._busy:
            return
        code = (self.inp_activation.text() or "").strip()
        if not self._selected_hsm_id:
            self._toast("No HSM selected. Please pick your device in Step 1.")
            return
        if not code:
            self._toast("Enter your activation code.")
            return

        self._set_busy(True, "Validating activation code...")
        self._activation_verified = False

        def _activate():
            ok, msg = ca_sync_handler.activate_device(self._selected_hsm_id, code)
            if not ok:
                raise RuntimeError(msg or "Invalid or expired activation code.")
            message = msg or "Device activated."
            return {"message": message, "ok": True}

        self._run_simple_worker(_activate, self._activation_ok, self._activation_fail)

    def _activation_ok(self, payload):
        self._set_busy(False)
        # Mark in-memory so Step 3 can proceed cleanly
        message = ""
        ok_flag = True
        if isinstance(payload, dict):
            message = payload.get("message", "")
            ok_flag = bool(payload.get("ok", True))
        elif isinstance(payload, str):
            message = payload
        self._activation_verified = ok_flag
        logging_handler.log(
            LogAction.HSM_ACTIVATE_OK,
            {
                "hsm_id": self._selected_hsm_id,
                "message": message or "Device activated.",
                "server_ok": ok_flag,
            },
        )
        self.stack.setCurrentIndex(2)
        if message and not ok_flag:
            self._toast(message)
        elif message and "activated" in message.lower():
            # Friendly heads-up that activation succeeded
            self.scan_status_label.setText(message)

    def _activation_fail(self, err: str):
        self._set_busy(False)
        self._activation_verified = False
        self._toast(f"Activation failed: {err}")
        logging_handler.log(
            LogAction.HSM_ACTIVATE_FAIL,
            {"hsm_id": self._selected_hsm_id, "reason": err},
        )
        logging_handler.log(
            LogAction.APPLICATION_ERROR,
            {"reason": f"Activation failed: {err}", "hsm_id": self._selected_hsm_id},
        )


    def _toast(self, message: str):
        QtWidgets.QMessageBox.information(self, "Registration", message)

    def _handle_step1_next(self):
        if self._busy:
            return
        self._activation_verified = False
        self.stack.setCurrentIndex(1)

    def _handle_step2_back(self):
        if self._busy:
            return
        self._activation_verified = False
        self.stack.setCurrentIndex(0)
