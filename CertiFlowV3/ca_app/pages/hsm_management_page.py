# ca_app/pages/hsm_management_page.py

import sys
import os
import secrets
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QTableWidget, QTableWidgetItem,
                               QPushButton, QFrame, QHeaderView, QMessageBox,
                               QAbstractItemView)
from PySide6.QtCore import Qt, QThread, Signal, QObject

# --- Path setup to import handlers and other pages ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import hsm_management_handler
from ca_app.pages.dialogs import BindHsmDialog, ActivationCodeDialog, GetReasonDialog


class HsmScanWorker(QObject):
    scan_finished = Signal(int)  # Emits the number of new devices found
    def run(self):
        new_device_count = hsm_management_handler.detect_new_hsms()
        self.scan_finished.emit(new_device_count)


class HsmManagementPage(QWidget):
    def __init__(self, main_window_ref):
        super().__init__()
        self.main_window = main_window_ref
        self.scan_thread = None
        self.scan_worker = None

        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # --- Left Side: Tables and Main Content ---
        content_container = QFrame()
        content_container.setObjectName("ContentArea")
        content_layout = QVBoxLayout(content_container)
        content_layout.setContentsMargins(25, 25, 25, 25)
        content_layout.setSpacing(15)

        # --- Title and Scan Button ---
        title_layout = QHBoxLayout()
        title = QLabel("HSM Provisioning")
        title.setObjectName("h1")
        self.scan_button = QPushButton("🔎 Scan for New Devices")
        self.scan_button.setObjectName("primary")
        self.scan_button.setFixedWidth(200)
        title_layout.addWidget(title)
        title_layout.addStretch()
        title_layout.addWidget(self.scan_button)
        content_layout.addLayout(title_layout)

        # --- Detected HSMs Table ---
        detected_title = QLabel("Newly Detected HSMs")
        detected_title.setObjectName("h2")
        self._create_detected_table()
        content_layout.addWidget(detected_title)
        content_layout.addWidget(self.detected_table)

        # --- Bound HSMs Table ---
        bound_title = QLabel("Bound & Activated HSMs")
        bound_title.setObjectName("h2")
        self._create_bound_table()
        content_layout.addWidget(bound_title)
        content_layout.addWidget(self.bound_table)

        # --- Right Side: Action Panel ---
        self._create_action_panel()

        main_layout.addWidget(content_container, 70)
        main_layout.addWidget(self.action_panel, 30)

        # --- Connections ---
        self.scan_button.clicked.connect(self._run_hsm_scan)
        self.detected_table.itemSelectionChanged.connect(self._on_detected_selected)
        self.bound_table.itemSelectionChanged.connect(self._on_bound_selected)
        self.bind_button.clicked.connect(self._on_bind_clicked)
        self.regen_button.clicked.connect(self._on_regen_clicked)
        self.view_code_button.clicked.connect(self._on_view_code_clicked)
        self.revoke_button.clicked.connect(self._on_revoke_clicked)
        self.reassign_button.clicked.connect(self._on_reassign_clicked)

    def _create_detected_table(self):
        self.detected_table = QTableWidget()
        self.detected_table.setColumnCount(2)
        self.detected_table.setHorizontalHeaderLabels(["HSM ID", "Detected At"])
        self.detected_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.detected_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.detected_table.verticalHeader().setVisible(False)
        header = self.detected_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)

    def _create_bound_table(self):
        self.bound_table = QTableWidget()
        self.bound_table.setColumnCount(3)
        self.bound_table.setHorizontalHeaderLabels(["HSM ID", "Bound To Email", "Status"])
        self.bound_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.bound_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.bound_table.verticalHeader().setVisible(False)
        header = self.bound_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)

    def _create_action_panel(self):
        self.action_panel = QFrame()
        self.action_panel.setObjectName("ActionPanel")
        panel_layout = QVBoxLayout(self.action_panel)
        panel_layout.setContentsMargins(20, 25, 20, 20)
        panel_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        panel_title = QLabel("Selected HSM")
        panel_title.setObjectName("h2")

        self.details_hsm_id = QLabel("Select an HSM to begin.")
        self.details_hsm_id.setObjectName("DetailLabel")
        self.details_hsm_id.setWordWrap(True)
        # Force rich text so "<b>…</b>" never shows as literally "b … /b"
        self.details_hsm_id.setTextFormat(Qt.TextFormat.RichText)

        # Buttons for detected device
        self.bind_button = QPushButton("Bind Device to User")
        self.bind_button.setObjectName("primary")
        self.bind_button.setVisible(False)

        # Buttons for bound/activated device
        self.regen_button = QPushButton("Regenerate Activation Code")
        self.regen_button.setObjectName("primary")
        self.regen_button.setVisible(False)

        self.view_code_button = QPushButton("View Activation Code")
        self.view_code_button.setObjectName("secondary")
        self.view_code_button.setVisible(False)

        self.reassign_button = QPushButton("Reassign to Another Email")
        self.reassign_button.setObjectName("primary")
        self.reassign_button.setVisible(False)

        self.revoke_button = QPushButton("Revoke Device")
        self.revoke_button.setObjectName("primary")
        self.revoke_button.setVisible(False)

        panel_layout.addWidget(panel_title)
        panel_layout.addSpacing(20)
        panel_layout.addWidget(self.details_hsm_id)
        panel_layout.addStretch()
        panel_layout.addWidget(self.bind_button)
        panel_layout.addWidget(self.view_code_button)
        panel_layout.addWidget(self.regen_button)
        panel_layout.addWidget(self.reassign_button)
        panel_layout.addWidget(self.revoke_button)
        self.action_panel.setVisible(False)

    def load_data(self):
        """Loads data into both tables from the handler."""
        # Detected
        detected_hsms = hsm_management_handler.get_detected_hsms_for_ui()
        self.detected_table.setRowCount(0)
        for row, hsm in enumerate(detected_hsms):
            self.detected_table.insertRow(row)
            masked = hsm.get('hsm_id_masked') or ""
            item = QTableWidgetItem(masked)
            # Store full dict including hsm_id_hash for hash-first actions
            item.setData(Qt.ItemDataRole.UserRole, hsm)
            self.detected_table.setItem(row, 0, item)
            self.detected_table.setItem(row, 1, QTableWidgetItem(hsm.get('detected_at', "")))

        # Bound / activated
        bound_hsms = hsm_management_handler.get_bound_hsms_for_ui()
        self.bound_table.setRowCount(0)
        for row, hsm in enumerate(bound_hsms):
            self.bound_table.insertRow(row)
            masked = hsm.get('hsm_id_masked') or ""
            item = QTableWidgetItem(masked)
            item.setData(Qt.ItemDataRole.UserRole, hsm)
            self.bound_table.setItem(row, 0, item)
            self.bound_table.setItem(row, 1, QTableWidgetItem(hsm.get('bound_email') or ""))
            self.bound_table.setItem(row, 2, QTableWidgetItem((hsm.get('status') or "").capitalize()))

        # Reset action panel when data reloads
        self._clear_selection_and_panel()

    def _run_hsm_scan(self):
        """Executes the HSM scan in a background thread."""
        self.scan_button.setEnabled(False)
        self.scan_button.setText("Scanning...")

        self.scan_thread = QThread()
        self.scan_worker = HsmScanWorker()
        self.scan_worker.moveToThread(self.scan_thread)
        self.scan_thread.started.connect(self.scan_worker.run)
        self.scan_worker.scan_finished.connect(self._on_scan_finished)
        self.scan_thread.start()

    def _on_scan_finished(self, new_count):
        QMessageBox.information(self, "Scan Complete", f"Found and registered {new_count} new HSM device(s).")
        self.scan_button.setEnabled(True)
        self.scan_button.setText("🔎 Scan for New Devices")
        self.load_data()

        # Cleanup thread
        self.scan_thread.quit()
        self.scan_thread.wait()

    def _clear_selection_and_panel(self):
        self.detected_table.clearSelection()
        self.bound_table.clearSelection()
        self.action_panel.setVisible(False)
        self.bind_button.setVisible(False)
        self.regen_button.setVisible(False)
        self.view_code_button.setVisible(False)
        self.reassign_button.setVisible(False)
        self.revoke_button.setVisible(False)
        self.details_hsm_id.setText("Select an HSM to begin.")

    def _on_detected_selected(self):
        selected_items = self.detected_table.selectedItems()
        if not selected_items:
            if not self.bound_table.selectedItems():
                self._clear_selection_and_panel()
            return

        self.bound_table.clearSelection()
        hsm = selected_items[0].data(Qt.ItemDataRole.UserRole) or {}
        masked = hsm.get('hsm_id_masked') or ""
        self.details_hsm_id.setText(f"<b>HSM ID:</b><br>{masked}")
        self.bind_button.setVisible(True)
        self.regen_button.setVisible(False)
        self.view_code_button.setVisible(False)
        self.reassign_button.setVisible(False)
        self.revoke_button.setVisible(False)
        self.action_panel.setVisible(True)

    def _on_bound_selected(self):
        selected_items = self.bound_table.selectedItems()
        if not selected_items:
            if not self.detected_table.selectedItems():
                self._clear_selection_and_panel()
            return

        self.detected_table.clearSelection()
        hsm = selected_items[0].data(Qt.ItemDataRole.UserRole) or {}
        masked = hsm.get('hsm_id_masked') or ""
        status = (hsm.get('status') or "").capitalize()
        email = hsm.get('bound_email') or ""
        self.details_hsm_id.setText(f"<b>HSM ID:</b><br>{masked}<br><b>Status:</b> {status}<br><b>Bound To:</b> {email}")

        self.bind_button.setVisible(False)
        self.regen_button.setVisible(True)
        has_code = bool(hsm.get('activation_code'))
        self.view_code_button.setVisible(has_code)
        self.reassign_button.setVisible(True)
        self.revoke_button.setVisible(True)
        self.action_panel.setVisible(True)

    def _on_bind_clicked(self):
        selected_items = self.detected_table.selectedItems()
        if not selected_items or not self.main_window.current_admin:
            return

        hsm = selected_items[0].data(Qt.ItemDataRole.UserRole) or {}
        # Use hash-first path so binding works even when plaintext HSMID is not available
        hsm_hash = hsm.get('hsm_id_hash') or ""
        bind_dialog = BindHsmDialog(hsm_hash, self)  # shows masked id in the dialog; you can pass masked too
        if not bind_dialog.exec():
            return

        email = bind_dialog.get_email()
        admin_id = self.main_window.current_admin['id']

        ok, msg, code = hsm_management_handler.bind_hsm_to_email_by_hash(admin_id, hsm_hash, email)
        if ok:
            display_id = hsm.get('hsm_id') or hsm.get('hsm_id_masked') or hsm_hash
            code_dialog = ActivationCodeDialog(email, display_id, code, self)
            code_dialog.exec()
            self.load_data()
            self.action_panel.setVisible(False)
        else:
            QMessageBox.critical(self, "Binding Failed", msg)

    def _on_regen_clicked(self):
        selected_items = self.bound_table.selectedItems()
        if not selected_items or not self.main_window.current_admin:
            return

        hsm = selected_items[0].data(Qt.ItemDataRole.UserRole) or {}
        hsm_hash = hsm.get('hsm_id_hash') or ""
        email = hsm.get('bound_email') or ""
        admin_id = self.main_window.current_admin['id']

        new_code = secrets.token_urlsafe(16)
        ok, msg = hsm_management_handler.regenerate_activation_code_by_hash(admin_id, hsm_hash, new_code)
        if ok:
            display_id = hsm.get('hsm_id') or hsm.get('hsm_id_masked') or hsm_hash
            code_dialog = ActivationCodeDialog(email, display_id, new_code, self)
            code_dialog.exec()
            self.load_data()
        else:
            QMessageBox.critical(self, "Regenerate Failed", msg)

    def _on_view_code_clicked(self):
        selected_items = self.bound_table.selectedItems()
        if not selected_items:
            return

        hsm = selected_items[0].data(Qt.ItemDataRole.UserRole) or {}
        code = hsm.get('activation_code')
        if not code:
            QMessageBox.information(self, "Activation Code", "No activation code stored for this device.")
            return

        email = hsm.get('bound_email') or ""
        display_id = hsm.get('hsm_id') or hsm.get('hsm_id_masked') or hsm.get('hsm_id_hash')
        dialog = ActivationCodeDialog(email, display_id, code, self)
        dialog.setWindowTitle("Activation Code")
        dialog.exec()

    def _on_revoke_clicked(self):
        selected_items = self.bound_table.selectedItems()
        if not selected_items or not self.main_window.current_admin:
            return

        hsm = selected_items[0].data(Qt.ItemDataRole.UserRole) or {}
        hsm_hash = hsm.get('hsm_id_hash') or ""
        admin_id = self.main_window.current_admin['id']

        reason_dialog = GetReasonDialog(self)
        if not reason_dialog.exec():
            return
        reason = reason_dialog.get_reason() or "Unspecified"

        ok, msg = hsm_management_handler.revoke_hsm_by_hash(admin_id, hsm_hash, reason)
        if ok:
            QMessageBox.information(self, "Device Revoked", "The device has been revoked.")
            self.load_data()
        else:
            QMessageBox.critical(self, "Revoke Failed", msg)

    def _on_reassign_clicked(self):
        selected_items = self.bound_table.selectedItems()
        if not selected_items or not self.main_window.current_admin:
            return

        hsm = selected_items[0].data(Qt.ItemDataRole.UserRole) or {}
        hsm_hash = hsm.get('hsm_id_hash') or ""
        current_email = hsm.get('bound_email') or ""
        admin_id = self.main_window.current_admin['id']

        reass_dialog = BindHsmDialog(hsm_hash, self)
        reass_dialog.set_email(current_email)
        if not reass_dialog.exec():
            return

        new_email = reass_dialog.get_email()
        if not new_email or new_email == current_email:
            return

        # Regenerate a fresh code and instruct admin to deliver it with the device
        new_code = secrets.token_urlsafe(16)
        ok, msg = hsm_management_handler.regenerate_activation_code_by_hash(admin_id, hsm_hash, new_code)
        if ok:
            display_id = hsm.get('hsm_id') or hsm.get('hsm_id_masked') or hsm_hash
            info = ActivationCodeDialog(new_email, display_id, new_code, self)
            info.setWindowTitle("Reassignment Code")
            info.exec()
            QMessageBox.information(
                self,
                "Reassignment",
                "Give the device and the new activation code to the new user."
            )
            self.load_data()
        else:
            QMessageBox.critical(self, "Reassign Failed", msg)

    def showEvent(self, event):
        super().showEvent(event)
        self.load_data()
