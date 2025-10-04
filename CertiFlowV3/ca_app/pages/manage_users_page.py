# ca_app/pages/manage_users_page.py

import sys
import os
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QTableWidget, QTableWidgetItem,
                               QPushButton, QFrame, QHeaderView, QMessageBox)
from PySide6.QtCore import Qt, QTimer

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import user_management_handler
from ca_app.pages.dialogs import GetReasonDialog


def _mask_hsmid(hsmid: str | None) -> str:
    if not hsmid:
        return ""
    s = str(hsmid)
    if len(s) <= 8:
        return s
    return f"{s[:4]}…{s[-4:]}"


def _status_color(status: str) -> str:
    palette = {
        "verified": "#4CAF50",
        "pending": "#F1C232",
        "revoked": "#E57373",
        "rejected": "#90A4AE",
    }
    return palette.get((status or "").lower(), "#E0E0E0")


class ManageUsersPage(QWidget):
    def __init__(self, main_window_ref):
        super().__init__()
        self.main_window = main_window_ref
        self.users_data = []  # Cache for user data

        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # --- Left Side: User List ---
        list_container = QFrame()
        list_container.setObjectName("ContentArea")
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(25, 25, 25, 25)
        list_layout.setSpacing(15)

        title = QLabel("User Management")
        title.setObjectName("h1")

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Search by email or HSM ID...")
        self.search_bar.textChanged.connect(self._filter_table)

        self._create_table()

        list_layout.addWidget(title)
        list_layout.addWidget(self.search_bar)
        list_layout.addWidget(self.user_table)

        # --- Right Side: Action Panel ---
        self._create_action_panel()

        main_layout.addWidget(list_container, 70)   # 70% width
        main_layout.addWidget(self.action_panel, 30)  # 30% width

        # --- Timer for automatic refresh ---
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.load_users)
        self.refresh_timer.start(30000)  # Refresh every 30 seconds

    def showEvent(self, event):
        super().showEvent(event)
        self.load_users()

    def _create_table(self):
        self.user_table = QTableWidget()
        self.user_table.setColumnCount(6)
        self.user_table.setHorizontalHeaderLabels(
            ["Email", "Overall Status", "Email Verified", "HSM Status", "HSM ID", "Certificate Expires"]
        )
        self.user_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.user_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.user_table.verticalHeader().setVisible(False)
        self.user_table.setShowGrid(False)

        header = self.user_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)

        self.user_table.itemSelectionChanged.connect(self._on_user_selected)

    def _create_action_panel(self):
        self.action_panel = QFrame()
        self.action_panel.setObjectName("ActionPanel")
        panel_layout = QVBoxLayout(self.action_panel)
        panel_layout.setContentsMargins(20, 25, 20, 20)
        panel_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        panel_title = QLabel("Selected User Details")
        panel_title.setObjectName("h2")

        self.details_email = QLabel("Select a user to see details.")
        self.details_email.setObjectName("DetailLabel")
        self.details_email.setWordWrap(True)

        self.details_hsm = QLabel()
        self.details_hsm.setObjectName("DetailLabel")
        self.details_hsm.setWordWrap(True)

        # Detailed verification status
        self.details_status_frame = QFrame()
        self.details_status_layout = QVBoxLayout(self.details_status_frame)
        self.details_status_layout.setContentsMargins(0, 0, 0, 0)
        self.details_overall_status = QLabel()
        self.details_email_verified = QLabel()
        self.details_hsm_status = QLabel()
        self.details_status_layout.addWidget(self.details_overall_status)
        self.details_status_layout.addWidget(self.details_email_verified)
        self.details_status_layout.addWidget(self.details_hsm_status)

        self.revoke_button = QPushButton("Revoke Certificate")
        self.revoke_button.setObjectName("danger")
        self.revoke_button.setVisible(False)
        self.revoke_button.clicked.connect(self._on_revoke_clicked)

        panel_layout.addWidget(panel_title)
        panel_layout.addSpacing(20)
        panel_layout.addWidget(self.details_email)
        panel_layout.addSpacing(10)
        panel_layout.addWidget(self.details_hsm)
        panel_layout.addSpacing(10)
        panel_layout.addWidget(self.details_status_frame)
        panel_layout.addStretch()
        panel_layout.addWidget(self.revoke_button)

    def load_users(self):
        self.users_data = user_management_handler.get_all_users_with_certificate_info()
        self.user_table.setRowCount(0)

        for row, user in enumerate(self.users_data):
            self.user_table.insertRow(row)

            # Keep the original dict handy
            email_item = QTableWidgetItem(user['email'])
            email_item.setData(Qt.ItemDataRole.UserRole, user)
            self.user_table.setItem(row, 0, email_item)

            self.user_table.setCellWidget(row, 1, self._create_status_widget(user['status']))
            self.user_table.setCellWidget(row, 2, self._create_verification_widget(user.get('email_verified', False)))
            self.user_table.setCellWidget(row, 3, self._create_hsm_status_widget(user.get('hsm_status')))

            # Masked HSM ID for display; raw stays in the cached user dict
            masked = _mask_hsmid(user.get('hsm_id'))
            self.user_table.setItem(row, 4, QTableWidgetItem(masked))

            expires = user.get('valid_to', 'N/A')
            if isinstance(expires, str) and ' ' in expires:
                expires = expires.split(' ')[0]
            self.user_table.setItem(row, 5, QTableWidgetItem(str(expires)))

        self._on_user_selected()  # Refresh details panel

    def _create_status_widget(self, status):
        text = (status or "").capitalize()
        label = QLabel(text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setStyleSheet(f"color: {_status_color(status)}; font-weight: 600;")
        return label

    def _create_verification_widget(self, is_verified):
        label = QLabel("✓ Verified" if is_verified else "❌ Pending")
        label.setStyleSheet("color: #4CAF50;" if is_verified else "color: #E57373;")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        return label

    def _create_hsm_status_widget(self, status):
        status_text = (status or "Unknown").capitalize()
        label = QLabel(status_text)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if status == 'activated':
            label.setStyleSheet("color: #4CAF50;")
        elif status == 'bound':
            label.setStyleSheet("color: #FFC107;")  # Amber for bound but not activated
        return label

    def _filter_table(self, text):
        q = (text or "").lower()
        for row in range(self.user_table.rowCount()):
            email_item = self.user_table.item(row, 0)
            hsm_item = self.user_table.item(row, 4)  # masked value
            should_show = (q in (email_item.text() or "").lower() or
                           q in (hsm_item.text() or "").lower())
            self.user_table.setRowHidden(row, not should_show)

    def _on_user_selected(self):
        selected_items = self.user_table.selectedItems()
        if not selected_items:
            self.details_email.setText("Select a user to see details.")
            self.details_hsm.setText("")
            self.details_overall_status.setText("")
            self.details_email_verified.setText("")
            self.details_hsm_status.setText("")
            self.revoke_button.setVisible(False)
            return

        user = selected_items[0].data(Qt.ItemDataRole.UserRole)

        # Details pane shows masked HSM ID
        self.details_email.setText(f"<b>Email:</b><br>{user['email']}")
        self.details_hsm.setText(f"<b>HSM ID:</b><br>{_mask_hsmid(user.get('hsm_id'))}")

        status = user['status']
        status_color = _status_color(status)
        self.details_overall_status.setText(
            f"<b>Overall Status:</b> "
            f"<span style='color:{status_color}; font-weight:600;'>{status.capitalize()}</span>"
        )
        email_verified_text = "✓ Verified" if user.get('email_verified') else "❌ Not Verified"
        self.details_email_verified.setText(f"<b>Email Status:</b> {email_verified_text}")

        hsm_status_text = (user.get('hsm_status') or "Unknown").capitalize()
        self.details_hsm_status.setText(f"<b>HSM Status:</b> {hsm_status_text}")

        can_revoke = bool(
            user['status'] == 'verified' and
            user.get('cert_serial') and
            not user.get('is_revoked')
        )
        self.revoke_button.setVisible(can_revoke)

    def _on_revoke_clicked(self):
        selected_items = self.user_table.selectedItems()
        if not selected_items or not self.main_window.current_admin:
            return

        user = selected_items[0].data(Qt.ItemDataRole.UserRole)
        email = user['email']
        cert_serial = user.get('cert_serial')

        if not cert_serial:
            QMessageBox.critical(self, "Error", "Cannot revoke: Certificate Serial Number is missing.")
            return

        # Mandatory reason dialog (matches updated GetReasonDialog signature)
        reason_dialog = GetReasonDialog(self)
        reason_dialog.setWindowTitle("Revoke Certificate")
        reason_dialog.prompt_label.setText(f"Please provide a reason for revoking the certificate for {email}.")
        if not reason_dialog.exec():
            return

        reason = reason_dialog.get_reason()
        if not reason:
            # Should not happen because dialog enforces it, but double-check
            QMessageBox.warning(self, "Reason Required", "A revocation reason is required.")
            return

        admin_id = self.main_window.current_admin['id']

        success, message = user_management_handler.revoke_certificate(
            user_email=email, cert_serial=cert_serial, admin_id=admin_id, reason=reason
        )

        if success:
            QMessageBox.information(self, "Success", message)
            self.load_users()
        else:
            QMessageBox.critical(self, "Revocation Failed", message)
