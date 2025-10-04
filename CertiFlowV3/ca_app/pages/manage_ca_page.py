# ca_app/pages/manage_ca_page.py

import os
import sys
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPushButton, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox, QAbstractItemView
)
from PySide6.QtCore import Qt

# --- Path setup and import of the new AddAdminDialog ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import admin_management_handler
from ca_app.pages.add_admin_dialog import AddAdminDialog


def _mask_hsmid(hsmid: str | None) -> str:
    if not hsmid:
        return ""
    s = str(hsmid)
    if len(s) <= 8:
        return s
    return f"{s[:4]}…{s[-4:]}"


class ManageCaPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.admins_data = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)

        # --- Title ---
        title = QLabel("Manage CA Administrators")
        title.setObjectName("h1")
        layout.addWidget(title)

        subtitle = QLabel("Add, remove, and view CA administrators.")
        subtitle.setObjectName("secondary_text")
        layout.addWidget(subtitle)

        # --- Table ---
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["ID", "Email", "HSM ID", "Role"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        layout.addWidget(self.table)

        # --- Action buttons ---
        action_layout = QHBoxLayout()
        self.add_button = QPushButton("➕ Add Admin")
        self.add_button.setObjectName("primary")
        self.remove_button = QPushButton("🗑 Remove Selected")
        self.remove_button.setObjectName("danger")

        action_layout.addStretch()
        action_layout.addWidget(self.add_button)
        action_layout.addWidget(self.remove_button)
        layout.addLayout(action_layout)

        # --- Signals ---
        self.add_button.clicked.connect(self._on_add_admin_clicked)
        self.remove_button.clicked.connect(self._on_remove_admin_clicked)

    def load_admins(self):
        """Fetches and displays all administrators in the table."""
        self.admins_data = admin_management_handler.get_all_admins()
        self.table.setRowCount(0)
        for row_idx, admin in enumerate(self.admins_data):
            self.table.insertRow(row_idx)

            id_item = QTableWidgetItem(str(admin['id']))
            # keep full admin dict for internal use
            id_item.setData(Qt.ItemDataRole.UserRole, admin)
            self.table.setItem(row_idx, 0, id_item)

            self.table.setItem(row_idx, 1, QTableWidgetItem(admin['email']))

            # Mask HSM ID for display; store raw in UserRole on the same cell
            masked = _mask_hsmid(admin.get('hsm_id'))
            hsm_item = QTableWidgetItem(masked)
            hsm_item.setToolTip(admin.get('hsm_id') or "")
            hsm_item.setData(Qt.ItemDataRole.UserRole, admin.get('hsm_id'))
            self.table.setItem(row_idx, 2, hsm_item)

            role = "Root Admin" if admin['is_root'] else "Admin"
            role_item = QTableWidgetItem(role)
            if admin['is_root']:
                role_item.setForeground(Qt.GlobalColor.yellow)
            self.table.setItem(row_idx, 3, role_item)

    def _require_root(self) -> bool:
        """Strong check for root-only operations."""
        admin = getattr(self.main_window, "current_admin", None)
        return bool(admin and admin.get('is_root'))

    def _on_add_admin_clicked(self):
        """Launches the Add Admin wizard (root only)."""
        if not self._require_root():
            QMessageBox.critical(self, "Permission Denied", "Only the root administrator can add admins.")
            return

        dialog = AddAdminDialog(self.main_window, self)
        dialog.admin_added_successfully.connect(self.load_admins)
        dialog.exec()

    def _on_remove_admin_clicked(self):
        """Handles the removal of a selected administrator (root only)."""
        if not self._require_root():
            QMessageBox.critical(self, "Permission Denied", "Only the root administrator can remove admins.")
            return

        selected_row = self.table.currentRow()
        if selected_row < 0:
            QMessageBox.warning(self, "No Selection", "Please select an admin to remove.")
            return

        admin_id = int(self.table.item(selected_row, 0).text())
        admin_email = self.table.item(selected_row, 1).text()

        confirm = QMessageBox.question(
            self, "Confirm Removal",
            f"Are you sure you want to remove administrator '{admin_email}'?\n"
            "This action is irreversible.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            success, msg = admin_management_handler.remove_admin(
                admin_id, self.main_window.current_admin['id']
            )
            if success:
                QMessageBox.information(self, "Success", msg)
                self.load_admins()
            else:
                QMessageBox.critical(self, "Error", msg)

    def showEvent(self, event):
        """
        Called every time the page is shown.
        Loads admins and enforces root-only permissions.
        """
        super().showEvent(event)
        self.load_admins()

        # --- CRITICAL SECURITY CHECK ---
        is_root = self.main_window.current_admin and self.main_window.current_admin.get('is_root')
        self.add_button.setVisible(is_root)
        self.remove_button.setVisible(is_root)
