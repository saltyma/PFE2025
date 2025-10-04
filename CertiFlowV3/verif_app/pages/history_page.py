# pages/history_page.py

from __future__ import annotations
import os
import sys
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                               QTableWidget, QTableWidgetItem, QMessageBox, QHeaderView)

# --- Path Setup ---
APP_PATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_PATH)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from ver_db_helper import list_verifications, get_verification
from pages.verification_result_dialog import VerificationResultDialog

class HistoryPage(QWidget):
    HEADERS = ["Timestamp (UTC)", "Result", "File Name", "Signer Email", "Details"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)

        title = QLabel("Verification History")
        title.setObjectName("h1")
        layout.addWidget(title)

        self.table = QTableWidget(0, len(self.HEADERS))
        self.table.setHorizontalHeaderLabels(self.HEADERS)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        layout.addWidget(self.table, 1)

        actions_layout = QHBoxLayout()
        actions_layout.addStretch()
        self.refresh_btn = QPushButton("Refresh History")
        self.refresh_btn.setObjectName("secondary")
        self.view_btn = QPushButton("View Details")
        self.view_btn.setObjectName("primary")
        actions_layout.addWidget(self.refresh_btn)
        actions_layout.addWidget(self.view_btn)
        layout.addLayout(actions_layout)

        # Connections
        self.refresh_btn.clicked.connect(self.refresh_history)
        self.view_btn.clicked.connect(self._view_selected_details)
        self.table.doubleClicked.connect(self._view_selected_details)

    def showEvent(self, event):
        """Called every time the page becomes visible."""
        super().showEvent(event)
        self.refresh_history()

    def refresh_history(self):
        rows = list_verifications(limit=200)
        self.table.setRowCount(0)
        for row in rows:
            i = self.table.rowCount()
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(row.get("verified_at_utc", "")))
            result_item = QTableWidgetItem(row.get("result", "").title())
            if row.get("result") == "valid":
                result_item.setForeground(Qt.GlobalColor.green)
            else:
                result_item.setForeground(Qt.GlobalColor.red)
            self.table.setItem(i, 1, result_item)
            self.table.setItem(i, 2, QTableWidgetItem(row.get("file_name", "")))
            self.table.setItem(i, 3, QTableWidgetItem(row.get("signer_email", "")))
            self.table.setItem(i, 4, QTableWidgetItem(row.get("reason", "")))
            # Store the database ID in the first item of the row
            self.table.item(i, 0).setData(Qt.ItemDataRole.UserRole, row.get("id"))

    def _view_selected_details(self):
        selected_items = self.table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a record from the history to view its details.")
            return

        row_id = selected_items[0].data(Qt.ItemDataRole.UserRole)
        record = get_verification(row_id)
        if not record:
            QMessageBox.critical(self, "Error", "Could not find the selected record in the database.")
            return

        dialog = VerificationResultDialog(self, result_data=record)
        dialog.exec()
