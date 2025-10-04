# pages/verification_result_dialog.py

from __future__ import annotations
import os
import sys
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QFrame, QGridLayout, QFileDialog,
                               QMessageBox)
from PySide6.QtCore import Qt

# --- Path Setup ---
APP_PATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_PATH)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from utils.report import export_json, export_text_summary
from utils.trust_manager import get_current_trust

class VerificationResultDialog(QDialog):
    def __init__(self, parent=None, result_data: dict = None):
        super().__init__(parent)
        self.setWindowTitle("Verification Result")
        self.setMinimumWidth(550)
        self.setModal(True)
        self.result_data = result_data or {}
        self._build_ui()
        if self.result_data:
            self.show_result(self.result_data)

    def _build_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(15)

        # Header (Icon + Title)
        header_layout = QHBoxLayout()
        self.title_label = QLabel("Verification Status")
        self.title_label.setObjectName("h2")
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()
        main_layout.addLayout(header_layout)

        # Details Card
        card = QFrame()
        card.setObjectName("ContentCard")
        grid = QGridLayout(card)
        grid.setSpacing(10)
        grid.setColumnStretch(1, 1)

        self.status_label = self._add_grid_row(grid, 0, "Status:")
        self.reason_label = self._add_grid_row(grid, 1, "Details:")
        self.signer_cn_label = self._add_grid_row(grid, 2, "Signer Name:")
        self.signer_email_label = self._add_grid_row(grid, 3, "Signer Email:")
        self.timestamp_label = self._add_grid_row(grid, 4, "Timestamp (UTC):")
        self.file_hash_label = self._add_grid_row(grid, 5, "Document Hash:")
        main_layout.addWidget(card)

        # Actions
        actions_layout = QHBoxLayout()
        actions_layout.addStretch()
        self.export_json_btn = QPushButton("Export as JSON")
        self.export_json_btn.setObjectName("secondary")
        self.export_json_btn.clicked.connect(self._export_json)
        self.export_txt_btn = QPushButton("Export as TXT")
        self.export_txt_btn.setObjectName("secondary")
        self.export_txt_btn.clicked.connect(self._export_txt)
        self.ok_button = QPushButton("OK")
        self.ok_button.setObjectName("primary")
        self.ok_button.clicked.connect(self.accept)
        actions_layout.addWidget(self.export_json_btn)
        actions_layout.addWidget(self.export_txt_btn)
        actions_layout.addWidget(self.ok_button)
        main_layout.addLayout(actions_layout)

    def _add_grid_row(self, grid, row, label_text):
        label = QLabel(label_text)
        label.setStyleSheet("font-weight: bold; color: #A0A0A0;")
        value_label = QLabel("...")
        value_label.setWordWrap(True)
        value_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        grid.addWidget(label, row, 0, Qt.AlignmentFlag.AlignTop)
        grid.addWidget(value_label, row, 1)
        return value_label

    def show_result(self, result: dict):
        self.result_data = result
        is_valid = result.get("result") == "valid"

        if is_valid:
            self.title_label.setText("Signature Valid")
            self.status_label.setText("<b style='color:#28a745;'>Authentic</b>")
        else:
            self.title_label.setText("Signature Invalid")
            self.status_label.setText("<b style='color:#E57373;'>Not Authentic</b>")

        self.reason_label.setText(result.get("reason", "No details provided."))
        self.signer_cn_label.setText(result.get("signer_cn", "N/A"))
        self.signer_email_label.setText(result.get("signer_email", "N/A"))
        self.timestamp_label.setText(result.get("pdf_sig_timestamp_utc", "N/A"))
        self.file_hash_label.setText(result.get("file_sha256", "N/A"))

        # Enable export buttons only if verification was successful enough to generate data
        can_export = "file_name" in result and "signer_email" in result
        self.export_json_btn.setEnabled(can_export)
        self.export_txt_btn.setEnabled(can_export)

    def _export_json(self):
        start_path = os.path.splitext(self.result_data.get("file_name", "report"))[0] + ".json"
        save_path, _ = QFileDialog.getSaveFileName(self, "Export JSON Report", start_path, "JSON Files (*.json)")
        if save_path:
            try:
                trust = get_current_trust()
                export_json(self.result_data, trust_snapshot=trust, out_path=save_path)
                QMessageBox.information(self, "Success", f"Report saved to:\n{save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not export report: {e}")

    def _export_txt(self):
        start_path = os.path.splitext(self.result_data.get("file_name", "report"))[0] + ".txt"
        save_path, _ = QFileDialog.getSaveFileName(self, "Export Text Summary", start_path, "Text Files (*.txt)")
        if save_path:
            try:
                trust = get_current_trust()
                export_text_summary(self.result_data, trust_snapshot=trust, out_path=save_path)
                QMessageBox.information(self, "Success", f"Summary saved to:\n{save_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Could not export summary: {e}")
