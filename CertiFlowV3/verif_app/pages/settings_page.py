# pages/settings_page.py

from __future__ import annotations
import os
import sys
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QPushButton,
                               QTextEdit, QMessageBox, QFrame, QApplication)
from cryptography import x509

# --- Path Setup ---
APP_PATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_PATH)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from utils.trust_manager import refresh_trust, get_current_trust

class SettingsPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._build_ui()
        self.load_snapshot()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        title = QLabel("Trust Settings")
        title.setObjectName("h1")
        layout.addWidget(title)

        card = QFrame()
        card.setObjectName("ContentCard")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(15)

        description = QLabel(
            "To verify signatures offline, this application stores a local copy (a 'snapshot') of the central "
            "Certificate Authority's (CA) data. This includes the CA's root certificate and a list of revoked "
            "certificates (CRL). If the CA has been updated recently, click 'Refresh Trust Snapshot' to download the latest data."
        )
        description.setObjectName("secondary_text")
        description.setWordWrap(True)
        card_layout.addWidget(description)

        self.refresh_btn = QPushButton("Refresh Trust Snapshot")
        self.refresh_btn.setObjectName("primary")
        self.refresh_btn.clicked.connect(self._on_refresh_clicked)
        card_layout.addWidget(self.refresh_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        self.info_box = QTextEdit()
        self.info_box.setReadOnly(True)
        self.info_box.setObjectName("JsonViewer")
        card_layout.addWidget(self.info_box, 1)

        layout.addWidget(card, 1)

    def showEvent(self, event):
        """Called every time the page becomes visible to ensure data is fresh."""
        super().showEvent(event)
        self.load_snapshot()

    def load_snapshot(self):
        snap = get_current_trust()
        if not snap:
            self.info_box.setPlainText("No trust snapshot found. Click 'Refresh Trust' to download the necessary CA data.")
            return

        lines = [
            "=== Current Trust Snapshot ===",
            f"  Snapshot Time (UTC): {snap.get('last_sync_utc', 'N/A')}",
            f"  CRL Version:         {snap.get('crl_version', 'N/A')}",
            f"  CRL Issued (UTC):    {snap.get('crl_issued_at_utc', 'N/A')}",
            "\n--- CA Root Certificate Details ---",
        ]
        try:
            pem = snap.get("ca_root_pem", "")
            if not pem:
                raise ValueError("PEM data is missing from snapshot.")
            cert = x509.load_pem_x509_certificate(pem.encode("utf-8"))
            lines.append(f"  Subject: {cert.subject.rfc4514_string()}")
            lines.append(f"  Issuer:  {cert.issuer.rfc4514_string()}")
            lines.append(f"  Serial:  {cert.serial_number}")
            lines.append(f"  Valid From (UTC): {cert.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"  Valid Until (UTC): {cert.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S')}")
        except Exception as e:
            lines.append(f"  (Could not parse CA root certificate: {e})")

        self.info_box.setPlainText("\n".join(lines))

    def _on_refresh_clicked(self):
        self.refresh_btn.setEnabled(False)
        self.refresh_btn.setText("Refreshing...")
        QApplication.processEvents()

        ok, msg = refresh_trust()

        self.refresh_btn.setEnabled(True)
        self.refresh_btn.setText("Refresh Trust Snapshot")
        if not ok:
            QMessageBox.warning(self, "Refresh Failed", msg or "An unknown error occurred.")
        else:
            self.load_snapshot()
            QMessageBox.information(self, "Success", msg or "Trust snapshot was refreshed successfully.")

