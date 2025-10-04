# user_app/pages/user_info_page.py

from PySide6.QtWidgets import (QWidget, QVBoxLayout, QGridLayout, QLabel,
                               QPushButton, QFrame, QSizePolicy)
from PySide6.QtCore import Qt, Signal

import db_helper  # for pulling local flags (email_verified, device_bound, activation_consumed)

class UserInfoPage(QWidget):
    """
    Displays detailed information about the user's digital certificate.
    """
    request_renewal = Signal()  # Signal to initiate the renewal process

    def __init__(self):
        super().__init__()

        # --- Main Layout ---
        # This layout will center the content card on the page
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignCenter)
        main_layout.setContentsMargins(40, 40, 40, 40)

        # --- Content Card ---
        # A styled frame to hold all the information for a clean look
        info_card = QFrame()
        info_card.setObjectName("info_card")  # Reuse style from QSS
        info_card.setMaximumWidth(700)        # Prevents it from becoming too wide

        card_layout = QVBoxLayout(info_card)
        card_layout.setSpacing(20)

        # --- Header ---
        title = QLabel("Your Digital Certificate Details")
        title.setObjectName("h2")
        title.setAlignment(Qt.AlignCenter)

        # --- Details Grid ---
        # QGridLayout is perfect for aligning labels and their values
        details_grid = QGridLayout()
        details_grid.setSpacing(15)
        details_grid.setColumnStretch(1, 1)  # Allows the value column to expand

        # Placeholders filled in set_user_data(...)
        self.cn_value = QLabel("...")
        self.email_value = QLabel("...")
        self.issuer_value = QLabel("...")
        self.valid_from_value = QLabel("...")
        self.valid_to_value = QLabel("...")
        self.serial_value = QLabel("...")
        self.serial_value.setWordWrap(True)  # Ensure long serials can wrap

        # Optional extras for V3 visibility
        self.hsmid_value = QLabel("...")
        self.email_verified_value = QLabel("...")
        self.device_bound_value = QLabel("...")
        self.activation_consumed_value = QLabel("...")

        # Add labels and value widgets to the grid
        row = 0
        details_grid.addWidget(self.create_info_label("Subject Name:"), row, 0)
        details_grid.addWidget(self.cn_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Email:"), row, 0)
        details_grid.addWidget(self.email_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Issuer:"), row, 0)
        details_grid.addWidget(self.issuer_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Valid From:"), row, 0)
        details_grid.addWidget(self.valid_from_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Valid To:"), row, 0)
        details_grid.addWidget(self.valid_to_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Serial Number:"), row, 0)
        details_grid.addWidget(self.serial_value, row, 1)
        row += 1

        # V3: show HSMID and local verification flags (optional UI fields)
        details_grid.addWidget(self.create_info_label("HSM ID:"), row, 0)
        details_grid.addWidget(self.hsmid_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Email Verified:"), row, 0)
        details_grid.addWidget(self.email_verified_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Device Bound:"), row, 0)
        details_grid.addWidget(self.device_bound_value, row, 1)
        row += 1

        details_grid.addWidget(self.create_info_label("Activation Consumed:"), row, 0)
        details_grid.addWidget(self.activation_consumed_value, row, 1)
        row += 1

        # --- Renewal Section ---
        self.renewal_status_label = QLabel("Checking certificate status...")
        self.renewal_status_label.setObjectName("secondary_text")
        self.renewal_status_label.setAlignment(Qt.AlignCenter)

        self.renew_button = QPushButton("Renew Certificate")
        self.renew_button.setObjectName("primary")
        self.renew_button.setFixedWidth(200)
        self.renew_button.clicked.connect(self.request_renewal.emit)

        # --- Assemble the Card ---
        card_layout.addWidget(title)
        card_layout.addLayout(details_grid)
        card_layout.addSpacing(20)
        card_layout.addWidget(self.renewal_status_label, alignment=Qt.AlignCenter)
        card_layout.addWidget(self.renew_button, alignment=Qt.AlignCenter)

        main_layout.addWidget(info_card)

    def create_info_label(self, text: str) -> QLabel:
        """Helper function to create styled labels for the grid."""
        label = QLabel(text)
        label.setStyleSheet("font-weight: bold; color: #a0a0a0;")
        return label

    def _bool_chip(self, value: int | bool | None) -> str:
        """
        Returns HTML text for a subtle yes/no indicator that works with existing QSS.
        """
        if value is None:
            return "N/A"
        val = bool(value)
        color = "#28a745" if val else "#dc3545"  # green / red
        text = "Yes" if val else "No"
        return f"<span style='color:{color}'>{text}</span>"

    def set_user_data(self, user_data: dict):
        """
        Populates the page with the user's certificate information and local flags.
        This method should be called after the user logs in.
        """
        cert_details = user_data.get('certificate_details', {})
        subject = cert_details.get('subject', {}) if cert_details else {}
        issuer = cert_details.get('issuer', {}) if cert_details else {}

        # Populate certificate basics
        if not cert_details:
            self.cn_value.setText("<font color='#dc3545'>Not available</font>")
            self.email_value.setText("N/A")
            self.issuer_value.setText("N/A")
            self.valid_from_value.setText("N/A")
            self.valid_to_value.setText("N/A")
            self.serial_value.setText("N/A")
        else:
            self.cn_value.setText(subject.get('commonName', 'N/A'))
            self.email_value.setText(subject.get('emailAddress', 'N/A'))
            self.issuer_value.setText(issuer.get('commonName', 'N/A'))
            self.valid_from_value.setText(cert_details.get('valid_from', 'N/A'))
            self.valid_to_value.setText(cert_details.get('valid_to', 'N/A'))
            self.serial_value.setText(str(cert_details.get('serial_number', 'N/A')))

        # V3 extras: HSMID and local flags from DB
        # Prefer HSMID from user_data; otherwise read from DB cache by email.
        hsm_id = user_data.get('hsm_id')
        email_for_lookup = subject.get('emailAddress') or user_data.get('email')
        flags = None
        if email_for_lookup:
            try:
                row = db_helper.get_user(email_for_lookup)
                if row:
                    flags = {
                        "email_verified": row.get("email_verified"),
                        "device_bound": row.get("device_bound"),
                        "activation_consumed": row.get("activation_consumed"),
                        "hsm_id": row.get("hsm_id")
                    }
            except Exception:
                flags = None

        if not hsm_id and flags and flags.get("hsm_id"):
            hsm_id = flags["hsm_id"]

        self.hsmid_value.setText(hsm_id or "N/A")

        if flags:
            self.email_verified_value.setText(self._bool_chip(flags.get("email_verified")))
            self.device_bound_value.setText(self._bool_chip(flags.get("device_bound")))
            self.activation_consumed_value.setText(self._bool_chip(flags.get("activation_consumed")))
        else:
            self.email_verified_value.setText("N/A")
            self.device_bound_value.setText("N/A")
            self.activation_consumed_value.setText("N/A")

        # Renewal hints based on expiry window (if available)
        expires_in_days = int(cert_details.get('expires_in_days', -1)) if cert_details else -1
        renewal_threshold_days = 30
        if 0 < expires_in_days <= renewal_threshold_days:
            self.renewal_status_label.setText(
                f"<font color='#ffc107'>Your certificate is expiring in {expires_in_days} days.</font>"
            )
            self.renew_button.setEnabled(True)
            self.renew_button.setText("Renew Certificate")
        elif expires_in_days <= 0:
            self.renewal_status_label.setText(
                "<font color='#dc3545'>Your certificate has expired!</font>"
            )
            self.renew_button.setEnabled(True)
            self.renew_button.setText("Request New Certificate")
        else:
            self.renewal_status_label.setText(
                "Your certificate is valid and does not require renewal yet."
            )
            self.renew_button.setEnabled(False)
