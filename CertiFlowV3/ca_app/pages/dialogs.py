# ca_app/pages/dialogs.py

import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ObjectIdentifier
import binascii
import textwrap
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTextEdit, QLineEdit, QDialogButtonBox, QGridLayout, QFrame, QApplication
)
from PySide6.QtCore import Qt

# Configurable private OID carrying HSM provenance (HSMID or metadata)
HSM_PROVENANCE_OID = os.environ.get("CERTIFLOW_HSM_PROV_OID", "1.3.6.1.4.1.55555.1.1")

def _mask_hsmid(hsmid: str) -> str:
    if not hsmid:
        return ""
    if len(hsmid) <= 8:
        return hsmid
    return f"{hsmid[:4]}…{hsmid[-4:]}"


class ViewCsrDialog(QDialog):
    """A dialog to display the details of a Certificate Signing Request."""
    def __init__(self, email, csr_pem, verification_status, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"CSR Details for {email}")
        self.setMinimumWidth(600)

        layout = QVBoxLayout(self)

        # --- Verification Status Section ---
        status_layout = QHBoxLayout()
        status_layout.setSpacing(15)

        def create_status_label(text, is_verified):
            label = QLabel(f"✓ {text}" if is_verified else f"❌ {text}")
            style = "color: #4CAF50; font-weight: bold;" if is_verified else "color: #E57373; font-weight: bold;"
            label.setStyleSheet(style)
            return label

        status_layout.addWidget(create_status_label("HSM Bound", verification_status.get('hsm_bound', False)))
        status_layout.addWidget(create_status_label("HSM Activated", verification_status.get('hsm_activated', False)))
        status_layout.addWidget(create_status_label("Email Verified", verification_status.get('email_verified', False)))
        status_layout.addStretch()

        status_frame = QFrame()
        status_frame.setObjectName("StatusFrame")
        status_frame.setLayout(status_layout)
        layout.addWidget(status_frame)

        # --- Parse CSR and show policy-relevant fields ---
        details_html = ""
        san_info_html = ""
        hsm_oid_html = ""

        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode())
            subj = csr.subject

            cn = subj.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value if subj.get_attributes_for_oid(NameOID.COMMON_NAME) else "N/A"
            org = subj.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value if subj.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) else "N/A"
            country = subj.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value if subj.get_attributes_for_oid(NameOID.COUNTRY_NAME) else "N/A"

            # Key details
            pk = csr.public_key()
            try:
                key_bits = getattr(pk, "key_size", None)
            except Exception:
                key_bits = None

            details_html = (
                f"<b>Applicant Email (request):</b> {email}<br>"
                f"<b>Common Name (CN):</b> {cn}<br>"
                f"<b>Organization (O):</b> {org}<br>"
                f"<b>Country (C):</b> {country}<br>"
                f"<b>Key Size:</b> {key_bits if key_bits else 'N/A'} bits"
            )

            # Subject Alternative Name: show RFC822 emails and check match
            san_emails = []
            try:
                san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                for gn in san:
                    # Only list rfc822Name entries
                    if isinstance(gn, x509.RFC822Name):
                        san_emails.append(gn.value)
            except x509.ExtensionNotFound:
                san_emails = []

            san_list_str = ", ".join(san_emails) if san_emails else "None"
            email_match = any(e.strip().lower() == email.strip().lower() for e in san_emails)

            san_info_html = (
                "<hr>"
                "<b>Subject Alternative Name (SAN):</b><br>"
                f"Email entries: {san_list_str}<br>"
                f"{'<span style=\"color:#4CAF50;font-weight:bold;\">✓ SAN contains applicant email</span>' if email_match else '<span style=\"color:#E57373;font-weight:bold;\">❌ SAN missing applicant email</span>'}"
            )

            # Custom HSM provenance OID (private extension)
            try:
                oid = ObjectIdentifier(HSM_PROVENANCE_OID)
                ext = csr.extensions.get_extension_for_oid(oid)
                # cryptography exposes unknown extensions as UnrecognizedExtension with raw .value bytes
                raw = getattr(ext.value, "value", None)
                decoded = None
                if isinstance(raw, (bytes, bytearray)):
                    # Try UTF-8; else hex
                    try:
                        decoded = raw.decode("utf-8").strip()
                    except Exception:
                        decoded = "0x" + binascii.hexlify(raw).decode()
                else:
                    # Some custom builders may embed a UTF8String directly
                    decoded = str(ext.value)

                masked = _mask_hsmid(decoded) if isinstance(decoded, str) else str(decoded)
                hsm_oid_html = (
                    "<hr>"
                    f"<b>HSM Provenance OID</b> ({HSM_PROVENANCE_OID}): "
                    f"{masked if decoded else 'Present but unreadable'}"
                )
            except x509.ExtensionNotFound:
                hsm_oid_html = (
                    "<hr>"
                    f"<b>HSM Provenance OID</b> ({HSM_PROVENANCE_OID}): "
                    "<span style='color:#E57373;font-weight:bold;'>Not present</span>"
                )

        except Exception as e:
            details_html = f"<b>Applicant Email (request):</b> {email}<br><i>Could not parse CSR details: {e}</i>"

        details_label = QLabel(details_html + san_info_html + hsm_oid_html)
        details_label.setTextFormat(Qt.TextFormat.RichText)
        details_label.setWordWrap(True)
        layout.addWidget(details_label)

        # --- CSR Content ---
        csr_label = QLabel("<b>CSR Content (PEM Format):</b>")
        layout.addWidget(csr_label)

        self.csr_text = QTextEdit()
        self.csr_text.setPlainText(textwrap.dedent(csr_pem).strip())
        self.csr_text.setReadOnly(True)
        self.csr_text.setObjectName("JsonViewer")  # reuse your existing dark style
        layout.addWidget(self.csr_text)

        # --- Buttons ---
        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)


class ConfirmPasswordDialog(QDialog):
    """A secure dialog to ask for the admin's HSM password for a sensitive action."""
    def __init__(self, action_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Admin Confirmation Required")

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        icon_label = QLabel("🔑")
        icon_label.setObjectName("wait_icon")
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_label)

        prompt_label = QLabel(f"To {action_name}, please re-enter your HSM password.")
        prompt_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(prompt_label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Enter HSM Password")
        layout.addWidget(self.password_input)

        self.error_label = QLabel("")
        self.error_label.setObjectName("error_text")
        self.error_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.error_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        ok_button.setText("Confirm")
        ok_button.setObjectName("primary")

        layout.addWidget(button_box)

    def get_password(self):
        return self.password_input.text()


class GetReasonDialog(QDialog):
    """A dialog to get a mandatory reason for an action like revocation."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Reason Required")

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        self.prompt_label = QLabel("Please provide a reason.")
        self.prompt_label.setWordWrap(True)
        layout.addWidget(self.prompt_label)

        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("Enter a reason...")
        layout.addWidget(self.reason_input)

        self.error_label = QLabel("")
        self.error_label.setObjectName("error_text")
        layout.addWidget(self.error_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _validate_and_accept(self):
        if not self.get_reason():
            self.error_label.setText("A reason is required.")
        else:
            self.accept()

    def get_reason(self):
        return self.reason_input.text().strip()


class ChangePasswordDialog(QDialog):
    """A dialog for securely changing the admin's HSM password."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change HSM Password")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        layout.addWidget(QLabel("<b>Current HSM Password:</b>"))
        self.old_password_input = QLineEdit()
        self.old_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.old_password_input)

        layout.addWidget(QLabel("<b>New HSM Password:</b>"))
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.new_password_input)

        layout.addWidget(QLabel("<b>Confirm New Password:</b>"))
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.confirm_password_input)

        self.error_label = QLabel("")
        self.error_label.setObjectName("error_text")
        layout.addWidget(self.error_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)
        ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        ok_button.setText("Confirm Change")
        ok_button.setObjectName("primary")
        layout.addWidget(button_box)

    def _validate_and_accept(self):
        if not self.old_password_input.text():
            self.error_label.setText("Current password is required.")
            return
        if len(self.new_password_input.text()) < 12:
            self.error_label.setText("New password must be at least 12 characters.")
            return
        if self.new_password_input.text() != self.confirm_password_input.text():
            self.error_label.setText("New passwords do not match.")
            return
        self.accept()

    def get_passwords(self):
        return self.old_password_input.text(), self.new_password_input.text()


class ViewCertificateDialog(QDialog):
    """A dialog to display the details of the Root CA certificate."""
    def __init__(self, cert_details, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Root Certificate Details")
        self.setMinimumWidth(600)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        title = QLabel("Root Certificate Information")
        title.setObjectName("h2")
        layout.addWidget(title)

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)

        subject = cert_details.get('subject', {})
        issuer = cert_details.get('issuer', {})

        grid.addWidget(self._create_grid_label("Common Name:"), 0, 0)
        grid.addWidget(QLabel(subject.get('commonName', 'N/A')), 0, 1)

        grid.addWidget(self._create_grid_label("Organization:"), 1, 0)
        grid.addWidget(QLabel(subject.get('organizationName', 'N/A')), 1, 1)

        grid.addWidget(self._create_grid_label("Valid From:"), 2, 0)
        grid.addWidget(QLabel(cert_details.get('valid_from', 'N/A')), 2, 1)

        grid.addWidget(self._create_grid_label("Valid To:"), 3, 0)
        grid.addWidget(QLabel(cert_details.get('valid_to', 'N/A')), 3, 1)

        grid.addWidget(self._create_grid_label("Serial Number:"), 4, 0)
        serial_label = QLabel(str(cert_details.get('serial_number', 'N/A')))
        serial_label.setWordWrap(True)
        grid.addWidget(serial_label, 4, 1)

        layout.addLayout(grid)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _create_grid_label(self, text):
        label = QLabel(text)
        label.setStyleSheet("font-weight: bold; color: #A0A0A0;")
        return label


class BindHsmDialog(QDialog):
    """A dialog to get an email address for binding an HSM."""
    def __init__(self, hsm_id: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Bind HSM to User")
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        prompt = QLabel(f"Please enter the institutional email address to associate with HSM ID:\n<b>{hsm_id}</b>")
        prompt.setWordWrap(True)
        layout.addWidget(prompt)

        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("user.name@institution.edu")
        layout.addWidget(self.email_input)

        self.error_label = QLabel("")
        self.error_label.setObjectName("error_text")
        layout.addWidget(self.error_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        button_box.accepted.connect(self._validate_and_accept)
        button_box.rejected.connect(self.reject)

        ok_button = button_box.button(QDialogButtonBox.StandardButton.Ok)
        ok_button.setText("Confirm Binding")
        ok_button.setObjectName("primary")

        layout.addWidget(button_box)

    def _validate_and_accept(self):
        email = self.get_email()
        if not email or '@' not in email or '.' not in email:
            self.error_label.setText("Please enter a valid email address.")
        else:
            self.accept()

    def get_email(self):
        return self.email_input.text().strip()


class ActivationCodeDialog(QDialog):
    """A user-friendly dialog to display the HSM activation code (one-time view)."""
    def __init__(self, email: str, hsm_id: str, code: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("HSM Binding Successful")
        self.setMinimumWidth(450)

        layout = QVBoxLayout(self)
        layout.setSpacing(15)

        title = QLabel("Activation Code Generated")
        title.setObjectName("h2")
        layout.addWidget(title)

        info_text = (
            f"The HSM device (<b>{hsm_id}</b>) has been successfully bound to <b>{email}</b>.\n"
            "Please provide the following activation code to the user. They will need it to register."
        )
        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        self.code_input = QLineEdit(code)
        self.code_input.setReadOnly(True)
        self.code_input.setObjectName("ActivationCode")

        copy_button = QPushButton("📋 Copy to Clipboard")
        copy_button.setObjectName("secondary")
        copy_button.clicked.connect(self._copy_to_clipboard)

        code_layout = QHBoxLayout()
        code_layout.addWidget(self.code_input)
        code_layout.addWidget(copy_button)
        layout.addLayout(code_layout)

        self.copy_status_label = QLabel("")
        self.copy_status_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        layout.addWidget(self.copy_status_label)

        button_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def _copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.code_input.text())
        self.copy_status_label.setText("Copied!")
