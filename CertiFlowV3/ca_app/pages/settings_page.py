# ca_app/pages/settings_page.py

import os
import sys
import json
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QFrame,
                               QFileDialog, QMessageBox, QScrollArea, QPushButton)
from PySide6.QtCore import Qt

# --- Path setup and necessary imports ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import backup_handler, auth_handler, certificate_handler
from ca_app.pages.dialogs import ConfirmPasswordDialog, ChangePasswordDialog, ViewCertificateDialog

class SettingsPage(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window

        # Main layout for the entire page (Title + Scroll Area)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(32, 32, 32, 32)
        main_layout.setSpacing(20)

        # 1. Title
        title = QLabel("System Settings")
        title.setObjectName("h1")
        main_layout.addWidget(title)

        # 2. Scroll Area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setObjectName("SettingsScrollArea")

        # 3. Scrollable content
        self.scroll_content_widget = QWidget()
        self.scroll_content_widget.setObjectName("SettingsScrollContent")
        self.content_layout = QVBoxLayout(self.scroll_content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(20)
        self.content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Email configuration warning banner (hidden by default)
        self.email_warn = QLabel("")
        self.email_warn.setStyleSheet("color: #E57373; font-weight: bold;")
        self.email_warn.setVisible(False)
        self.content_layout.addWidget(self.email_warn)

        # --- Account Management Section ---
        account_card = self._create_settings_card("Account Management")
        account_layout = account_card.layout()
        account_layout.addWidget(QLabel("Securely change the password for your HSM keystore."))
        self.change_password_button = QPushButton("Change HSM Password")
        self.change_password_button.setObjectName("primary")
        account_layout.addWidget(self.change_password_button)
        self.content_layout.addWidget(account_card)

        # --- System & Data Management Section ---
        system_card = self._create_settings_card("System & Data Management")
        system_layout = system_card.layout()
        system_layout.addWidget(QLabel("Create or restore a secure database backup."))
        backup_button = QPushButton("Create Database Backup")
        backup_button.setObjectName("secondary")
        system_layout.addWidget(backup_button)
        restore_warning_label = QLabel("⚠️ This action is irreversible and will overwrite all current data.")
        restore_warning_label.setStyleSheet("color: #E57373; font-weight: bold;")
        system_layout.addWidget(restore_warning_label)
        restore_button = QPushButton("Restore from Backup")
        restore_button.setObjectName("danger")
        system_layout.addWidget(restore_button)
        line = self._create_separator()
        system_layout.addWidget(line)
        system_layout.addWidget(QLabel("View details of the root CA certificate."))
        view_cert_button = QPushButton("View Root Certificate")
        view_cert_button.setObjectName("secondary")
        system_layout.addWidget(view_cert_button)
        self.content_layout.addWidget(system_card)

        self.content_layout.addStretch()

        scroll_area.setWidget(self.scroll_content_widget)
        main_layout.addWidget(scroll_area)

        # Connections
        self.change_password_button.clicked.connect(self._on_change_password)
        backup_button.clicked.connect(self._on_create_backup)
        restore_button.clicked.connect(self._on_restore_backup)
        view_cert_button.clicked.connect(self._on_view_certificate)

    def _create_settings_card(self, title_text):
        card = QFrame()
        card.setObjectName("SettingsCard")
        layout = QVBoxLayout(card)
        layout.setSpacing(10)
        title = QLabel(title_text)
        title.setObjectName("h2")
        layout.addWidget(title)
        layout.addWidget(self._create_separator())
        return card

    def _create_separator(self):
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        line.setStyleSheet("background-color: #3A3A3A;")
        return line

    # ---------------- Email configuration check (config.json) ----------------
    def _email_config_missing(self) -> tuple[bool, str]:
        """
        Check ca_app/config.json for the required settings:
          - sender_email
          - app_password
          - token_secret
        Optionally:
          - api_base_url (used for links; defaults internally if absent)
        Returns (missing, message).
        """
        cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config.json"))
        if not os.path.exists(cfg_path):
            return True, ("⚠️ Email verification is not configured. Missing file: "
                          f"{cfg_path}. Verification emails will not be sent.")

        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            return True, ("⚠️ Email verification is not configured. "
                          f"Could not parse {cfg_path}. Verification emails will not be sent.")

        required = ["sender_email", "app_password", "token_secret"]
        missing_keys = [k for k in required if not str(cfg.get(k, "")).strip()]
        if missing_keys:
            return True, ("⚠️ Email verification is not configured. Missing keys in config.json: "
                          + ", ".join(missing_keys)
                          + ". Verification emails will not be sent.")

        # All good
        return False, ""

    # ---------------- Actions ----------------
    def _on_change_password(self):
        if not self.main_window.current_admin or not self.main_window.hsm_path:
            QMessageBox.critical(self, "Error", "Cannot change password. Admin session is invalid.")
            return
        dialog = ChangePasswordDialog(self)
        if not dialog.exec():
            return
        old_pwd, new_pwd = dialog.get_passwords()
        admin_id = self.main_window.current_admin['id']
        hsm_path = self.main_window.hsm_path
        success, message = auth_handler.change_admin_password(admin_id, hsm_path, old_pwd, new_pwd)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Failed", message)

    def _on_create_backup(self):
        if not self.main_window.current_admin:
            QMessageBox.critical(self, "Error", "Authentication error. Please log in again.")
            return
        backup_dir = QFileDialog.getExistingDirectory(self, "Select Backup Location")
        if not backup_dir:
            return
        admin_id = self.main_window.current_admin['id']
        success, message = backup_handler.create_backup(backup_dir, admin_id)
        if success:
            QMessageBox.information(self, "Backup Successful", message)
        else:
            QMessageBox.critical(self, "Backup Failed", message)

    def _on_restore_backup(self):
        if not self.main_window.current_admin:
            QMessageBox.critical(self, "Error", "Authentication error. Please log in again.")
            return
        backup_file, _ = QFileDialog.getOpenFileName(self, "Select Backup File to Restore", "", "SQLite Files (*.sqlite)")
        if not backup_file:
            return
        confirm_msg = (f"You are about to overwrite the entire database with the contents of:\n\n"
                       f"{os.path.basename(backup_file)}\n\n"
                       f"This action is irreversible. Are you absolutely sure?")
        reply = QMessageBox.warning(self, "Confirm Restore", confirm_msg,
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
        if reply != QMessageBox.StandardButton.Yes:
            return
        pass_dialog = ConfirmPasswordDialog("authorize this destructive restore operation", self)
        if not pass_dialog.exec():
            return
        admin_id = self.main_window.current_admin['id']
        success, message = backup_handler.restore_from_backup(backup_file, admin_id)
        if success:
            QMessageBox.information(self, "Restore Successful", f"{message}\nThe application will now restart.")
            self.main_window.close()
        else:
            QMessageBox.critical(self, "Restore Failed", message)

    def _on_view_certificate(self):
        details, error = certificate_handler.get_root_certificate_details()
        if error:
            QMessageBox.critical(self, "Error", error)
            return
        dialog = ViewCertificateDialog(details, self)
        dialog.exec()

    def showEvent(self, event):
        """Refresh the email configuration banner each time the page becomes visible."""
        super().showEvent(event)
        missing, msg = self._email_config_missing()
        self.email_warn.setText(msg if missing else "")
        self.email_warn.setVisible(missing)
