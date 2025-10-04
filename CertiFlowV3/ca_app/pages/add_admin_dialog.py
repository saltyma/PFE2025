# ca_app/pages/add_admin_dialog.py

import os
import sys
from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QStackedWidget, QFrame,
                               QFileDialog, QProgressBar, QMessageBox, QWidget)
from PySide6.QtCore import Qt, Signal, QThread, QObject

# --- Path setup ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import admin_management_handler


class ProvisioningWorker(QObject):
    """Worker thread to handle the HSM provisioning process."""
    finished = Signal(bool, str)

    def __init__(self, root_hsm_path, root_hsm_password, new_admin_email,
                 new_admin_password, new_hsm_path, performing_admin_id):
        super().__init__()
        self.root_hsm_path = root_hsm_path
        self.root_hsm_password = root_hsm_password
        self.new_admin_email = new_admin_email
        self.new_admin_password = new_admin_password
        self.new_hsm_path = new_hsm_path
        self.performing_admin_id = performing_admin_id

    def run(self):
        success, message = admin_management_handler.provision_new_admin_hsm(
            root_hsm_path=self.root_hsm_path,
            root_hsm_password=self.root_hsm_password,
            new_admin_email=self.new_admin_email,
            new_admin_password=self.new_admin_password,
            new_hsm_path=self.new_hsm_path,
            performing_admin_id=self.performing_admin_id
        )
        self.finished.emit(success, message)


class AddAdminDialog(QDialog):
    """A multi-step wizard for securely adding a new CA administrator."""
    admin_added_successfully = Signal()

    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.setWindowTitle("Add New CA Administrator")
        self.setMinimumSize(550, 450)
        self.setModal(True)

        # --- Data storage for the wizard ---
        self.new_admin_data = {}
        self.worker_thread = None
        self.worker = None

        # --- Main Layout ---
        main_layout = QVBoxLayout(self)
        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)

        # --- Create and add pages to the wizard ---
        self.stack.addWidget(self._create_step_1_credentials())   # index 0
        self.stack.addWidget(self._create_step_2_hsm_selection()) # index 1
        self.stack.addWidget(self._create_step_3_root_auth())     # index 2
        self.stack.addWidget(self._create_step_4_summary())       # index 3
        self.stack.addWidget(self._create_step_5_progress())      # index 4

    # --- Wizard Page Creation Methods ---

    def _create_step_1_credentials(self):
        page = QWidget()
        layout = self._create_wizard_page_layout(
            page, "Step 1 of 4: New Administrator Credentials",
            "Enter the email and a temporary password for the new administrator. "
            "This password must be shared with them securely."
        )

        self.new_email_input = QLineEdit()
        self.new_email_input.setPlaceholderText("Enter new admin's email")
        self.new_password_input = QLineEdit()
        self.new_password_input.setPlaceholderText("Create temporary password")
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm temporary password")
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)

        layout.addWidget(QLabel("New Admin Email:"))
        layout.addWidget(self.new_email_input)
        layout.addSpacing(10)
        layout.addWidget(QLabel("Temporary Password:"))
        layout.addWidget(self.new_password_input)
        layout.addWidget(self.confirm_password_input)
        layout.addStretch()
        layout.addLayout(self._create_nav_buttons(next_slot=self._validate_step_1))
        return page

    def _create_step_2_hsm_selection(self):
        page = QWidget()
        layout = self._create_wizard_page_layout(
            page, "Step 2 of 4: Prepare New HSM Drive",
            "Insert the new administrator's blank USB drive and select its location."
        )
        self.new_hsm_path_input = QLineEdit()
        self.new_hsm_path_input.setPlaceholderText("No drive selected")
        self.new_hsm_path_input.setReadOnly(True)
        browse_button = QPushButton("Browse...")
        browse_button.setObjectName("secondary")
        browse_button.clicked.connect(self._browse_for_hsm)

        hsm_layout = QHBoxLayout()
        hsm_layout.addWidget(self.new_hsm_path_input)
        hsm_layout.addWidget(browse_button)

        layout.addLayout(hsm_layout)
        layout.addStretch()
        layout.addLayout(self._create_nav_buttons(prev_slot=lambda: self.stack.setCurrentIndex(0),
                                                  next_slot=self._validate_step_2))
        return page

    def _create_step_3_root_auth(self):
        page = QWidget()
        layout = self._create_wizard_page_layout(
            page, "Step 3 of 4: Authorize Action",
            "To proceed, please enter your (root admin) password to authorize this sensitive action."
        )
        self.root_password_input = QLineEdit()
        self.root_password_input.setPlaceholderText("Enter your root admin password")
        self.root_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.root_password_input)
        layout.addStretch()
        layout.addLayout(self._create_nav_buttons(prev_slot=lambda: self.stack.setCurrentIndex(1),
                                                  next_slot=self._validate_step_3))
        return page

    def _create_step_4_summary(self):
        page = QWidget()
        layout = self._create_wizard_page_layout(
            page, "Step 4 of 4: Final Confirmation",
            "Review the details below. This action is irreversible."
        )
        self.summary_email_label = QLabel()
        self.summary_hsm_label = QLabel()
        self.summary_email_label.setObjectName("SummaryLabel")
        self.summary_hsm_label.setObjectName("SummaryLabel")

        warning_label = QLabel("⚠️ This will format the selected drive and create a new administrator account.")
        warning_label.setWordWrap(True)

        layout.addWidget(self.summary_email_label)
        layout.addWidget(self.summary_hsm_label)
        layout.addSpacing(20)
        layout.addWidget(warning_label)
        layout.addStretch()
        layout.addLayout(self._create_nav_buttons(prev_slot=lambda: self.stack.setCurrentIndex(2),
                                                  next_text="Create & Add Admin",
                                                  next_slot=self._start_provisioning))
        return page

    def _create_step_5_progress(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)

        self.progress_title = QLabel("Provisioning HSM...")
        self.progress_title.setObjectName("h2")

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Indeterminate progress

        self.progress_details = QLabel("This may take a moment...")
        self.progress_details.setObjectName("secondary_text")
        self.progress_details.setWordWrap(True)

        # Retry/Back controls shown only on failure
        btn_row = QHBoxLayout()
        btn_row.setSpacing(12)
        self.progress_back_btn = QPushButton("Back to Summary")
        self.progress_back_btn.setObjectName("secondary")
        self.progress_back_btn.setVisible(False)
        self.progress_back_btn.clicked.connect(self._back_to_summary_from_progress)

        self.progress_retry_btn = QPushButton("Retry Provisioning")
        self.progress_retry_btn.setObjectName("primary")
        self.progress_retry_btn.setVisible(False)
        self.progress_retry_btn.clicked.connect(self._retry_provisioning)

        btn_row.addWidget(self.progress_back_btn)
        btn_row.addWidget(self.progress_retry_btn)

        layout.addWidget(self.progress_title, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.progress_bar)
        layout.addWidget(self.progress_details, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addLayout(btn_row)
        return page

    # --- Helper and Validation Methods ---

    def _create_wizard_page_layout(self, parent_widget, title, subtitle):
        """Helper to create a consistent layout for each wizard page."""
        frame = QFrame(parent_widget)
        frame.setObjectName("WizardFrame")
        layout = QVBoxLayout(frame)
        layout.setSpacing(15)

        step_label = QLabel(title)
        step_label.setObjectName("StepLabel")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("SubtitleLabel")
        subtitle_label.setWordWrap(True)

        layout.addWidget(step_label)
        layout.addWidget(subtitle_label)
        layout.addSpacing(20)

        # Main layout to center the frame
        main_layout = QVBoxLayout(parent_widget)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(frame)
        return layout

    def _create_nav_buttons(self, prev_slot=None, next_slot=None, next_text="Next"):
        """Helper to create navigation buttons for the wizard."""
        nav_layout = QHBoxLayout()
        self.error_label = QLabel()
        self.error_label.setObjectName("ErrorLabel")

        prev_button = QPushButton("Back")
        prev_button.setObjectName("secondary")
        if prev_slot:
            prev_button.clicked.connect(prev_slot)
        else:
            prev_button.setVisible(False)

        next_button = QPushButton(next_text)
        next_button.setObjectName("primary")
        if next_slot:
            next_button.clicked.connect(next_slot)

        nav_layout.addWidget(self.error_label)
        nav_layout.addStretch()
        nav_layout.addWidget(prev_button)
        nav_layout.addWidget(next_button)
        return nav_layout

    def _show_error(self, message):
        self.error_label.setText(message)

    def _validate_step_1(self):
        email = self.new_email_input.text().strip()
        pwd = self.new_password_input.text()
        confirm_pwd = self.confirm_password_input.text()

        if not email or '@' not in email:
            return self._show_error("Invalid email address.")
        if len(pwd) < 12:
            return self._show_error("Password must be at least 12 characters.")
        if pwd != confirm_pwd:
            return self._show_error("Passwords do not match.")

        self.new_admin_data['email'] = email
        self.new_admin_data['password'] = pwd
        self._show_error("")
        self.stack.setCurrentIndex(1)

    def _browse_for_hsm(self):
        directory = QFileDialog.getExistingDirectory(self, "Select New Admin's USB Drive")
        if directory:
            self.new_hsm_path_input.setText(directory)

    def _validate_step_2(self):
        path = self.new_hsm_path_input.text()
        if not path or not os.path.isdir(path):
            return self._show_error("Please select a valid drive.")
        if self.main_window.hsm_path and path == self.main_window.hsm_path:
            return self._show_error("Cannot use the same drive as the root admin.")

        self.new_admin_data['hsm_path'] = path
        self._show_error("")
        self.stack.setCurrentIndex(2)

    def _validate_step_3(self):
        pwd = self.root_password_input.text()
        if not pwd:
            return self._show_error("Root password is required.")

        self.new_admin_data['root_password'] = pwd
        self._show_error("")
        # Update summary before showing
        self.summary_email_label.setText(f"<b>New Admin Email:</b> {self.new_admin_data['email']}")
        self.summary_hsm_label.setText(f"<b>Target Drive:</b> {self.new_admin_data['hsm_path']}")
        self.stack.setCurrentIndex(3)

    # --- Provisioning orchestration ---

    def _start_provisioning(self):
        self.stack.setCurrentIndex(4)  # Switch to progress page
        self._set_progress_ui(running=True, title="Provisioning HSM...",
                              details="This may take a moment...")

        # Start worker with the currently captured inputs
        self._launch_worker()

    def _retry_provisioning(self):
        # Keep user on the progress page and restart the worker
        self._set_progress_ui(running=True, title="Retrying...",
                              details="Attempting provisioning again...")
        self._launch_worker()

    def _launch_worker(self):
        # Ensure any previous thread is fully cleaned up
        self._teardown_worker()

        self.worker_thread = QThread()
        self.worker = ProvisioningWorker(
            root_hsm_path=self.main_window.hsm_path,
            root_hsm_password=self.new_admin_data['root_password'],
            new_admin_email=self.new_admin_data['email'],
            new_admin_password=self.new_admin_data['password'],
            new_hsm_path=self.new_admin_data['hsm_path'],
            performing_admin_id=self.main_window.current_admin['id']
        )
        self.worker.moveToThread(self.worker_thread)
        self.worker_thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_provisioning_finished)
        self.worker_thread.start()

    def _on_provisioning_finished(self, success, message):
        # Stop the spinner regardless of result
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)

        if success:
            self.progress_title.setText("Success!")
            self.progress_details.setText(message)
            self.admin_added_successfully.emit()
            QMessageBox.information(self, "Success", message)
            self._teardown_worker()
            self.accept()  # Close the dialog
        else:
            # Keep the dialog open on the progress page with exact error, allow retry/back
            self.progress_title.setText("Provisioning Failed")
            self.progress_details.setText(message)
            self.progress_back_btn.setVisible(True)
            self.progress_retry_btn.setVisible(True)
            QMessageBox.critical(self, "Error", message)
            self._teardown_worker()

    def _back_to_summary_from_progress(self):
        # Let the admin adjust inputs and try again
        self.stack.setCurrentIndex(3)

    def _set_progress_ui(self, running: bool, title: str, details: str):
        self.progress_title.setText(title)
        self.progress_details.setText(details)
        if running:
            self.progress_bar.setRange(0, 0)  # Indeterminate
            self.progress_back_btn.setVisible(False)
            self.progress_retry_btn.setVisible(False)
        else:
            self.progress_bar.setRange(0, 1)
            self.progress_bar.setValue(1)

    def _teardown_worker(self):
        if self.worker_thread:
            try:
                if self.worker_thread.isRunning():
                    self.worker_thread.quit()
                    self.worker_thread.wait()
            except Exception:
                pass
        self.worker_thread = None
        self.worker = None
