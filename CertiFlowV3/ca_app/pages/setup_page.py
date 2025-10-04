# A wizard for the first-time root admin to generate keys and the root CA certificate.
# ca_app/pages/setup_page.py

import os
import sys
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QPushButton, QFileDialog, QStackedWidget,
                               QFrame, QApplication)
from PySide6.QtCore import Qt, Signal

# --- Path setup ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import setup_handler
from ca_app import ca_db_helper

class SetupPage(QWidget):
    """A multi-step wizard for the initial setup of the Root CA."""
    setup_complete = Signal(dict)
    setup_failed = Signal(str)  # new: propagate exact failure text to parent

    def __init__(self):
        super().__init__()
        
        main_layout = QVBoxLayout(self)
        main_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.stack = QStackedWidget()
        main_layout.addWidget(self.stack)

        # Create and add pages to the stack
        self.create_welcome_page()
        self.create_credentials_page()
        self.create_hsm_page()
        self.create_summary_page()
        self.create_progress_page()

    def create_welcome_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(15)
        
        title = QLabel("Welcome to CertiFlow")
        title.setObjectName("h1")
        
        intro = QLabel(
            "This is the one-time setup process to create your Root Certificate Authority.\n"
            "This will generate your master cryptographic keys and the first root administrator account."
        )
        intro.setObjectName("secondary_text")
        intro.setWordWrap(True)
        intro.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        next_button = QPushButton("Begin Setup")
        next_button.setObjectName("primary")
        next_button.setFixedWidth(200)
        next_button.clicked.connect(lambda: self.stack.setCurrentIndex(1))

        layout.addWidget(title, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addSpacing(20)
        layout.addWidget(intro)
        layout.addSpacing(40)
        layout.addWidget(next_button, alignment=Qt.AlignmentFlag.AlignCenter)
        
        self.stack.addWidget(page)

    def create_credentials_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        frame = QFrame()
        frame.setMaximumWidth(450)
        frame_layout = QVBoxLayout(frame)
        frame_layout.setSpacing(10)
        
        title = QLabel("Step 1: Create Root Administrator")
        title.setObjectName("h2")
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter Root Admin Email")
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Create a Strong HSM Password")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setPlaceholderText("Confirm HSM Password")
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.cred_error_label = QLabel("")
        self.cred_error_label.setObjectName("error_text")
        
        next_button = QPushButton("Next")
        next_button.setObjectName("primary")
        next_button.clicked.connect(self._validate_credentials)
        
        frame_layout.addWidget(title)
        frame_layout.addSpacing(20)
        frame_layout.addWidget(QLabel("Administrator Email:"))
        frame_layout.addWidget(self.email_input)
        frame_layout.addSpacing(15)
        frame_layout.addWidget(QLabel("HSM Encryption Password:"))
        frame_layout.addWidget(self.password_input)
        frame_layout.addWidget(self.confirm_password_input)
        frame_layout.addWidget(self.cred_error_label)
        frame_layout.addSpacing(20)
        frame_layout.addWidget(next_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addWidget(frame)
        self.stack.addWidget(page)

    def _validate_credentials(self):
        email = self.email_input.text()
        password = self.password_input.text()
        confirm = self.confirm_password_input.text()
        if not email or '@' not in email:
            self.cred_error_label.setText("Please enter a valid email address.")
            return
        if len(password) < 12:
            self.cred_error_label.setText("Password must be at least 12 characters.")
            return
        if password != confirm:
            self.cred_error_label.setText("Passwords do not match.")
            return
        self.stack.setCurrentIndex(2)

    def create_hsm_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        frame = QFrame()
        frame.setMaximumWidth(450)
        frame_layout = QVBoxLayout(frame)
        
        title = QLabel("Step 2: Select Secure Drive (HSM)")
        title.setObjectName("h2")
        
        self.hsm_path_input = QLineEdit()
        self.hsm_path_input.setPlaceholderText("Select your secure USB drive")
        self.hsm_path_input.setReadOnly(True)
        
        browse_button = QPushButton("Browse...")
        browse_button.setObjectName("secondary")
        browse_button.clicked.connect(self._browse_for_hsm)
        
        self.hsm_error_label = QLabel("")
        self.hsm_error_label.setObjectName("error_text")
        
        next_button = QPushButton("Next")
        next_button.setObjectName("primary")
        next_button.clicked.connect(self._validate_hsm_path)
        
        frame_layout.addWidget(title)
        frame_layout.addSpacing(20)
        frame_layout.addWidget(QLabel("Select the root of your USB drive:"))
        hsm_layout = QHBoxLayout()
        hsm_layout.addWidget(self.hsm_path_input)
        hsm_layout.addWidget(browse_button)
        frame_layout.addLayout(hsm_layout)
        frame_layout.addWidget(self.hsm_error_label)
        frame_layout.addSpacing(20)
        frame_layout.addWidget(next_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addWidget(frame)
        self.stack.addWidget(page)

    def _browse_for_hsm(self):
        directory = QFileDialog.getExistingDirectory(self, "Select HSM Drive")
        if directory:
            self.hsm_path_input.setText(directory)

    def _validate_hsm_path(self):
        path = self.hsm_path_input.text()
        if not path or not os.path.isdir(path):
            self.hsm_error_label.setText("Please select a valid directory.")
            return
        if os.listdir(path):
            self.hsm_error_label.setText("Warning: Selected drive is not empty.")
        # Update summary and move to next page
        self.summary_email.setText(f"<b>Admin Email:</b> {self.email_input.text()}")
        self.summary_hsm.setText(f"<b>HSM Path:</b> {self.hsm_path_input.text()}")
        self.stack.setCurrentIndex(3)

    def create_summary_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        frame = QFrame()
        frame.setMaximumWidth(450)
        frame_layout = QVBoxLayout(frame)
        
        title = QLabel("Step 3: Confirmation")
        title.setObjectName("h2")
        
        self.summary_email = QLabel()
        self.summary_hsm = QLabel()
        
        warning = QLabel(
            "This action is irreversible and will initialize the entire system. "
            "Ensure the selected drive is correct."
        )
        warning.setWordWrap(True)
        warning.setObjectName("secondary_text")
        
        finish_button = QPushButton("Initialize System")
        finish_button.setObjectName("primary")
        finish_button.clicked.connect(self._run_setup)
        
        frame_layout.addWidget(title)
        frame_layout.addSpacing(20)
        frame_layout.addWidget(self.summary_email)
        frame_layout.addWidget(self.summary_hsm)
        frame_layout.addSpacing(20)
        frame_layout.addWidget(warning)
        frame_layout.addSpacing(20)
        frame_layout.addWidget(finish_button, alignment=Qt.AlignmentFlag.AlignRight)
        
        layout.addWidget(frame)
        self.stack.addWidget(page)

    def create_progress_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(20)
        
        self.progress_label = QLabel("Initializing System...")
        self.progress_label.setObjectName("h2")
        
        self.progress_details = QLabel("Generating ECC key...")
        self.progress_details.setObjectName("secondary_text")

        self.finish_button = QPushButton("Finish")
        self.finish_button.setObjectName("primary")
        self.finish_button.setVisible(False)
        self.finish_button.clicked.connect(self._on_finish)
        
        layout.addWidget(self.progress_label)
        layout.addWidget(self.progress_details)
        layout.addWidget(self.finish_button)

        self.stack.addWidget(page)

    def _run_setup(self):
        self.stack.setCurrentIndex(4) # Switch to progress page
        QApplication.processEvents() # Ensure UI updates

        email = self.email_input.text()
        password = self.password_input.text()
        hsm_path = self.hsm_path_input.text()

        # --- THIS IS THE FIX ---
        # The org_details argument was removed from the handler, so we remove it here.
        success, message = setup_handler.initialize_root_ca(
            email, password, hsm_path
        )
        # --- END OF FIX ---
        
        if success:
            self.progress_label.setText("Setup Complete!")
            self.progress_details.setText(message)
            self.finish_button.setVisible(True)
        else:
            self.progress_label.setText("Setup Failed!")
            self.progress_details.setText(message)
            self.setup_failed.emit(message)
    
    def _on_finish(self):
        # After a successful setup, we need to log in the new admin.
        # We can simulate this by fetching their details from the DB.
        admin_data = ca_db_helper.get_admin(self.email_input.text())
        if admin_data:
            self.setup_complete.emit(admin_data)
