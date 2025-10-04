# user_app/pages/rejection_page.py

import sys
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PySide6.QtCore import Qt, Signal

class RejectionPage(QWidget):
    navigate_to_login = Signal()

    def __init__(self, email: str = "your account"):
        super().__init__()
        self.email = email # Store email to personalize message if needed

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(50, 50, 50, 50)
        layout.setSpacing(20)

        # Logo
        title_text = "Certi<span style='color:#5294e2;'>Flow.</span>"
        logo = QLabel(title_text)
        logo.setObjectName("h1")
        logo.setAlignment(Qt.AlignCenter)

        # Main Message
        message_title = QLabel("Registration Unsuccessful")
        message_title.setObjectName("h2")
        message_title.setAlignment(Qt.AlignCenter)

        # Add an objectName to message_body for findChild method to work
        self.message_body_label = QLabel(
            f"Unfortunately, the Certificate Authority has rejected the registration request for {self.email}. "
            f"This could be due to various reasons, such as incorrect information, or institutional policy."
        )
        self.message_body_label.setObjectName("secondary_text")
        self.message_body_label.setAlignment(Qt.AlignCenter)
        self.message_body_label.setWordWrap(True)

        # Contact Instructions
        contact_info = QLabel(
            "Please contact your IT administrator or the Certificate Authority for more details or to re-submit your request."
        )
        contact_info.setObjectName("secondary_text")
        contact_info.setAlignment(Qt.AlignCenter)
        contact_info.setWordWrap(True)


        # Back to Login Button
        back_button = QPushButton("Back to Login")
        back_button.setObjectName("primary")
        back_button.clicked.connect(self.navigate_to_login.emit)
        back_button.setFixedWidth(200) # Give it a fixed width

        layout.addWidget(logo)
        layout.addSpacing(30)
        layout.addWidget(message_title)
        layout.addWidget(self.message_body_label) # Use the named label here
        layout.addWidget(contact_info)
        layout.addSpacing(30)
        layout.addWidget(back_button, alignment=Qt.AlignCenter)

    def set_email(self, email: str):
        """Allows updating the email after initialization."""
        self.email = email
        # Update the message body to reflect the new email
        # FIX: Use the stored QLael reference instead of findChild for direct access
        self.message_body_label.setText(
            f"Unfortunately, the Certificate Authority has rejected the registration request for {self.email}. "
            f"This could be due to various reasons, such as incorrect information, or institutional policy."
        )
