# user_app/pages/verification_result_dialog.py

import sys
from PySide6.QtWidgets import (QApplication, QDialog, QVBoxLayout, QHBoxLayout, 
                               QLabel, QPushButton, QFrame, QGridLayout, QSpacerItem, QSizePolicy)
from PySide6.QtCore import Qt

class VerificationResultDialog(QDialog):
    """
    A custom, styled dialog to display the results of a signature verification.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Verification Result")
        self.setMinimumWidth(450)
        self.setModal(True) # Blocks interaction with the main window

        # Main layout
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(15)

        # --- Icon and Title ---
        header_layout = QHBoxLayout()
        self.icon_label = QLabel()
        self.icon_label.setObjectName("result_icon")
        
        self.title_label = QLabel("Verification Status")
        self.title_label.setObjectName("h2")

        header_layout.addWidget(self.icon_label)
        header_layout.addSpacing(15)
        header_layout.addWidget(self.title_label)
        header_layout.addStretch()

        # --- Details Frame ---
        details_frame = QFrame()
        details_frame.setObjectName("details_frame")
        details_grid = QGridLayout(details_frame)
        details_grid.setSpacing(10)
        details_grid.setColumnStretch(1, 1)

        self.signer_label = QLabel("...")
        self.timestamp_label = QLabel("...")
        self.status_label = QLabel("...")
        self.details_label = QLabel("...")
        self.details_label.setWordWrap(True)

        details_grid.addWidget(QLabel("Signed By:"), 0, 0)
        details_grid.addWidget(self.signer_label, 0, 1)
        details_grid.addWidget(QLabel("Timestamp (UTC):"), 1, 0)
        details_grid.addWidget(self.timestamp_label, 1, 1)
        details_grid.addWidget(QLabel("Signature Status:"), 2, 0)
        details_grid.addWidget(self.status_label, 2, 1)
        details_grid.addWidget(QLabel("Details:"), 3, 0)
        details_grid.addWidget(self.details_label, 3, 1)

        # --- Close Button ---
        self.ok_button = QPushButton("OK")
        self.ok_button.setObjectName("primary")
        self.ok_button.setFixedWidth(120)
        self.ok_button.clicked.connect(self.accept)

        # --- Assemble Layout ---
        main_layout.addLayout(header_layout)
        main_layout.addWidget(details_frame)
        main_layout.addSpacing(10)
        main_layout.addWidget(self.ok_button, alignment=Qt.AlignCenter)

    def set_result(self, success: bool, message: str):
        """
        Configures the dialog's content based on the verification outcome.
        """
        if success:
            self.icon_label.setText("✅")
            self.icon_label.setStyleSheet("color: #28a745;")
            self.title_label.setText("Signature Valid")
            
            # Parse the success message
            lines = message.split('\n')
            self.status_label.setText("<b style='color:#28a745;'>Authentic</b>")
            self.signer_label.setText("N/A")
            self.timestamp_label.setText("N/A")
            self.details_label.setText("The signature has been successfully verified.")

            for line in lines:
                if "Signed by:" in line:
                    self.signer_label.setText(line.split(":", 1)[1].strip())
                elif "Timestamp (UTC):" in line:
                    self.timestamp_label.setText(line.split(":", 1)[1].strip())
        else:
            self.icon_label.setText("❌")
            self.icon_label.setStyleSheet("color: #dc3545;")
            self.title_label.setText("Signature Invalid")

            self.status_label.setText("<b style='color:#dc3545;'>Not Authentic</b>")
            self.signer_label.setText("Unknown")
            self.timestamp_label.setText("N/A")
            self.details_label.setText(message.split('\n', 1)[-1].strip())