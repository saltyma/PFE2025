# user_app/pages/view_documents_page.py

import os
import subprocess
import sys
from datetime import datetime # <-- FIX: Import the datetime class
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QScrollArea, QFrame, 
                               QHBoxLayout, QPushButton, QGridLayout, QFileDialog)
from PySide6.QtCore import Qt, QEvent

# --- Add db_helper and the new dialog to the path ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import db_helper
from pages.file_not_found_dialog import FileNotFoundDialog

class DocumentItemWidget(QFrame):
    """A redesigned, responsive, and interactive card for each document."""
    def __init__(self, doc_info: dict, parent_page, parent=None):
        super().__init__(parent)
        self.doc_info = doc_info
        self.parent_page = parent_page # To signal a refresh
        self.setObjectName("document_card")
        self.setCursor(Qt.PointingHandCursor)

        # Layouts
        main_layout = QGridLayout(self)
        main_layout.setContentsMargins(20, 15, 20, 15)
        main_layout.setColumnStretch(1, 1) # Allow details column to expand

        # --- Column 0: Icon ---
        # --- FIX: Set the icon text directly. QSS pseudo-elements are unreliable. ---
        icon = QLabel("📄") 
        icon.setObjectName("file_icon")
        
        # --- Column 1: Details ---
        details_layout = QVBoxLayout()
        filename = QLabel(doc_info.get("original_filename", "Unknown File"))
        filename.setObjectName("filename_label")
        
        # Format the timestamp nicely
        timestamp_str = doc_info.get('timestamp', 'N/A')
        try:
            # Attempt to parse and reformat for better readability
            dt_obj = datetime.fromisoformat(timestamp_str.replace(" ", "T"))
            formatted_time = dt_obj.strftime('%d %b %Y, %H:%M:%S')
            timestamp = QLabel(f"Signed: {formatted_time} UTC")
        except (ValueError, AttributeError):
            timestamp = QLabel(f"Signed: {timestamp_str[:19]} UTC") # Fallback
        
        timestamp.setObjectName("timestamp_label")
        details_layout.addWidget(filename)
        details_layout.addWidget(timestamp)

        # --- Column 2: Signer Email ---
        # --- FIX: Use the 'user_email' key from the updated db_helper query ---
        signer_email = QLabel(doc_info.get("user_email", "No email found"))
        signer_email.setObjectName("email_label")

        # Assemble Grid
        main_layout.addWidget(icon, 0, 0, 2, 1, Qt.AlignTop)
        main_layout.addLayout(details_layout, 0, 1, 2, 1)
        main_layout.addWidget(signer_email, 0, 2, 2, 1, Qt.AlignRight | Qt.AlignVCenter)

    def mousePressEvent(self, event: QEvent):
        """Make the entire card clickable."""
        if event.button() == Qt.LeftButton:
            self.handle_open_location()
        super().mousePressEvent(event)

    def handle_open_location(self):
        filepath = self.doc_info.get("signed_filepath")
        if filepath and os.path.exists(filepath):
            directory = os.path.dirname(filepath)
            if sys.platform == 'win32':
                os.startfile(directory)
            elif sys.platform == 'darwin':
                subprocess.Popen(['open', directory])
            else:
                subprocess.Popen(['xdg-open', directory])
        else:
            # File not found, launch the dialog
            dialog = FileNotFoundDialog(self.doc_info.get("original_filename"), self)
            dialog.exec()

            if dialog.result == "remove":
                db_helper.delete_signed_document(self.doc_info["id"])
                self.parent_page.load_document_history() # Refresh the list
            elif dialog.result == "relocate":
                db_helper.update_document_path(self.doc_info["id"], dialog.new_path)
                self.doc_info["signed_filepath"] = dialog.new_path # Update in memory
                self.handle_open_location() # Try opening again

class ViewDocumentsPage(QWidget):
    def __init__(self):
        super().__init__()
        self.current_user_email = None
        self.current_user_data = {}

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 40, 40, 40)
        main_layout.setSpacing(20)

        header_layout = QHBoxLayout()
        title = QLabel("Signed Document History")
        title.setObjectName("h2")
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setObjectName("secondary")
        self.refresh_button.setFixedWidth(100)
        self.refresh_button.clicked.connect(self.load_document_history)
        header_layout.addWidget(self.refresh_button)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setObjectName("document_scroll_area")

        # --- FIX: Set an object name on the container for specific styling ---
        self.scroll_content = QWidget()
        self.scroll_content.setObjectName("scroll_content")

        self.list_layout = QVBoxLayout(self.scroll_content)
        self.list_layout.setContentsMargins(10, 10, 10, 10)
        self.list_layout.setSpacing(10)
        self.list_layout.setAlignment(Qt.AlignTop)
        scroll_area.setWidget(self.scroll_content)

        main_layout.addLayout(header_layout)
        main_layout.addWidget(scroll_area)

    def set_current_user(self, user_data: dict):
        self.current_user_data = user_data
        self.current_user_email = user_data.get('email')

    def load_documents(self, email: str):
        self.current_user_email = email
        self.load_document_history()

    def showEvent(self, event):
        """Reloads documents every time the page becomes visible."""
        self.load_document_history()
        super().showEvent(event)

    def load_document_history(self):
        # Clear existing widgets
        while self.list_layout.count():
            child = self.list_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        if not self.current_user_email:
            # This can happen if the page is loaded before user data is set
            no_user_label = QLabel("Could not load documents. User not identified.")
            no_user_label.setObjectName("secondary_text")
            no_user_label.setAlignment(Qt.AlignCenter)
            self.list_layout.addWidget(no_user_label)
            return

        documents = db_helper.get_signed_documents_for_user(self.current_user_email)

        if not documents:
            no_docs_label = QLabel("You haven't signed any documents yet.")
            no_docs_label.setObjectName("secondary_text")
            no_docs_label.setAlignment(Qt.AlignCenter)
            self.list_layout.addWidget(no_docs_label)
        else:
            for doc in documents:
                item_widget = DocumentItemWidget(doc, self)
                self.list_layout.addWidget(item_widget)

