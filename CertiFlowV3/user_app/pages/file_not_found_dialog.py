# user_app/pages/file_not_found_dialog.py

from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout, QFileDialog
from PySide6.QtCore import Qt

class FileNotFoundDialog(QDialog):
    """
    A dialog that prompts the user what to do when a document's path is invalid.
    Returns 'remove', 'relocate', or None.
    """
    def __init__(self, filename, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Not Found")
        self.setMinimumWidth(450)
        self.setModal(True)
        self.result = None
        self.new_path = None

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(25, 25, 25, 25)

        icon_label = QLabel("⚠️")
        icon_label.setStyleSheet("font-size: 28pt;")

        title = QLabel(f"Could not find file: <b>{filename}</b>")
        title.setWordWrap(True)

        message = QLabel("The file may have been moved or deleted. What would you like to do?")
        message.setObjectName("secondary_text")
        message.setWordWrap(True)

        # --- Buttons ---
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(10)

        self.remove_button = QPushButton("Remove From List")
        self.remove_button.setObjectName("secondary")
        self.remove_button.clicked.connect(self.on_remove)

        self.locate_button = QPushButton("Locate File...")
        self.locate_button.setObjectName("primary")
        self.locate_button.clicked.connect(self.on_locate)

        buttons_layout.addStretch()
        buttons_layout.addWidget(self.remove_button)
        buttons_layout.addWidget(self.locate_button)
        buttons_layout.addStretch()

        # --- Assemble ---
        main_layout.addWidget(icon_label, alignment=Qt.AlignCenter)
        main_layout.addWidget(title, alignment=Qt.AlignCenter)
        main_layout.addWidget(message, alignment=Qt.AlignCenter)
        main_layout.addSpacing(15)
        main_layout.addLayout(buttons_layout)

    def on_remove(self):
        self.result = "remove"
        self.accept()

    def on_locate(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Locate Signed File")
        if file_path:
            self.result = "relocate"
            self.new_path = file_path
            self.accept()
