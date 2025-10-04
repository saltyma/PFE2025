"""
CertiFlow Verifier - Main window
- Splash appears alone (no sidebar), then auto-switch to Verify & show sidebar
- Adopts the CA Owner application's layout and style, with a green theme.
"""

from __future__ import annotations
import sys, os
import threading
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QPushButton, QStackedWidget, QLabel)
from PySide6.QtCore import Qt, QTimer

# --- PATH SETUP ---
APP_PATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_PATH)
sys.path.append(PROJECT_ROOT)
sys.path.append(APP_PATH)

from pages.splash_page import SplashPage
from pages.verify_page import VerifyPage
from pages.history_page import HistoryPage
from pages.settings_page import SettingsPage # <-- Import the settings page
from utils import log_sync

APP_TITLE = "CertiFlow - Verifier"

def _apply_styles(app):
    from pathlib import Path
    qss_path = Path(__file__).parent / "styles" / "verifier_style.qss"
    try:
        qss = qss_path.read_text(encoding="utf-8")
        app.setStyleSheet(qss)
    except FileNotFoundError:
        print(f"Warning: Stylesheet not found at {qss_path}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.setMinimumSize(960, 600)

        central_widget = QWidget()
        self.main_layout = QHBoxLayout(central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.setCentralWidget(central_widget)

        # --- Sidebar (matches ca_owner app style) ---
        self.sidebar = self._create_sidebar()
        self.main_layout.addWidget(self.sidebar)

        # --- Content Area ---
        self.content_area = QStackedWidget()
        self.content_area.setObjectName("ContentArea")
        self.main_layout.addWidget(self.content_area, 1) # Add stretch factor

        # --- Add pages ---
        self.splash_page = SplashPage()
        self.verify_page = VerifyPage()
        self.history_page = HistoryPage()
        self.settings_page = SettingsPage() # <-- Instantiate the settings page

        self.content_area.addWidget(self.splash_page)
        self.content_area.addWidget(self.verify_page)
        self.content_area.addWidget(self.history_page)
        self.content_area.addWidget(self.settings_page) # <-- Add to stack

        # --- Initial State ---
        self.sidebar.setVisible(False)
        self.content_area.setCurrentWidget(self.splash_page)
        self.splash_page.splash_done.connect(self._on_splash_done)

        self._log_sync_thread = None
        self._log_sync_lock = threading.Lock()
        self.log_sync_timer = QTimer(self)
        self.log_sync_timer.setInterval(30000)
        self.log_sync_timer.timeout.connect(self._trigger_log_sync)
        self.log_sync_timer.start()
        self._trigger_log_sync()


    def _create_sidebar(self):
        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("Sidebar")
        # --- STYLE: Match CA app's fixed width ---
        sidebar_widget.setFixedWidth(240)
        layout = QVBoxLayout(sidebar_widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)
        layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # --- STYLE: Center the logo ---
        logo_label = QLabel("Certi<span style='color:#16a34a;'>Flow.</span>")
        logo_label.setObjectName("Logo")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter) # <-- Center horizontally
        layout.addWidget(logo_label)
        layout.addSpacing(20)

        # --- Navigation Buttons ---
        self.nav_buttons = {
            "verify": QPushButton("Verify Signature"),
            "history": QPushButton("History"),
            "settings": QPushButton("Settings"), # <-- Add settings button
        }
        for name, btn in self.nav_buttons.items():
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            layout.addWidget(btn)

        layout.addStretch()
        return sidebar_widget

    def _on_splash_done(self):
        self.sidebar.setVisible(True)
        self.nav_buttons["verify"].setChecked(True)
        self.content_area.setCurrentWidget(self.verify_page)

        # --- Connect navigation signals after splash ---
        self.nav_buttons["verify"].clicked.connect(lambda: self.content_area.setCurrentWidget(self.verify_page))
        self.nav_buttons["history"].clicked.connect(lambda: self.content_area.setCurrentWidget(self.history_page))
        self.nav_buttons["settings"].clicked.connect(lambda: self.content_area.setCurrentWidget(self.settings_page))
        self._trigger_log_sync()

    def _trigger_log_sync(self):
        with self._log_sync_lock:
            if self._log_sync_thread and self._log_sync_thread.is_alive():
                return

            def _run():
                try:
                    ok, message = log_sync.sync_with_ca()
                    if not ok and message:
                        print(f"[VerifierLogSync] {message}")
                finally:
                    with self._log_sync_lock:
                        self._log_sync_thread = None

            thread = threading.Thread(target=_run, name="VerifierLogSync", daemon=True)
            self._log_sync_thread = thread
            thread.start()

def main():
    app = QApplication(sys.argv)
    _apply_styles(app)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
