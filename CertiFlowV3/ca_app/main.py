# ca_app/main.py

import os
import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QStackedWidget, QPushButton, QLabel,
                               QSizePolicy)
from PySide6.QtCore import Qt

# --- Path setup ---
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ca_app.handlers import auth_handler
from ca_app.pages.login_page import LoginPage
from ca_app.pages.hsm_wait_page import HsmWaitPage
from ca_app.pages.setup_page import SetupPage
from ca_app.pages.dashboard_page import DashboardPage
from ca_app.pages.manage_users_page import ManageUsersPage
# --- NEW: Import the HSM Management Page ---
from ca_app.pages.hsm_management_page import HsmManagementPage
from ca_app.pages.view_logs_page import ViewLogsPage
from ca_app.pages.manage_ca_page import ManageCaPage
from ca_app.pages.settings_page import SettingsPage


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CertiFlow - CA Authority")
        self.setMinimumSize(960, 600)
        self.current_admin = None
        self.hsm_path = None

        central_widget = QWidget()
        self.main_layout = QHBoxLayout(central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.setCentralWidget(central_widget)

        self.sidebar = self._create_sidebar()
        self.main_layout.addWidget(self.sidebar)
        self.sidebar.setVisible(False)

        self.content_stack = QStackedWidget()
        self.content_stack.setObjectName("ContentArea")
        self.main_layout.addWidget(self.content_stack)

        self._add_pages_to_stack()
        self._connect_signals()
        
        if auth_handler.check_first_run():
            self.content_stack.setCurrentWidget(self.setup_page)
        else:
            self.content_stack.setCurrentWidget(self.login_page)

    def _create_sidebar(self):
        sidebar_widget = QWidget()
        sidebar_widget.setObjectName("Sidebar")
        sidebar_widget.setFixedWidth(240)
        sidebar_layout = QVBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(12, 12, 12, 12)
        sidebar_layout.setSpacing(8)
        sidebar_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        logo_text = "Certi<span style='color:#9B2335;'>Flow.</span>"
        logo_label = QLabel(logo_text)
        logo_label.setObjectName("Logo")
        sidebar_layout.addWidget(logo_label)
        sidebar_layout.addSpacing(20)

        # --- MODIFIED: Add HSM Provisioning button ---
        self.nav_buttons = {
            "dashboard": QPushButton("Dashboard"),
            "users": QPushButton("Manage Users"),
            "hsm": QPushButton("HSM Provisioning"),
            "logs": QPushButton("View Logs"),
            "ca": QPushButton("Manage CA"),
            "settings": QPushButton("Settings"),
        }
        for btn in self.nav_buttons.values():
            btn.setCheckable(True)
            btn.setAutoExclusive(True)
            sidebar_layout.addWidget(btn)

        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        sidebar_layout.addWidget(spacer)
        
        self.logout_button = QPushButton("Logout")
        sidebar_layout.addWidget(self.logout_button)
        return sidebar_widget

    def _add_pages_to_stack(self):
        self.login_page = LoginPage()
        self.hsm_wait_page = HsmWaitPage()
        self.setup_page = SetupPage()
        self.dashboard_page = DashboardPage(self)
        self.manage_users_page = ManageUsersPage(self)
        # --- NEW: Instantiate the HSM Management Page ---
        self.hsm_management_page = HsmManagementPage(self)
        self.view_logs_page = ViewLogsPage(self)
        self.manage_ca_page = ManageCaPage(self)
        self.settings_page = SettingsPage(self)

        self.content_stack.addWidget(self.login_page)
        self.content_stack.addWidget(self.hsm_wait_page)
        self.content_stack.addWidget(self.setup_page)
        self.content_stack.addWidget(self.dashboard_page)
        self.content_stack.addWidget(self.manage_users_page)
        # --- NEW: Add HSM page to the stack ---
        self.content_stack.addWidget(self.hsm_management_page)
        self.content_stack.addWidget(self.view_logs_page)
        self.content_stack.addWidget(self.manage_ca_page)
        self.content_stack.addWidget(self.settings_page)

    def _connect_signals(self):
        self.login_page.navigate_to_hsm_wait.connect(self.navigate_to_hsm_wait)
        self.hsm_wait_page.navigate_to_login.connect(self.navigate_to_login)
        self.hsm_wait_page.login_success.connect(self.on_login_success)
        self.hsm_wait_page.login_failure.connect(self.on_login_failure)
        self.setup_page.setup_complete.connect(self.on_setup_complete)

        self.nav_buttons["dashboard"].clicked.connect(self.navigate_to_dashboard)
        self.nav_buttons["users"].clicked.connect(self.navigate_to_manage_users)
        # --- NEW: Connect the HSM Provisioning button ---
        self.nav_buttons["hsm"].clicked.connect(self.navigate_to_hsm_management)
        self.nav_buttons["logs"].clicked.connect(lambda: self.content_stack.setCurrentWidget(self.view_logs_page))
        self.nav_buttons["ca"].clicked.connect(lambda: self.content_stack.setCurrentWidget(self.manage_ca_page))
        self.nav_buttons["settings"].clicked.connect(lambda: self.content_stack.setCurrentWidget(self.settings_page))
        self.logout_button.clicked.connect(self.navigate_to_login)

    def navigate_to_dashboard(self):
        self.dashboard_page.load_dashboard_data()
        self.content_stack.setCurrentWidget(self.dashboard_page)

    def navigate_to_manage_users(self):
        self.content_stack.setCurrentWidget(self.manage_users_page)
    
    # --- NEW: Navigation function for the HSM page ---
    def navigate_to_hsm_management(self):
        self.content_stack.setCurrentWidget(self.hsm_management_page)

    def navigate_to_hsm_wait(self, email, password):
        self.content_stack.setCurrentWidget(self.hsm_wait_page)
        self.hsm_wait_page.start_login_process(email, password)

    def on_login_success(self, admin_data, hsm_path):
        self.current_admin = admin_data
        self.hsm_path = hsm_path
        self.setWindowTitle(f"CertiFlow CA Authority - [{self.current_admin['email']}]")
        self.sidebar.setVisible(True)
        self.nav_buttons["dashboard"].setChecked(True)
        self.navigate_to_dashboard()

    def on_setup_complete(self, admin_data):
        self.current_admin = admin_data
        self.hsm_path = None 
        self.setWindowTitle(f"CertiFlow CA Authority - [{self.current_admin['email']}]")
        self.sidebar.setVisible(True)
        self.nav_buttons["dashboard"].setChecked(True)
        self.navigate_to_dashboard()

    def on_login_failure(self, message):
        self.navigate_to_login()
        self.login_page.show_error(message)

    def navigate_to_login(self):
        self.hsm_wait_page.stop_worker()
        self.sidebar.setVisible(False)
        self.login_page.clear_form()
        self.content_stack.setCurrentWidget(self.login_page)
        self.current_admin = None
        self.hsm_path = None
        self.setWindowTitle("CertiFlow - CA Authority")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    style_path = os.path.join(os.path.dirname(__file__), "styles", "ca_style.qss")
    try:
        with open(style_path, "r") as f:
            app.setStyleSheet(f.read())
    except FileNotFoundError:
        print(f"Warning: Stylesheet not found at {style_path}.")
    
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
