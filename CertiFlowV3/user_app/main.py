# user_app/main.py
# CertiFlow V3 — Main Window (minimal wiring fixes, no visual redesign)

import json
import os
import sys
import threading

from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QStackedWidget,
    QWidget,
    QLabel,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QFrame,
    QSizePolicy,
    QButtonGroup,
)
from PySide6.QtCore import Qt, QTimer


# Ensure relative imports work when running directly
APP_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(APP_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)
if APP_DIR not in sys.path:
    sys.path.append(APP_DIR)

# Pages
from pages.login_page import LoginPage
from pages.hsm_wait_page import HSMWaitPage
from pages.registration_page import RegistrationPage
from pages.pending_approval_page import PendingApprovalPage
from pages.home_page import HomePage
from pages.sign_document_page import SignDocumentPage
from pages.verify_signature_page import VerifySignaturePage
from pages.user_info_page import UserInfoPage
from pages.renew_certificate_page import RenewCertificatePage
from pages.view_documents_page import ViewDocumentsPage
from pages.rejection_page import RejectionPage

# Local helpers
import db_helper
from utils import certificate, ca_sync_handler


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CertiFlow")
        # Preserve window sizing expectations
        self.setMinimumSize(960, 600)

        # Style
        self._apply_stylesheet()

        # App state
        self.current_user_email: str | None = None
        self.current_user_data: dict | None = None
        self._log_sync_email: str | None = None
        self._log_sync_thread = None
        self._log_sync_lock = threading.Lock()

        self.log_sync_timer = QTimer(self)
        self.log_sync_timer.setInterval(30000)
        self.log_sync_timer.timeout.connect(self._trigger_log_sync)

        # Layout: sidebar + content stack
        self.sidebar, self.nav_buttons, self.nav_group, self.logout_button = self._build_sidebar()
        self.sidebar.hide()

        self.stack = QStackedWidget(self)

        content_frame = QFrame(self)
        content_frame.setObjectName("ContentArea")
        content_layout = QVBoxLayout(content_frame)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)
        content_layout.addWidget(self.stack)

        container = QWidget(self)
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(0)
        container_layout.addWidget(self.sidebar)
        container_layout.addWidget(content_frame, 1)

        self.setCentralWidget(container)

        self.login_page = LoginPage()
        self.hsm_wait_page = HSMWaitPage()
        self.registration_page = RegistrationPage()
        self.pending_page = PendingApprovalPage()
        self.home_page = HomePage()
        self.sign_page = SignDocumentPage()
        self.verify_page = VerifySignaturePage()
        self.user_info_page = UserInfoPage()
        self.renew_page = RenewCertificatePage()
        self.view_docs_page = ViewDocumentsPage()
        self.rejection_page = RejectionPage()

        for p in [
            self.login_page, self.hsm_wait_page, self.registration_page,
            self.pending_page, self.home_page, self.sign_page, self.verify_page,
            self.user_info_page, self.renew_page, self.view_docs_page, self.rejection_page
        ]:
            self.stack.addWidget(p)

        # Wiring (V3)
        self._connect_signals()

        # Start
        self.stack.setCurrentWidget(self.login_page)

    # ---------------- Wiring ----------------

    def _connect_signals(self):
        # Login
        # On success LoginPage emits navigate_to_hsm_wait(email) (legacy signal name).
        # We route straight to Home because HSM unlock already happened inside the page.
        self.login_page.navigate_to_hsm_wait.connect(self._on_login_success_legacy)
        self.login_page.navigate_to_registration.connect(self.go_to_registration)
        self.login_page.navigate_to_pending.connect(self.go_to_pending)
        self.login_page.navigate_to_rejection.connect(self.go_to_rejection)

        # Registration flow
        self.registration_page.registration_completed.connect(self.go_to_pending)
        # Back to Login must work regardless of router style
        self.registration_page.navigate_to_login.connect(self.go_to_login)

        # Pending page
        self.pending_page.request_rejected.connect(self.go_to_rejection)
        self.pending_page.navigate_to_login.connect(self.go_to_login)

        # HSM wait page is only used during registration scans now.
        # Keep behavior no-op in login path.
        self.hsm_wait_page.hsm_detected.connect(lambda _hid: None)

        # Home page navigation to subpages (optional signals)
        if hasattr(self.home_page, "navigate_to_sign"):
            self.home_page.navigate_to_sign.connect(self.go_to_sign)
        if hasattr(self.home_page, "navigate_to_verify"):
            self.home_page.navigate_to_verify.connect(self.go_to_verify)
        if hasattr(self.home_page, "navigate_to_certificate_info"):
            self.home_page.navigate_to_certificate_info.connect(self.go_to_user_info)
        if hasattr(self.home_page, "navigate_to_view_documents"):
            self.home_page.navigate_to_view_documents.connect(self.go_to_view_documents)
        if hasattr(self.home_page, "navigate_to_renew"):
            self.home_page.navigate_to_renew.connect(self.go_to_renew)
        if hasattr(self.home_page, "request_trust_sync"):
            self.home_page.request_trust_sync.connect(self._handle_trust_sync_request)

        # Renew page → back to home on submission
        if hasattr(self.renew_page, "renewal_request_submitted"):
            self.renew_page.renewal_request_submitted.connect(lambda _email: self.go_to_home())

        # Rejection page → back to login
        if hasattr(self.rejection_page, "navigate_to_login"):
            self.rejection_page.navigate_to_login.connect(self.go_to_login)

    def _handle_trust_sync_request(self):
        if hasattr(self.home_page, "set_trust_sync_feedback"):
            self.home_page.set_trust_sync_feedback(
                "Syncing trust material...", variant="progress", in_progress=True
            )

        root_pem, root_err = ca_sync_handler.get_root_certificate()
        crl_bundle, crl_err = ca_sync_handler.get_crl()

        if root_err or crl_err or not root_pem or not crl_bundle:
            message = root_err or crl_err or "Unable to fetch trust material from the CA."
            if hasattr(self.home_page, "set_trust_sync_feedback"):
                self.home_page.set_trust_sync_feedback(f"Sync failed: {message}", variant="error")
            return

        crl_payload = crl_bundle.get("crl_pem") if isinstance(crl_bundle, dict) else None
        if not crl_payload and isinstance(crl_bundle, dict):
            revoked_serials = crl_bundle.get("revoked_serials")
            if revoked_serials is not None:
                try:
                    crl_payload = json.dumps(revoked_serials)
                except (TypeError, ValueError):
                    crl_payload = str(revoked_serials)
        if crl_payload is None:
            crl_payload = ""

        version_value = crl_bundle.get("version") if isinstance(crl_bundle, dict) else None
        try:
            crl_version = int(version_value) if version_value is not None else None
        except (TypeError, ValueError):
            crl_version = None
        issued_at = crl_bundle.get("issued_at_utc") if isinstance(crl_bundle, dict) else None

        try:
            db_helper.upsert_trust_cache(
                ca_root_pem=root_pem,
                crl_pem=crl_payload,
                crl_version=crl_version,
                crl_issued_at_utc=issued_at,
            )
        except Exception as exc:
            if hasattr(self.home_page, "set_trust_sync_feedback"):
                self.home_page.set_trust_sync_feedback(f"Sync failed: {exc}", variant="error")
            return

        if hasattr(self.home_page, "set_trust_sync_feedback"):
            revoked_total = 0
            if isinstance(crl_bundle, dict):
                revoked = crl_bundle.get("revoked_serials")
                if isinstance(revoked, list):
                    revoked_total = len(revoked)
            summary = "Trust material refreshed."
            if revoked_total:
                summary = f"Trust material refreshed. {revoked_total} certificate(s) revoked."
            self.home_page.set_trust_sync_feedback(summary, variant="success")

        if hasattr(self.home_page, "set_user_data"):
            payload = self.current_user_data or {}
            self.home_page.set_user_data(payload)

    def _trigger_log_sync(self):
        email = self._log_sync_email
        if not email:
            return

        with self._log_sync_lock:
            if self._log_sync_thread and self._log_sync_thread.is_alive():
                return

            def _run(target_email: str):
                try:
                    ok, message = logging_handler.sync_with_ca(target_email)
                    if not ok and message:
                        print(f"[LogSync] {message}")
                finally:
                    with self._log_sync_lock:
                        self._log_sync_thread = None

            thread = threading.Thread(
                target=_run,
                args=(email,),
                name="UserAppLogSync",
                daemon=True,
            )
            self._log_sync_thread = thread
            thread.start()

    def _update_log_sync_identity(self, email: str | None, *, immediate: bool = False):
        self._log_sync_email = email
        if not email:
            self.log_sync_timer.stop()
            return

        if immediate:
            self._trigger_log_sync()
        if not self.log_sync_timer.isActive():
            self.log_sync_timer.start()

    # ---------------- Navigation helpers ----------------

    def go_to_login(self):
        self.current_user_email = None
        self.current_user_data = None
        self._set_sidebar_authenticated(False)
        self.stack.setCurrentWidget(self.login_page)
        self._update_log_sync_identity(None)

    def go_to_pending(self, email: str):
        self._set_sidebar_authenticated(False)
        self.current_user_email = email
        self.pending_page.start_status_check(email)
        self.stack.setCurrentWidget(self.pending_page)
        self._update_log_sync_identity(email, immediate=True)

    def go_to_rejection(self, email: str):
        self._set_sidebar_authenticated(False)
        self.rejection_page.set_email(email)
        self.stack.setCurrentWidget(self.rejection_page)
        self._update_log_sync_identity(email, immediate=True)

    def go_to_registration(self):
        self._set_sidebar_authenticated(False)
        self.stack.setCurrentWidget(self.registration_page)

    def go_to_home(self):
        # Pass current_user_data if available
        if self.current_user_data:
            if hasattr(self.home_page, "set_user_data"):
                self.home_page.set_user_data(self.current_user_data)
        self._set_sidebar_authenticated(True)
        self._activate_nav("home")
        self.stack.setCurrentWidget(self.home_page)
        self._update_log_sync_identity(self.current_user_email, immediate=True)

    def go_to_sign(self):
        if self.current_user_data and hasattr(self.sign_page, "set_current_user"):
            self.sign_page.set_current_user(self.current_user_data)
        self._set_sidebar_authenticated(True)
        self._activate_nav("sign")
        self.stack.setCurrentWidget(self.sign_page)

    def go_to_verify(self):
        self._set_sidebar_authenticated(True)
        self._activate_nav("verify")
        self.stack.setCurrentWidget(self.verify_page)

    def go_to_user_info(self):
        if self.current_user_data and hasattr(self.user_info_page, "set_user_data"):
            self.user_info_page.set_user_data(self.current_user_data)
        self._set_sidebar_authenticated(True)
        self._activate_nav("info")
        self.stack.setCurrentWidget(self.user_info_page)

    def go_to_renew(self):
        if self.current_user_data and hasattr(self.renew_page, "set_current_user"):
            self.renew_page.set_current_user(self.current_user_data)
        self._set_sidebar_authenticated(True)
        self._clear_nav_selection()
        self.stack.setCurrentWidget(self.renew_page)

    def go_to_view_documents(self):
        if self.current_user_data and hasattr(self.view_docs_page, "set_current_user"):
            self.view_docs_page.set_current_user(self.current_user_data)
        elif self.current_user_email and hasattr(self.view_docs_page, "set_current_user"):
            self.view_docs_page.set_current_user({"email": self.current_user_email})
        if hasattr(self.view_docs_page, "load_document_history"):
            self.view_docs_page.load_document_history()
        self._set_sidebar_authenticated(True)
        self._activate_nav("view_docs")
        self.stack.setCurrentWidget(self.view_docs_page)

    # ---------------- Helpers ----------------

    def _on_login_success_legacy(self, email: str):
        """
        Legacy signal from LoginPage on success. Fetch user data from local cache
        and route to Home. This avoids using HSMWait in the login path for V3.
        """
        self.current_user_email = email
        self.current_user_data = self._build_user_data(email)
        self.go_to_home()

    def _build_user_data(self, email: str) -> dict:
        """
        Construct the user_data dict expected by pages from local cache.
        """
        row = db_helper.get_user(email)
        if not row:
            return {"email": email}

        cert_pem = row.get("cert_pem")
        cert_details = None
        if cert_pem:
            details, err = certificate.parse_certificate_pem(cert_pem)
            if not err:
                cert_details = details

        return {
            "email": email,
            "hsm_id": row.get("hsm_id"),
            "certificate_pem": cert_pem,
            "certificate_details": cert_details or {}
        }

    def _set_sidebar_authenticated(self, is_authenticated: bool):
        if is_authenticated:
            self.sidebar.show()
            for button in self.nav_buttons.values():
                button.setEnabled(True)
            self.logout_button.setEnabled(True)
        else:
            for button in self.nav_buttons.values():
                button.setEnabled(False)
            self.logout_button.setEnabled(False)
            self.sidebar.hide()
            self._clear_nav_selection()

    def _clear_nav_selection(self):
        self.nav_group.setExclusive(False)
        for button in self.nav_buttons.values():
            was_blocked = button.blockSignals(True)
            button.setChecked(False)
            button.blockSignals(was_blocked)
        self.nav_group.setExclusive(True)

    def _activate_nav(self, key: str):
        if key not in self.nav_buttons:
            self._clear_nav_selection()
            return
        self.nav_group.setExclusive(False)
        for name, button in self.nav_buttons.items():
            was_blocked = button.blockSignals(True)
            button.setChecked(name == key)
            button.blockSignals(was_blocked)
        self.nav_group.setExclusive(True)

    def _handle_logout(self):
        self.go_to_login()

    def _build_sidebar(self):
        sidebar = QFrame(self)
        sidebar.setObjectName("Sidebar")
        size_policy = QSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        sidebar.setSizePolicy(size_policy)
        sidebar.setMinimumWidth(240)

        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(24, 28, 24, 24)
        layout.setSpacing(8)
        layout.setAlignment(Qt.AlignTop)

        logo_label = QLabel("Certi<span style='color:#5294e2;'>Flow.</span>")
        logo_label.setObjectName("Logo")
        logo_label.setTextFormat(Qt.RichText)
        layout.addWidget(logo_label)
        layout.addSpacing(20)

        nav_group = QButtonGroup(sidebar)
        nav_group.setExclusive(True)

        buttons: dict[str, QPushButton] = {}

        nav_items = [
            ("home", "Home", "nav_home", self.go_to_home),
            ("sign", "Sign Document", "nav_sign", self.go_to_sign),
            ("verify", "Verify Signature", "nav_verify", self.go_to_verify),
            ("view_docs", "View Documents", "nav_view_documents", self.go_to_view_documents),
            ("info", "My Certificate", "nav_info", self.go_to_user_info),
        ]

        for key, label, object_name, handler in nav_items:
            button = QPushButton(label, sidebar)
            button.setObjectName(object_name)
            button.setCheckable(True)
            button.setCursor(Qt.PointingHandCursor)
            button.setEnabled(False)
            button.clicked.connect(handler)
            layout.addWidget(button)
            nav_group.addButton(button)
            buttons[key] = button

        layout.addStretch(1)

        logout_button = QPushButton("Logout", sidebar)
        logout_button.setObjectName("nav_logout")
        logout_button.setCursor(Qt.PointingHandCursor)
        logout_button.clicked.connect(self._handle_logout)
        logout_button.setEnabled(False)
        layout.addWidget(logout_button)

        return sidebar, buttons, nav_group, logout_button

    def _apply_stylesheet(self):
        style_path = os.path.join(APP_DIR, "styles", "main_style.qss")
        alt_path   = os.path.join(APP_DIR, "main_style.qss")
        for p in (style_path, alt_path):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    self.setStyleSheet(f.read())
                    break
            except FileNotFoundError:
                pass



def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()