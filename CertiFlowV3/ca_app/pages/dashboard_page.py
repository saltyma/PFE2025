# ca_app/pages/dashboard_page.py

import sys
import os
import json
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QPushButton, QScrollArea, QFrame, QMessageBox)
from PySide6.QtCore import Qt, Signal

import requests

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import request_handler, user_management_handler
from ca_app.pages.dialogs import ViewCsrDialog, ConfirmPasswordDialog, GetReasonDialog


def _load_api_base() -> str:
    cfg_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "config.json"))
    try:
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = json.load(fh)
            base = (cfg.get("api_base_url") or "http://127.0.0.1:7001").strip()
            return base.rstrip("/") if base else "http://127.0.0.1:7001"
    except Exception:
        return "http://127.0.0.1:7001"


API_BASE_URL = _load_api_base()

class StatCard(QFrame):
    """A custom widget to display a key statistic on the dashboard."""
    def __init__(self, title, value, color="#2D2D2D"):
        super().__init__()
        self.setObjectName("StatCard")
        self.setStyleSheet(f"#StatCard {{ background-color: {color}; border-radius: 8px; }}")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        self.value_label = QLabel(str(value))
        self.value_label.setObjectName("StatValue")
        
        self.title_label = QLabel(title)
        self.title_label.setObjectName("StatTitle")

        layout.addWidget(self.value_label)
        layout.addWidget(self.title_label)

class RequestItemWidget(QFrame):
    """A custom widget to display a single pending request with its verification status."""
    approve_clicked = Signal(int)
    reject_clicked = Signal(int)
    view_clicked = Signal(dict)  # Pass the whole request dict

    def __init__(self, request_data):
        super().__init__()
        self.setObjectName("RequestItem")
        self.request_data = request_data
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 10, 15, 10)
        
        top_layout = QHBoxLayout()
        info_layout = QVBoxLayout()
        email_label = QLabel(request_data['email'])
        email_label.setObjectName("ItemTitle")
        date_label = QLabel(f"Requested on: {request_data['request_date'].split(' ')[0]}")
        date_label.setObjectName("ItemSubtitle")
        info_layout.addWidget(email_label)
        info_layout.addWidget(date_label)
        top_layout.addLayout(info_layout)
        top_layout.addStretch()

        # Action Buttons
        view_button = QPushButton("View Details")
        view_button.setObjectName("secondary")

        reject_button = QPushButton("Reject")
        reject_button.setObjectName("reject")

        self.approve_button = QPushButton("Approve")
        self.approve_button.setObjectName("primary")
        # Prevent accidental keyboard activation when focus is on this button
        self.approve_button.setAutoDefault(False)
        self.approve_button.setDefault(False)

        top_layout.addWidget(view_button)
        top_layout.addWidget(reject_button)
        top_layout.addWidget(self.approve_button)

        main_layout.addLayout(top_layout)

        # Verification Status Section
        status_frame = QFrame()
        status_frame.setObjectName("StatusFrame")
        status_layout = QHBoxLayout(status_frame)
        status_layout.setContentsMargins(0, 5, 0, 5)
        status_layout.setSpacing(20)

        verification_status = request_data.get('verification_status', {})
        self.hsm_bound = bool(verification_status.get('hsm_bound', False))
        self.hsm_activated = bool(verification_status.get('hsm_activated', False))
        self.email_verified = bool(verification_status.get('email_verified', False))

        def create_status_label(text, is_verified):
            label = QLabel(f"✓ {text}" if is_verified else f"❌ {text}")
            style_class = "VerifiedStatus" if is_verified else "UnverifiedStatus"
            label.setObjectName(style_class)
            return label

        status_layout.addWidget(QLabel("<b>Verification Status:</b>"))
        status_layout.addWidget(create_status_label("HSM Bound", self.hsm_bound))
        status_layout.addWidget(create_status_label("HSM Activated", self.hsm_activated))
        status_layout.addWidget(create_status_label("Email Verified", self.email_verified))
        status_layout.addStretch()
        
        main_layout.addWidget(status_frame)
        
        # Approve is enabled only if all checks pass
        all_ok = self.hsm_bound and self.hsm_activated and self.email_verified
        self.approve_button.setEnabled(all_ok)
        if not all_ok:
            missing = []
            if not self.hsm_bound: missing.append("HSM not bound")
            if not self.hsm_activated: missing.append("HSM not activated")
            if not self.email_verified: missing.append("Email not verified")
            self.approve_button.setToolTip("Cannot approve: " + ", ".join(missing))
        else:
            self.approve_button.setToolTip("All checks passed. Approve request.")

        # Signals
        # Use methods to guard against double clicks and ensure enabled state
        self.approve_button.clicked.connect(self._on_approve_clicked)
        reject_button.clicked.connect(lambda: self.reject_clicked.emit(self.request_data['id']))
        view_button.clicked.connect(lambda: self.view_clicked.emit(self.request_data))

    def _on_approve_clicked(self):
        # Guard: ignore if disabled (prevents race/double-activation)
        if not self.approve_button.isEnabled():
            return
        # Temporary disable to prevent double-click spam
        self.approve_button.setEnabled(False)
        try:
            self.approve_clicked.emit(self.request_data['id'])
        finally:
            # Button is re-enabled by parent after list refresh.
            pass


class DashboardPage(QWidget):
    def __init__(self, main_window_ref):
        super().__init__()
        self.main_window = main_window_ref
        
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(20)

        title = QLabel("System Dashboard")
        title.setObjectName("h1")

        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(20)
        
        self.pending_card = StatCard("Pending Requests", "0", "#A66321")
        self.users_card = StatCard("Active Users", "0", "#2188A6")
        self.issued_card = StatCard("Certs Issued", "0", "#3A4A4A")
        self.revoked_card = StatCard("Certs Revoked", "0", "#9B2335")
        
        stats_layout.addWidget(self.pending_card)
        stats_layout.addWidget(self.users_card)
        stats_layout.addWidget(self.issued_card)
        stats_layout.addWidget(self.revoked_card)

        requests_title = QLabel("Pending Certificate Requests")
        requests_title.setObjectName("h2")

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setObjectName("RequestScrollArea")
        
        scroll_content = QWidget()
        scroll_content.setObjectName("RequestListContainer")
        self.requests_layout = QVBoxLayout(scroll_content)
        self.requests_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.requests_layout.setSpacing(10)
        
        self.scroll_area.setWidget(scroll_content)

        main_layout.addWidget(title)
        main_layout.addLayout(stats_layout)
        main_layout.addWidget(requests_title)
        main_layout.addWidget(self.scroll_area)
        
    def showEvent(self, event):
        super().showEvent(event)
        self.load_dashboard_data()

    def load_dashboard_data(self):
        pending_requests = request_handler.get_pending_requests()
        all_users = user_management_handler.get_all_users_with_certificate_info()
        
        active_users_count = sum(1 for u in all_users if u.get('status') == 'verified' and not u.get('is_revoked'))
        issued_count = sum(1 for u in all_users if u.get('cert_serial'))
        revoked_count = sum(1 for u in all_users if u.get('is_revoked'))

        self.pending_card.value_label.setText(str(len(pending_requests)))
        self.users_card.value_label.setText(str(active_users_count))
        self.issued_card.value_label.setText(str(issued_count))
        self.revoked_card.value_label.setText(str(revoked_count))

        # Clear existing request widgets before reloading
        for i in reversed(range(self.requests_layout.count())): 
            widget = self.requests_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        if not pending_requests:
            no_req_label = QLabel("No pending requests.")
            no_req_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.requests_layout.addWidget(no_req_label)
        else:
            for req in pending_requests:
                item = RequestItemWidget(req)
                item.approve_clicked.connect(self.handle_approve)
                item.reject_clicked.connect(self.handle_reject)
                item.view_clicked.connect(self.handle_view)
                self.requests_layout.addWidget(item)

    def handle_view(self, request_data):
        dialog = ViewCsrDialog(
            email=request_data['email'],
            csr_pem=request_data['csr_pem'],
            verification_status=request_data['verification_status'],
            parent=self
        )
        dialog.exec()

    def handle_approve(self, request_id):
        if not self.main_window.current_admin or not self.main_window.hsm_path:
            QMessageBox.critical(self, "Error", "Admin session is invalid. Please log in again.")
            return

        # Re-fetch request data just-in-time to avoid stale approvals
        request_data = next((r for r in request_handler.get_pending_requests() if r['id'] == request_id), None)
        if not request_data:
            QMessageBox.warning(self, "Request Expired", "This request is no longer pending and may have already been processed.")
            self.load_dashboard_data()
            return

        # Hard-disable if checks are not all green (safety)
        vs = request_data.get('verification_status', {})
        if not (vs.get('hsm_bound') and vs.get('hsm_activated') and vs.get('email_verified')):
            missing = []
            if not vs.get('hsm_bound'): missing.append("HSM not bound")
            if not vs.get('hsm_activated'): missing.append("HSM not activated")
            if not vs.get('email_verified'): missing.append("Email not verified")
            QMessageBox.warning(self, "Not Ready", "Cannot approve: " + ", ".join(missing))
            self.load_dashboard_data()
            return

        pass_dialog = ConfirmPasswordDialog(f"approve the request for {request_data['email']}", self)
        if not pass_dialog.exec():
            # User cancelled; refresh to re-enable buttons correctly
            self.load_dashboard_data()
            return

        password = pass_dialog.get_password()
        admin_id = self.main_window.current_admin['id']
        hsm_path = self.main_window.hsm_path

        payload = {
            "admin_id": admin_id,
            "admin_hsm_path": hsm_path,
            "admin_hsm_password": password,
        }
        url = f"{API_BASE_URL}/api/requests/{request_id}/approve"

        try:
            response = requests.post(url, json=payload, timeout=10)
            response.raise_for_status()
            resp_payload = response.json()
        except requests.exceptions.HTTPError as http_err:
            resp_obj = http_err.response if http_err.response is not None else locals().get("response")
            try:
                error_payload = resp_obj.json() if resp_obj is not None else {}
                message = (
                    error_payload.get("error", {}).get("message")
                    or error_payload.get("message")
                    or str(http_err)
                )
            except Exception:
                message = str(http_err)
            QMessageBox.critical(self, "Approval Failed", message)
            self.load_dashboard_data()
            return
        except requests.exceptions.RequestException as req_err:
            QMessageBox.critical(
                self,
                "Approval Failed",
                f"Network error contacting CA API: {req_err}",
            )
            self.load_dashboard_data()
            return

        if not resp_payload.get("ok", False):
            message = resp_payload.get("error", {}).get("message") or "Approval failed."
            QMessageBox.critical(self, "Approval Failed", message)
        else:
            message = resp_payload.get("message") or "Request approved and certificate issued."
            QMessageBox.information(self, "Success", message)

        # Always refresh after attempting an action
        self.load_dashboard_data()

    def handle_reject(self, request_id):
        if not self.main_window.current_admin:
            return
        
        request_data = next((r for r in request_handler.get_pending_requests() if r['id'] == request_id), None)
        if not request_data:
            QMessageBox.warning(self, "Request Expired", "This request is no longer pending.")
            self.load_dashboard_data()
            return

        reason_dialog = GetReasonDialog("Reject Request", f"Please provide a reason for rejecting the request from {request_data['email']}.", self)
        if not reason_dialog.exec():
            return
            
        reason = reason_dialog.get_reason()
        admin_id = self.main_window.current_admin['id']

        success, message = request_handler.reject_request(request_id, admin_id, reason)
        if success:
            QMessageBox.information(self, "Success", message)
        else:
            QMessageBox.critical(self, "Rejection Failed", message)
        
        self.load_dashboard_data()
