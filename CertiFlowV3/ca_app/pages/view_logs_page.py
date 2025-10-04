# ca_app/pages/view_logs_page.py

import sys
import os
import json
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel,
                               QLineEdit, QTableWidget, QTableWidgetItem,
                               QFrame, QHeaderView, QScrollArea)
from PySide6.QtCore import Qt, QTimer

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
from ca_app.handlers import log_handler


# --- Action categorization for subtle visual tagging (no layout changes) ---
HSM_TAGS = {
    "HSM_DETECTED", "HSM_BOUND", "HSM_ACTIVATED",
    "HSM_CODE_REGENERATED", "HSM_REVOKED"
}
EMAIL_TAGS = {"EMAIL_VERIFICATION_SENT", "EMAIL_VERIFIED"}
USER_REQ_TAGS = {"USER_REQUEST_APPROVED", "USER_REQUEST_REJECTED", "USER_CERT_REVOKED"}
ADMIN_TAGS = {
    "ADMIN_LOGIN_SUCCESS", "ADMIN_LOGIN_FAILURE", "ADMIN_LOGOUT",
    "ADMIN_PASSWORD_CHANGED", "NEW_ADMIN_ADDED", "ADMIN_REMOVED"
}
SYSTEM_TAGS = {
    "SYSTEM_BACKUP_SUCCESS", "SYSTEM_BACKUP_FAILURE",
    "SYSTEM_RESTORE_SUCCESS", "SYSTEM_RESTORE_FAILURE",
    "ROOT_CA_GENERATED"
}
ERROR_TAGS = {"CA_APPLICATION_ERROR", "CA_DATABASE_ERROR"}

def _action_category(action: str) -> str:
    if action in HSM_TAGS: return "HSM"
    if action in EMAIL_TAGS: return "EMAIL"
    if action in USER_REQ_TAGS: return "USER"
    if action in ADMIN_TAGS: return "ADMIN"
    if action in SYSTEM_TAGS: return "SYSTEM"
    if action in ERROR_TAGS: return "ERROR"
    return "OTHER"

def _category_color(cat: str) -> str:
    # Colors chosen to complement existing palette without changing themes
    return {
        "HSM":    "#2188A6",   # teal-ish
        "EMAIL":  "#A66321",   # bronze
        "USER":   "#3A4A4A",   # slate
        "ADMIN":  "#9B2335",   # crimson accent used elsewhere
        "SYSTEM": "#6E6E6E",   # neutral
        "ERROR":  "#E57373",   # warning red
        "OTHER":  "#A0A0A0",
    }.get(cat, "#A0A0A0")


def _category_palette(cat: str) -> tuple[str, str]:
    accent = _category_color(cat)
    hex_color = accent.lstrip("#")
    try:
        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
    except Exception:
        r = g = b = 128
    background = f"rgba({r}, {g}, {b}, 0.16)"
    return accent, background


def _humanize_key(key: str) -> str:
    key = str(key or "").strip()
    if not key:
        return "Info"
    return key.replace("_", " ").title()


def _stringify_detail_value(value) -> str:
    if isinstance(value, dict):
        return "\n".join(f"• {k}: {v}" for k, v in value.items()) or "(empty)"
    if isinstance(value, (list, tuple, set)):
        items = [str(v) for v in value if v not in (None, "")]
        if not items:
            return "(empty)"
        return "\n".join(f"• {item}" for item in items)
    if value in (None, ""):
        return "(empty)"
    return str(value)


class ViewLogsPage(QWidget):
    def __init__(self, main_window_ref):
        super().__init__()
        self.main_window = main_window_ref
        self.logs_data = []  # Cache

        main_layout = QHBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # --- Left Side: Log List ---
        list_container = QFrame()
        list_container.setObjectName("ContentArea")
        list_layout = QVBoxLayout(list_container)
        list_layout.setContentsMargins(25, 25, 25, 25)
        list_layout.setSpacing(15)

        title = QLabel("System Audit Logs")
        title.setObjectName("h1")

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("Filter by Actor, Action, or Details...")
        self.search_bar.textChanged.connect(self._filter_table)

        self._create_table()

        list_layout.addWidget(title)
        list_layout.addWidget(self.search_bar)
        list_layout.addWidget(self.log_table)

        # --- Right Side: Details Panel ---
        self._create_details_panel()

        main_layout.addWidget(list_container, 70)
        main_layout.addWidget(self.details_panel, 30)

        # Auto refresh
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setInterval(10000)
        self.refresh_timer.timeout.connect(self.load_logs)

    def showEvent(self, event):
        self.load_logs()
        self.refresh_timer.start()
        super().showEvent(event)

    def hideEvent(self, event):
        self.refresh_timer.stop()
        super().hideEvent(event)

    def _create_table(self):
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(3)
        self.log_table.setHorizontalHeaderLabels(["Actor", "Action", "Timestamp"])
        self.log_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.log_table.setEditTriggers(QTableWidget.EditTriggers.NoEditTriggers)
        self.log_table.verticalHeader().setVisible(False)
        self.log_table.setShowGrid(False)
        header = self.log_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.log_table.itemSelectionChanged.connect(self._on_log_selected)

    def _create_details_panel(self):
        self.details_panel = QFrame()
        self.details_panel.setObjectName("ActionPanel")
        panel_layout = QVBoxLayout(self.details_panel)
        panel_layout.setContentsMargins(20, 25, 20, 20)
        panel_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        panel_title = QLabel("Log Details")
        panel_title.setObjectName("h2")

        self.details_actor_label = QLabel("Select a log entry to view details.")
        self.details_actor_label.setWordWrap(True)
        self.details_actor_label.setObjectName("secondary_text")

        self.details_action_label = QLabel()
        self.details_action_label.setWordWrap(True)

        self.details_timestamp_label = QLabel()
        self.details_timestamp_label.setWordWrap(True)

        self.detail_cards_wrap = QFrame()
        self.detail_cards_wrap.setObjectName("DetailCardWrap")
        self.detail_cards_layout = QVBoxLayout(self.detail_cards_wrap)
        self.detail_cards_layout.setContentsMargins(0, 0, 0, 0)
        self.detail_cards_layout.setSpacing(10)

        self.detail_scroll = QScrollArea()
        self.detail_scroll.setObjectName("DetailScrollArea")
        self.detail_scroll.setWidgetResizable(True)
        self.detail_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.detail_scroll.setWidget(self.detail_cards_wrap)

        panel_layout.addWidget(panel_title)
        panel_layout.addSpacing(20)
        panel_layout.addWidget(self.details_actor_label)
        panel_layout.addWidget(self.details_action_label)
        panel_layout.addWidget(self.details_timestamp_label)
        panel_layout.addSpacing(18)
        panel_layout.addWidget(self.detail_scroll, 1)

        self.details_panel.setVisible(False)

    def load_logs(self):
        self.log_table.setSortingEnabled(False)
        current_selection = self.log_table.currentRow()

        self.logs_data = log_handler.get_all_logs()
        self.log_table.setRowCount(0)

        for row, log in enumerate(self.logs_data):
            self.log_table.insertRow(row)

            actor = log.get('admin_email') or log.get('user_email', 'System')
            action = log.get('action', 'N/A')
            timestamp = (log.get('timestamp', 'N/A') or 'N/A').split('.')[0]

            # Store full dict in the first column
            actor_item = QTableWidgetItem(actor)
            actor_item.setData(Qt.ItemDataRole.UserRole, log)

            # Action cell with category tag and subtle color
            cat = _action_category(action)
            tag = f"[{cat}] " if cat != "OTHER" else ""
            action_item = QTableWidgetItem(f"{tag}{action}")
            action_item.setForeground(Qt.black)  # readable on your background
            action_item.setBackground(Qt.transparent)
            # Use inline style via Data role to avoid stylesheet changes
            # We emulate a "pill" by just coloring the text; no layout change.
            action_item.setData(Qt.ItemDataRole.ToolTipRole, f"Category: {cat}")

            # Set a per-item foreground color for quick scanning
            from PySide6.QtGui import QColor
            action_item.setForeground(QColor(_category_color(cat)))

            self.log_table.setItem(row, 0, actor_item)
            self.log_table.setItem(row, 1, action_item)
            self.log_table.setItem(row, 2, QTableWidgetItem(timestamp))

        if 0 <= current_selection < self.log_table.rowCount():
            self.log_table.selectRow(current_selection)

        self.log_table.setSortingEnabled(True)

    def _filter_table(self, text):
        q = text.lower().strip()
        for row in range(self.log_table.rowCount()):
            row_item = self.log_table.item(row, 0)
            if not row_item:
                continue
            log_data = row_item.data(Qt.ItemDataRole.UserRole) or {}
            searchable = (
                f"{log_data.get('admin_email','')} {log_data.get('user_email','')} "
                f"{log_data.get('action','')} {json.dumps(log_data.get('details',{}))}"
            ).lower()
            self.log_table.setRowHidden(row, q not in searchable)

    def _clear_detail_cards(self):
        if not hasattr(self, "detail_cards_layout"):
            return
        while self.detail_cards_layout.count():
            item = self.detail_cards_layout.takeAt(0)
            widget = item.widget()
            if widget:
                widget.deleteLater()

    def _render_detail_cards(self, details: dict, category: str):
        self._clear_detail_cards()

        accent, background = _category_palette(category)

        if not details:
            placeholder = QLabel("No additional metadata recorded for this entry.")
            placeholder.setWordWrap(True)
            placeholder.setObjectName("secondary_text")
            self.detail_cards_layout.addWidget(placeholder)
            self.detail_cards_layout.addStretch(1)
            return

        for key, value in sorted(details.items(), key=lambda item: str(item[0]).lower()):
            pretty_key = _humanize_key(key)
            pretty_value = _stringify_detail_value(value)

            card = QFrame()
            card.setObjectName("DetailCard")
            card.setStyleSheet(
                f"background-color: {background}; border: 1px solid {accent}; border-radius: 12px;"
            )

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(14, 12, 14, 12)
            card_layout.setSpacing(6)

            key_label = QLabel(pretty_key.upper())
            key_label.setObjectName("DetailCardKey")
            key_label.setStyleSheet(f"color: {accent};")

            value_label = QLabel(pretty_value)
            value_label.setWordWrap(True)
            value_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            value_label.setObjectName("DetailCardValue")

            card_layout.addWidget(key_label)
            card_layout.addWidget(value_label)

            self.detail_cards_layout.addWidget(card)

        self.detail_cards_layout.addStretch(1)

    def _on_log_selected(self):
        row = self.log_table.currentRow()
        if row < 0:
            self.details_panel.setVisible(False)
            return

        row_item = self.log_table.item(row, 0)
        log_data = (row_item.data(Qt.ItemDataRole.UserRole) if row_item else {}) or {}

        actor = log_data.get('admin_email') or log_data.get('user_email', 'System')
        action = log_data.get('action', 'N/A')
        timestamp = log_data.get('timestamp', 'N/A')
        details = log_data.get('details', {})

        # Parse JSON string details if needed
        if isinstance(details, (bytes, str)):
            try:
                details = json.loads(details) if str(details).strip() else {}
            except Exception:
                details = {"raw": details}

        cat = _action_category(action)

        accent_color, _ = _category_palette(cat)

        self.details_actor_label.setText(f"<b>Actor:</b> {actor}")
        self.details_action_label.setText(f"<b>Action:</b> <span style='color:{accent_color};'>[{cat}] {action}</span>")
        self.details_timestamp_label.setText(f"<b>Timestamp:</b> {timestamp}")

        self._render_detail_cards(details, cat)

        self.details_panel.setVisible(True)
