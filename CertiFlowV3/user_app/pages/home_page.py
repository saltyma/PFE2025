# user_app/pages/home_page.py
# Redesigned CertiFlow user dashboard with rich status cards

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Any, Optional, Callable

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QFrame,
    QSizePolicy,
    QGraphicsDropShadowEffect,
)
from PySide6.QtCore import Qt, Signal, QEvent
from PySide6.QtGui import QColor

import db_helper


def _format_timestamp(value: Optional[str]) -> str:
    if not value:
        return "N/A"
    try:
        normalized = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo:
            dt = dt.astimezone(timezone.utc)
            return dt.strftime("%d %b %Y • %H:%M UTC")
        return dt.strftime("%d %b %Y • %H:%M")
    except Exception:
        return value


class HomePage(QWidget):
    navigate_to_sign = Signal()
    navigate_to_verify = Signal()
    navigate_to_view_documents = Signal()
    navigate_to_certificate_info = Signal()
    navigate_to_renew = Signal()
    request_trust_sync = Signal()

    def __init__(self):
        super().__init__()
        self.user_data: Dict[str, Any] | None = None
        self._clickable_cards: dict[QFrame, Callable[[], None]] = {}
        self._trust_sync_in_progress = False

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(40, 36, 40, 36)
        main_layout.setSpacing(28)

        # ----- Hero card -----
        self.hero_card = self._create_card("HeroCard")
        hero_layout = QVBoxLayout(self.hero_card)
        hero_layout.setSpacing(18)

        self.greeting_label = QLabel("Welcome to Certi<span style='color:#5294e2;'>Flow.</span>")
        self.greeting_label.setObjectName("h1")
        self.greeting_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.greeting_label.setTextFormat(Qt.TextFormat.RichText)

        self.hero_subtitle = QLabel("Loading your workspace...")
        self.hero_subtitle.setObjectName("HeroSubtitle")
        self.hero_subtitle.setWordWrap(True)

        hero_details = QGridLayout()
        hero_details.setHorizontalSpacing(24)
        hero_details.setVerticalSpacing(8)

        self.hero_email_value = self._create_metric_value()
        self.hero_hsm_value = self._create_metric_value()
        self.hero_sync_value = self._create_metric_value()

        hero_details.addWidget(self._create_detail_label("Email"), 0, 0)
        hero_details.addWidget(self.hero_email_value, 1, 0)
        hero_details.addWidget(self._create_detail_label("HSM Device"), 0, 1)
        hero_details.addWidget(self.hero_hsm_value, 1, 1)
        hero_details.addWidget(self._create_detail_label("Last synced"), 0, 2)
        hero_details.addWidget(self.hero_sync_value, 1, 2)

        hero_layout.addWidget(self.greeting_label)
        hero_layout.addWidget(self.hero_subtitle)
        hero_layout.addLayout(hero_details)

        # ----- Status cards -----
        self.cards_container = QFrame()
        self.cards_container.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred
        )
        self.cards_layout = QGridLayout(self.cards_container)
        self.cards_layout.setContentsMargins(0, 0, 0, 0)
        self.cards_layout.setHorizontalSpacing(20)
        self.cards_layout.setVerticalSpacing(20)
        self.cards_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        self.certificate_card = self._create_card("SummaryCard")
        cert_layout = QVBoxLayout(self.certificate_card)
        cert_layout.setSpacing(10)

        cert_title = QLabel("Certificate status")
        cert_title.setObjectName("CardTitle")
        self.cert_status_chip = self._create_status_chip()
        self.cert_validity_label = QLabel("Issued —")
        self.cert_validity_label.setObjectName("CardMeta")
        self.cert_expiry_hint = QLabel("Awaiting details...")
        self.cert_expiry_hint.setObjectName("CardHint")
        self.cert_expiry_hint.setWordWrap(True)

        cert_header = QHBoxLayout()
        cert_header.setSpacing(10)
        cert_header.addWidget(cert_title)
        cert_header.addStretch(1)
        cert_header.addWidget(self.cert_status_chip)

        cert_layout.addLayout(cert_header)
        cert_layout.addWidget(self.cert_validity_label)
        cert_layout.addWidget(self.cert_expiry_hint)

        self._register_clickable(self.certificate_card, self.navigate_to_certificate_info.emit)

        self.security_card = self._create_card("SummaryCard")
        security_layout = QVBoxLayout(self.security_card)
        security_layout.setSpacing(10)

        security_title = QLabel("Security gates")
        security_title.setObjectName("CardTitle")
        self.hsm_status_chip = self._create_status_chip()
        self.flags_detail_label = QLabel("Checking activation...")
        self.flags_detail_label.setObjectName("CardHint")
        self.flags_detail_label.setWordWrap(True)
        self.flags_detail_label.setTextFormat(Qt.TextFormat.RichText)

        sec_header = QHBoxLayout()
        sec_header.setSpacing(10)
        sec_header.addWidget(security_title)
        sec_header.addStretch(1)
        sec_header.addWidget(self.hsm_status_chip)

        security_layout.addLayout(sec_header)
        security_layout.addWidget(self.flags_detail_label)

        self.documents_card = self._create_card("SummaryCard")
        docs_layout = QVBoxLayout(self.documents_card)
        docs_layout.setSpacing(10)

        docs_title = QLabel("Recent activity")
        docs_title.setObjectName("CardTitle")
        self.docs_metric_label = QLabel("0")
        self.docs_metric_label.setObjectName("Metric")
        self.docs_hint_label = QLabel("No documents signed yet.")
        self.docs_hint_label.setObjectName("CardHint")
        self.docs_hint_label.setWordWrap(True)

        docs_layout.addWidget(docs_title)
        docs_layout.addWidget(self.docs_metric_label)
        docs_layout.addWidget(self.docs_hint_label)

        self._register_clickable(self.documents_card, self.navigate_to_view_documents.emit)

        self.trust_card = self._create_card("SummaryCard")
        trust_layout = QVBoxLayout(self.trust_card)
        trust_layout.setSpacing(10)

        trust_title = QLabel("Trust material")
        trust_title.setObjectName("CardTitle")
        self.trust_sync_label = QLabel("Root/CRL not synced yet.")
        self.trust_sync_label.setObjectName("CardHint")
        self.trust_sync_label.setWordWrap(True)
        self.trust_sync_label.setProperty("variant", "info")
        self._update_trust_hint_variant("info")
        self.trust_version_label = QLabel("—")
        self.trust_version_label.setObjectName("CardMeta")

        trust_layout.addWidget(trust_title)
        trust_layout.addWidget(self.trust_version_label)
        trust_layout.addWidget(self.trust_sync_label)

        self.trust_card.setToolTip("Click to refresh root certificate and CRL cache")
        self._register_clickable(self.trust_card, self._on_trust_card_clicked)

        self._set_card_tone(self.certificate_card, "primary")
        self._set_card_tone(self.security_card, "warning")
        self._set_card_tone(self.documents_card, "neutral")
        self._set_card_tone(self.trust_card, "info")

        self._card_widgets = [
            self.certificate_card,
            self.security_card,
            self.documents_card,
            self.trust_card,
        ]
        self._current_card_columns: Optional[int] = None
        self._apply_card_grid(2)

        main_layout.addWidget(self.hero_card)
        main_layout.addWidget(self.cards_container)
        main_layout.addStretch(1)

    # ----- Helpers -----

    def _create_card(self, object_name: str) -> QFrame:
        frame = QFrame()
        frame.setObjectName(object_name)
        frame.setProperty("hover", False)
        frame.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setOffset(0, 12)
        shadow.setColor(QColor(0, 0, 0, 120))
        shadow.setEnabled(True)
        frame.setGraphicsEffect(shadow)
        return frame

    def _set_card_tone(self, card: QFrame, tone: str):
        card.setProperty("tone", tone)
        style = card.style()
        if style:
            style.unpolish(card)
            style.polish(card)

    def _apply_card_grid(self, columns: int):
        columns = max(1, columns)
        while self.cards_layout.count():
            item = self.cards_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(self.cards_container)
        for col in range(4):
            self.cards_layout.setColumnStretch(col, 0)
        for index, widget in enumerate(self._card_widgets):
            row = index // columns
            col = index % columns
            self.cards_layout.addWidget(widget, row, col)
        for col in range(columns):
            self.cards_layout.setColumnStretch(col, 1)
        self._current_card_columns = columns

    def _create_detail_label(self, text: str) -> QLabel:
        label = QLabel(text)
        label.setObjectName("DetailLabel")
        return label

    def _create_metric_value(self) -> QLabel:
        label = QLabel("—")
        label.setObjectName("HeroMetric")
        label.setWordWrap(False)
        return label

    def _create_status_chip(self) -> QLabel:
        label = QLabel("Pending")
        label.setObjectName("StatusChip")
        label.setProperty("status", "neutral")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        style = label.style()
        if style:
            style.unpolish(label)
            style.polish(label)
        return label

    def _register_clickable(self, frame: QFrame, callback: Callable[[], None]):
        frame.installEventFilter(self)
        frame.setCursor(Qt.CursorShape.PointingHandCursor)
        self._clickable_cards[frame] = callback

    def _set_chip_state(self, label: QLabel, state: str, text: str):
        label.setText(text)
        label.setProperty("status", state)
        style = label.style()
        if style:
            style.unpolish(label)
            style.polish(label)

    def _update_trust_hint_variant(self, variant: str):
        self.trust_sync_label.setProperty("variant", variant)
        style = self.trust_sync_label.style()
        if style:
            style.unpolish(self.trust_sync_label)
            style.polish(self.trust_sync_label)

    def _on_trust_card_clicked(self):
        if self._trust_sync_in_progress:
            return
        self.set_trust_sync_feedback("Syncing trust material...", variant="progress", in_progress=True)
        self.request_trust_sync.emit()

    def set_trust_sync_feedback(self, message: str, *, variant: str = "info", in_progress: bool = False):
        self._trust_sync_in_progress = in_progress
        self.trust_sync_label.setText(message)
        self._update_trust_hint_variant(variant)

    # ----- Event handling -----

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not hasattr(self, "_card_widgets") or not self._card_widgets:
            return
        width = event.size().width() if event else self.width()
        columns = 1 if width < 900 else 2
        if self._current_card_columns != columns:
            self._apply_card_grid(columns)

    def eventFilter(self, obj, event):
        if obj in self._clickable_cards:
            if event.type() == QEvent.Type.Enter:
                obj.setProperty("hover", True)
                style = obj.style()
                if style:
                    style.unpolish(obj)
                    style.polish(obj)
            elif event.type() == QEvent.Type.Leave:
                obj.setProperty("hover", False)
                style = obj.style()
                if style:
                    style.unpolish(obj)
                    style.polish(obj)
            elif event.type() == QEvent.Type.MouseButtonRelease and event.button() == Qt.MouseButton.LeftButton:
                callback = self._clickable_cards.get(obj)
                if callback:
                    callback()
                return True
        return super().eventFilter(obj, event)

    # ----- Data binding -----

    def set_user_data(self, user_data: Dict[str, Any]):
        self.user_data = user_data or {}

        email = (user_data or {}).get('email', 'N/A')
        cert_details = (user_data or {}).get('certificate_details') or {}
        subject = cert_details.get('subject', {}) if cert_details else {}
        common_name = subject.get('commonName') or subject.get('name') or email

        # Hero section
        self.greeting_label.setText(f"Welcome back, {common_name}!")
        self.hero_subtitle.setText("Here is a snapshot of your signing readiness.")
        self.hero_email_value.setText(email)

        user_row = None
        try:
            user_row = db_helper.get_user(email)
        except Exception:
            user_row = None

        hsm_id = user_data.get('hsm_id') or (user_row.get('hsm_id') if user_row else None)
        self.hero_hsm_value.setText(hsm_id or "Unavailable")
        self.hero_sync_value.setText(_format_timestamp(user_row.get('last_sync') if user_row else None))

        # Certificate card
        if not cert_details:
            self._set_chip_state(self.cert_status_chip, "bad", "Missing")
            self.cert_validity_label.setText("No certificate issued yet")
            self.cert_expiry_hint.setText("Complete registration to receive your digital certificate.")
        else:
            expires_in_days = cert_details.get('expires_in_days')
            valid_from = _format_timestamp(cert_details.get('valid_from'))
            valid_to = _format_timestamp(cert_details.get('valid_to'))
            self.cert_validity_label.setText(f"Valid {valid_from} → {valid_to}")

            if expires_in_days is None:
                self._set_chip_state(self.cert_status_chip, "neutral", "Unknown")
                self.cert_expiry_hint.setText("Unable to determine expiration window.")
            else:
                expires_in_days = int(expires_in_days)
                if expires_in_days < 0:
                    self._set_chip_state(self.cert_status_chip, "bad", "Expired")
                    self.cert_expiry_hint.setText(
                        f"Certificate expired {abs(expires_in_days)} day(s) ago — renew immediately."
                    )
                elif expires_in_days == 0:
                    self._set_chip_state(self.cert_status_chip, "bad", "Expires today")
                    self.cert_expiry_hint.setText("Your certificate expires today. Renew to avoid downtime.")
                elif expires_in_days <= 30:
                    self._set_chip_state(self.cert_status_chip, "warn", f"{expires_in_days} days left")
                    self.cert_expiry_hint.setText(
                        "Plan a renewal now and submit the request from the sidebar when ready."
                    )
                elif expires_in_days <= 45:
                    self._set_chip_state(self.cert_status_chip, "warn", f"{expires_in_days} days left")
                    self.cert_expiry_hint.setText(
                        "You're within the renewal window — use the sidebar to request a new certificate."
                    )
                else:
                    self._set_chip_state(self.cert_status_chip, "good", "Active")
                    self.cert_expiry_hint.setText(f"{expires_in_days} days remaining. All clear.")

        # Security gates card
        if not user_row:
            self._set_chip_state(self.hsm_status_chip, "neutral", "Pending setup")
            self.flags_detail_label.setText("We could not load your device status from the cache.")
        else:
            email_verified = bool(user_row.get('email_verified'))
            device_bound = bool(user_row.get('device_bound'))
            activation_consumed = bool(user_row.get('activation_consumed'))

            if activation_consumed:
                self._set_chip_state(self.hsm_status_chip, "good", "Activated")
            elif device_bound:
                self._set_chip_state(self.hsm_status_chip, "warn", "Bound")
            else:
                self._set_chip_state(self.hsm_status_chip, "bad", "Unbound")

            flags_text = []
            flags_text.append(self._format_flag("Email verified", email_verified))
            flags_text.append(self._format_flag("Device bound", device_bound))
            flags_text.append(self._format_flag("Activation used", activation_consumed))
            self.flags_detail_label.setText("&nbsp;&nbsp;".join(flags_text))

        # Documents card
        docs = []
        try:
            docs = db_helper.get_signed_documents_for_user(email)
        except Exception:
            docs = []

        doc_count = len(docs)
        self.docs_metric_label.setText(str(doc_count))
        if doc_count:
            latest = docs[0]
            ts = _format_timestamp(latest.get('timestamp'))
            filename = latest.get('original_filename') or latest.get('signed_filepath') or "document"
            self.docs_hint_label.setText(f"Last signed: {filename} ({ts})")
        else:
            self.docs_hint_label.setText("Start by signing your first document.")

        # Trust material card
        trust_row = None
        try:
            trust_row = db_helper.get_trust_cache()
        except Exception:
            trust_row = None

        if trust_row:
            version = trust_row.get('crl_version')
            issued = _format_timestamp(trust_row.get('crl_issued_at_utc'))
            synced = _format_timestamp(trust_row.get('last_sync_utc'))
            self.trust_version_label.setText(f"CRL version {version} • Issued {issued}")
            self.set_trust_sync_feedback(f"Last synced {synced}")
        else:
            self.trust_version_label.setText("Root and CRL not downloaded")
            self.set_trust_sync_feedback("Run a sync to pull the latest trust material.")

    def _format_flag(self, label: str, value: bool) -> str:
        if value:
            background = "rgba(103, 210, 134, 0.18)"
            color = "#67d286"
            icon = "✔"
        else:
            background = "rgba(255, 138, 155, 0.18)"
            color = "#ff8a9b"
            icon = "✖"
        return (
            "<span style=\""
            "padding:4px 10px; border-radius:12px; display:inline-block; "
            f"background-color:{background}; color:{color}; font-weight:600;\""
            f">{icon} {label}</span>"
        )
