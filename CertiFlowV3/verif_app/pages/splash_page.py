# Splash/startup page that shows CertiFlow logo and message.
# pages/splash_page.py

# verif_app/pages/splash_page.py
from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGraphicsOpacityEffect
from PySide6.QtCore import Qt, QTimer, Signal, QPropertyAnimation, QEasingCurve
import os

class SplashPage(QWidget):
    splash_done = Signal()

    def __init__(self):
        super().__init__()
        self.setObjectName("SplashPage")
        self.setWindowFlags(Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setAlignment(Qt.AlignCenter)

        self.content_widget = QWidget()
        self.card_layout = QVBoxLayout(self.content_widget)
        self.card_layout.setAlignment(Qt.AlignCenter)
        self.card_layout.setSpacing(10) # Spacing between logo and the text block below it

        # --- Logo ---
        self.logo_label = QLabel("Certi<span style='color:#16a34a;'>Flow.</span>")
        self.logo_label.setObjectName("SplashTitle")
        self.card_layout.addWidget(self.logo_label)

        # --- NEW: Grouping container for text below the logo ---
        # This prevents the text from ever overlapping with the large logo above it.
        text_container = QWidget()
        text_layout = QVBoxLayout(text_container)
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(5) # Keep these lines close together
        text_layout.setAlignment(Qt.AlignCenter)

        self.subtitle_label = QLabel("Secure Document Verifier")
        self.subtitle_label.setObjectName("SplashSubtitle")
        text_layout.addWidget(self.subtitle_label)

        self.hint_label = QLabel("Initializing...")
        self.hint_label.setObjectName("SplashHint")
        text_layout.addWidget(self.hint_label)
        
        # Add the container to the main card layout
        self.card_layout.addWidget(text_container)
        # --- End of fix ---
        
        self.main_layout.addStretch()
        self.main_layout.addWidget(self.content_widget)
        self.main_layout.addStretch()

        # --- Opacity Animation ---
        self.opacity_effect = QGraphicsOpacityEffect(self.content_widget)
        self.content_widget.setGraphicsEffect(self.opacity_effect)
        self.animation = QPropertyAnimation(self.opacity_effect, b"opacity")
        self.animation.setDuration(1200)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setEasingCurve(QEasingCurve.InQuad)

        # --- Timer for transition ---
        self.timer_duration = 5000
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.emit_splash_done)

    def showEvent(self, event):
        super().showEvent(event)
        self.animation.start()
        self.timer.start(self.timer_duration)

    def emit_splash_done(self):
        self.splash_done.emit()