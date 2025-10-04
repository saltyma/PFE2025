"""
Verifier App configuration
--------------------------
Holds constants and settings for the Verifier app.
"""

# URL of the CA server API (LAN or localhost).
# Example: "http://127.0.0.1:5000/api"
# Adjust depending on where you run your CA app.
CA_API_URL = "http://127.0.0.1:7001/api"

# Default DB filename (used by ver_db_helper)
DB_FILENAME = "verifier_app.sqlite"

# Application metadata
APP_NAME = "CertiFlow Verifier"
APP_VERSION = "1.0.0"

# Email identity used when pushing audit logs to the CA owner API.
LOG_SYNC_EMAIL = "verifier@certiflow.local"
