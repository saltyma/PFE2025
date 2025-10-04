# user_app/utils/email_verifier.py

# Define the required institutional domain as a constant.
# This makes it easy to change if needed in the future without searching the code.
INSTITUTIONAL_DOMAIN = "uit.ac.ma"


def is_valid_institutional_email(email: str) -> tuple[bool, str]:
    """
    Validates if the provided email is a valid institutional email address.

    Checks:
    - Input type is str
    - Not empty after trimming
    - Contains '@' and has a non-empty local part
    - Ends with '@uit.ac.ma' (case-insensitive)

    Returns:
        (is_valid: bool, message: str)
    """
    if not isinstance(email, str):
        return (False, "Error: Input must be a valid text format.")

    cleaned_email = email.strip()

    if not cleaned_email:
        return (False, "Email cannot be empty. Please enter your email.")

    if '@' not in cleaned_email:
        return (False, "Invalid email format. Please include an '@'.")

    if cleaned_email.startswith('@'):
        return (False, "Invalid email format. Name is missing before '@'.")

    if not cleaned_email.lower().endswith(f"@{INSTITUTIONAL_DOMAIN}"):
        return (False, f"Access denied. Email must be from the institution (@{INSTITUTIONAL_DOMAIN}).")

    return (True, "Email address is valid.")


# ---------------------------------------------------------------------------
# Optional helper: trigger a verification email via the CA (V3 flow)
# Endpoint: POST /api/email/send_verification
# Implemented as a soft dependency to avoid import cycles; imported on demand.
# ---------------------------------------------------------------------------
def resend_verification_email(email: str) -> tuple[bool, str]:
    """
    Requests the CA to resend a verification email to `email`.

    Returns:
        (ok: bool, message: str)
    """
    is_valid, msg = is_valid_institutional_email(email)
    if not is_valid:
        return False, msg

    try:
        # Lazy import to avoid circular imports in utils.*
        from utils import ca_sync_handler  # noqa: WPS433 (runtime import intended)
    except Exception as e:
        return False, f"Internal error: CA sync module unavailable ({e})."

    ok, message = ca_sync_handler.send_verification_email(email)
    return ok, message


# ---------- Example Usage (for standalone testing) ----------
if __name__ == "__main__":
    test_cases = [
        "student.name@uit.ac.ma",      # Valid
        " professor@uit.ac.ma ",       # Valid (with whitespace)
        "ADMIN@UIT.AC.MA",             # Valid (uppercase)
        "invalid@gmail.com",           # Invalid domain
        "test@uca.ac.ma",              # Invalid domain
        "missing_at_symbol.com",       # Invalid format
        "@uit.ac.ma",                  # Invalid format
        "",                            # Empty
        "   ",                         # Empty (whitespace only)
        None,                          # Invalid type
        12345                          # Invalid type
    ]

    print("--- Testing Email Verifier Function ---")
    for test_email in test_cases:
        is_valid, message = is_valid_institutional_email(test_email)
        status = "✅ Valid" if is_valid else "❌ Invalid"
        print(f"Email: '{test_email}'")
        print(f"  ↳ Status: {status}, Message: {message}\n")
