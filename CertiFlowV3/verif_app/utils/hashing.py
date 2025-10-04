# verif_app/utils/hashing.py

"""
Hashing helpers for the Verifier application.
- `hash_pdf_normalized_text`: Replicates the user_app's hashing of extracted text for signature verification.
- `sha256_file_hex`: Hashes the entire file for identification purposes.
"""

from __future__ import annotations
from typing import Tuple
import hashlib
import os
import pypdf

def hash_pdf_normalized_text(path: str) -> Tuple[bytes | None, str | None]:
    """
    Extracts all text from a PDF, normalizes it, and returns its SHA-256 hash.
    This is the correct method for signature verification, matching the user_app.
    """
    try:
        reader = pypdf.PdfReader(path)
        text_content = ""
        for page in reader.pages:
            extracted = page.extract_text()
            if extracted:
                text_content += extracted
        
        # Normalize whitespace to ensure consistent hashing
        normalized_text = " ".join(text_content.split())
        
        return hashlib.sha256(normalized_text.encode("utf-8")).digest(), None
    except Exception as e:
        return None, f"Failed to extract or hash PDF text content: {e}"


def sha256_file_hex(path: str) -> Tuple[str | None, str | None]:
    """
    Computes the SHA-256 hash of a file's raw byte content and returns it as a hex string.
    Used for uniquely identifying the file version in the database.
    """
    if not os.path.exists(path):
        return None, "File not found."
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest(), None
    except Exception as e:
        return None, f"Failed to hash file: {e}"

