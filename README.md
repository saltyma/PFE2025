# CertiFlow – Secure Local PKI & Hardware Signing

CertiFlow is a hardware-anchored PKI signing infrastructure combining:
• A custom hardware signing module (HSM)
• Local certificate authority and CRL management
• Offline signature verification
• Audit logging and trust boundaries

It demonstrates private-key isolation, offline trust, and DFIR-oriented auditability
in a fully local environment.

📄 **Technical Whitepaper (PDF):** [CertiFlow-Technical-Report.pdf](docs/CertiFlow-Technical-Report.pdf)

---

CertiFlow couples a desktop certificate-authority workflow with a dedicated STM32U5-based
hardware security module (HSM). The repository contains two major deliverables:

* **`STM32U5_USBX_crypto/`** – Azure RTOS–based firmware that turns an STM32U5 MCU into a
  USB composite device exposing a virtual smartcard-like command set used for key
  management and signing. A pre-built binary is provided alongside the full
  STM32CubeIDE project.
* **`CertiFlowV3/`** – A suite of PySide6 desktop applications (CA Owner, User, and
  Verifier) plus a Flask API server that orchestrate HSM provisioning, certificate
  issuance, document signing, and signature verification.

Use this README as an end-to-end guide covering firmware build/flash procedures, local
Python environment setup, configuration, and the operational flows for provisioning
hardware, registering end users, and verifying signatures.

---

## Repository layout

| Path | Description |
| --- | --- |
| `STM32U5_USBX_crypto/` | Complete STM32CubeIDE project for the HSM firmware plus a ready-made `.bin` image. |
| `CertiFlowV3/ca_app/` | CA Owner desktop application and the Flask API server used by all clients. |
| `CertiFlowV3/user_app/` | End-user desktop application for registration, signing, and verification. |
| `CertiFlowV3/verif_app/` | Standalone verifier desktop application for offline signature checks. |
| `CertiFlowV3/create_user_cache.py` | Creates the encrypted local cache used by the user app. |
| `CertiFlowV3/create_ver_db.py` | Initializes the verifier app database. |
| `CertiFlowV3/requirements.txt` | Python dependencies shared by all CertiFlow applications. |

---

## Prerequisites

### Hardware

* STMicroelectronics **STM32U5** development board compatible with the provided project
  (tested on STM32U585 devices).
* USB Type-C/Type-A cables for both firmware flashing and virtual COM-port access.
* A freshly formatted or empty USB mass-storage device dedicated to storing the CA Owner’s
  root keys (e.g., a USB flash drive). Keep it connected only when performing CA Owner
  operations to avoid accidental selection.

### Software

| Component | Recommendation |
| --- | --- |
| Firmware toolchain | STM32CubeIDE 1.15 (or newer with STM32U5 support) and the ST-LINK/V3 drivers. |
| Flasher (optional) | STM32CubeProgrammer if you prefer flashing the provided binary manually. |
| Python | CPython 3.10 or newer on Windows, Linux, or macOS. All apps were tested on Windows 10 and Ubuntu 22.04. |
| Python package manager | `pip` (bundled with modern Python releases). |
| Serial terminal | PuTTY (Windows) or screen/minicom (Linux/macOS) for interacting with the HSM console. |

### Python dependencies

All CertiFlow desktop applications share the same dependency set. Create a virtual
environment and install the requirements once:

```bash
cd CertiFlowV3
python -m venv .venv
source .venv/bin/activate  # On Windows use: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

The `requirements.txt` file includes GUI, cryptography, USB serial, HTTP, and testing
libraries required by every CertiFlow component.

After installing the dependencies you can initialize the local databases using the
provided helper scripts (see [Initialize the desktop databases](#initialize-the-desktop-databases)).

---

## Firmware: `STM32U5_USBX_crypto`

### Build the firmware in STM32CubeIDE

1. Launch STM32CubeIDE and import the project (`File` → `Open Projects from File System…`
   → Select the `STM32U5_USBX_crypto` directory).
2. Open `STM32U5_USBX_crypto.ioc` if you want to review middleware configuration (Azure
   RTOS, USBX CDC-ACM class, etc.). Generate code if prompted.
3. Build the `STM32U5_USBX_crypto` target (`Project` → `Build All`). The IDE produces an
   ELF and BIN inside `STM32U5_USBX_crypto/Debug/`.
4. Connect the STM32U5 board via ST-LINK and run `Debug` or `Run` to flash directly from
   the IDE.

### Flash the provided binary without building

If you simply want to evaluate the firmware, flash the ready-made image located at
`STM32U5_USBX_crypto/STM32U5_USBX_crypto.bin` using STM32CubeProgrammer or STM32CubeIDE’s
`External Tools → Program` dialog.

1. Connect the board via USB (ST-LINK interface).
2. Launch STM32CubeProgrammer, connect to the target, and browse for the provided `.bin`.
3. Program the image at address `0x08000000` and start execution.

### Access the HSM command channel over USB (PuTTY)

The firmware enumerates as a USB CDC-ACM virtual COM port configured for 115200 bps, 8 data
bits, no parity, and one stop bit.

1. After flashing, connect the board’s USB data port to your PC.
2. Locate the assigned COM port (Windows Device Manager → “Ports (COM & LPT)”; on Linux
   use `dmesg | tail` for `/dev/ttyACM*`).
3. Open PuTTY (or another terminal) with:
   * Speed: **115200**
   * Data bits: **8**
   * Parity: **None**
   * Stop bits: **1**
   * Flow control: **None**
4. Press Enter. Once the firmware finishes booting and the CA Owner application binds the
   device, you can issue ASCII commands followed by `Enter`.

#### HSM command reference

All commands return a status line prefixed with `OK` or `ERR`. Some commands also send a
second line payload (e.g., base64 data). The session times out automatically if idle.

| Command | Syntax | Requires unlocked session? | Description & Notes |
| --- | --- | --- | --- |
| `INFO` | `INFO` | No | Returns the firmware identification banner (`OK HSM-EMU v0.1`). |
| `HSMID` | `HSMID` | No | Responds with a unique device identifier used during provisioning. Payload is on the next line. |
| `PING` | `PING` | No | Health check returning `OK PONG`. Useful for connectivity tests. |
| `UNLOCK` | `UNLOCK <PIN>` | No | Unlocks the keystore. On first use it sets the PIN and returns `OK NEWPIN`; subsequent successful unlocks return `OK UNLOCKED`. Five failed attempts trigger a temporary lockout (`ERR LOCKED`). |
| `LOGOUT` | `LOGOUT` | Yes (active session) | Ends the session and returns `OK BYE`. Use when you are done using the device. |
| `RESET` | `RESET` | Yes | Terminates the session and clears transient state (response `OK RESET`). |
| `FACTORY` | `FACTORY` | Yes | Wipes the stored PIN and key material. Only available while unlocked to avoid remote wipes. Use with caution; response `OK FACTORY` if successful. |
| `KEYGEN` | `KEYGEN EC P256` | Yes | Generates a new P-256 key pair if none exists and persists it. Returns `OK KEYGEN` or `OK KEYEXISTS` if a key is already present. |
| `PUBKEY` | `PUBKEY` | Yes | Sends a base64-encoded SubjectPublicKeyInfo for the resident key pair on the next line (`OK PUBKEY`). |
| `SIGN` | `SIGN SHA256 <64-hex-digest>` | Yes | Signs a SHA-256 digest with the stored private key and returns the DER-encoded ECDSA signature in base64 (`OK SIG`). Digest must be 64 hex characters. |

---

## CertiFlow desktop applications (`CertiFlowV3`)

### Initialize the desktop databases

After installing the Python dependencies, create the local SQLite databases required by the
user and verifier applications (the CA Owner database is created automatically on first
launch):

```bash
cd CertiFlowV3
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
python create_user_cache.py
python create_ver_db.py
```

These scripts can be re-run safely; they ensure schema creation and migrations when needed.

### Configure email, networking, and identity settings

Before launching any application, review the configuration files and adjust the hardcoded
placeholders:

| File | Key fields to update | Purpose |
| --- | --- | --- |
| `ca_app/config.json` | `sender_email`, `app_password`, `token_secret`, `api_base_url`, `email_cooldown_seconds` | Sets the SMTP credentials used to email activation links and the base URL that other apps should reach. |
| `user_app/config.py` | `CA_API_URL` | Endpoint for the CA Owner API (use an IP/hostname reachable by the user machine). |
| `verif_app/config.py` | `CA_API_URL`, `LOG_SYNC_EMAIL`, optional `APP_VERSION` | Configure the API endpoint and the audit-log identity for the verifier application. |

*For multi-machine deployments* set `api_base_url`, `CA_API_URL`, and the email templates
so that HTTPS domains (e.g., `https://ca.example.com`) are reachable by every node.
Update DNS, firewall rules, and reverse proxies accordingly.

> ⚠️ **Email delivery** – The CA Owner app sends verification emails via SMTP using
> the credentials in `ca_app/config.json`. Supply an application-specific password and
> allow the account to send transactional email. Without this, user email verification
> links will fail.

### Launch order and runtime layout

1. **Start the CA Owner API server** (Terminal A):
   ```bash
   cd CertiFlowV3
   source .venv/bin/activate
   python -m waitress --listen=0.0.0.0:7001 ca_app.api_server:app  # production-style
   # or for quick tests:
   python ca_app/api_server.py
   ```
   The API exposes health and provisioning endpoints at the base URL configured above.

2. **Start the CA Owner desktop application** (Terminal B):
   ```bash
   cd CertiFlowV3
   source .venv/bin/activate
   python ca_app/main.py
   ```
   * On first launch, the app detects that no CA database exists and opens the **Setup**
     page. Insert the dedicated USB storage device and carefully select it as the root-key
     destination.
   * Create the initial Root CA Owner account. The application generates and stores the
     CA private key, writes it to the selected USB device, and seeds the local database.

   > ⚠️ **USB selection warning** – Double-check the chosen drive letter/path when storing
   > root keys. Selecting the wrong device will overwrite its contents.

3. **Start the User and Verifier applications** (each in their own terminal or machine):
   ```bash
   # User application
   cd CertiFlowV3
   source .venv/bin/activate
   python user_app/main.py

   # Verifier application
   cd CertiFlowV3
   source .venv/bin/activate
   python verif_app/main.py
   ```

### HSM provisioning and user onboarding workflow

Follow this sequence whenever you flash a new STM32U5 HSM and onboard a user:

1. **Flash and connect the HSM** using the firmware instructions above. Leave it connected
   to the CA Owner workstation.
2. **Bind the HSM to an email account** in the CA Owner app:
   1. Navigate to the *HSM Provisioning* page.
   2. Detect the new device (the app listens for the `HSMID` exposed over the CDC channel).
   3. Enter the user’s email address—the same address that will later receive the
      verification email.
   4. Record the generated **activation code**. Store it securely; the user will need it to
      complete registration.
3. **Update CA Owner email settings** (`ca_app/config.json`) with the SMTP credentials that
   can send to the user’s mailbox. Restart the API server after editing the file.
4. **User registration** (on the user’s PC):
   1. Connect the provisioned HSM and ensure the drivers load.
   2. Launch `python user_app/main.py`.
   3. On the registration page, supply the same email address, the activation code from the
      CA Owner, choose a strong HSM PIN (4–32 digits/characters), and enter the user’s name.
   4. The app communicates with the API server, unlocks the HSM, generates keys if needed,
      and submits a certificate signing request (CSR).
5. **Email verification**: The user receives an activation email with a link. They must
   open it to mark their account as verified.
6. **CA Owner approval**: In the CA Owner dashboard, review the pending request. Once the
   email is verified, the HSM is bound, and the activation code is consumed, approve the
   request using the CA Owner password. This issues the certificate.
7. **User operations**: The user can now sign PDFs/documents, view history, and verify
   signatures directly within the user app. The included verifier app can validate
   signatures without logging in, making it suitable for third parties.

### Running across multiple machines or domains

* Ensure firewalls allow TCP access to the Flask API port (default 7001).
* If serving over the internet, terminate TLS and update `api_base_url`, `CA_API_URL`, and
  email templates to point at the HTTPS domain.
* Adjust `LOG_SYNC_EMAIL` (verifier app) and any audit-log routing rules so that they match
  your organizational email addresses.

### Hardcoded values to review before production

* `ca_app/config.json` → `token_secret`: replace with a high-entropy random string.
* `ca_app/config.json` → `email_cooldown_seconds`: tune to control how often activation
  emails can be resent.
* `user_app/config.py` and `verif_app/config.py` → API URLs and audit-email addresses.
* Any static file paths for document storage inside the apps (default is user home
  directories; adjust within the GUI settings if necessary).

---

## Operational tips

* Keep the dedicated USB storage with CA keys offline when not actively issuing
  certificates.
* Back up the CA Owner SQLite database and USB keystore regularly. The CA Owner app
  includes backup utilities under **Settings → Backups**.
* The HSM firmware enforces PIN lockouts. If you trigger a lockout, wait for the lockout
  timer to expire (30 seconds per event by default) before attempting another unlock.
* Use the `FACTORY` command only during device recycling. It wipes all credentials and
  requires re-provisioning from scratch.

---

## Support & contributions

Issues and enhancements can be tracked through your chosen project management workflow.
Before submitting patches, ensure that `pytest` and manual smoke tests on all three desktop
applications pass while connected to a test HSM running the provided firmware.
