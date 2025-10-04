# CertiFlow

![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

A local, hardware-assisted digital signing application for institutional use, built on a foundation of security and user-friendliness.

---

## 📖 About The Project



**CertiFlow** is a desktop application designed to provide a secure and intuitive digital signing workflow within an organization. It operates on a local network and is split into two distinct parts:

* **User Application:** A client-side GUI that allows users to register, manage their digital identity tied to a hardware device (like a secure USB), sign documents, and view their signed files.
* **CA Owner Application:** A separate GUI for the Certificate Authority administrator to manage user requests, issue certificates, revoke access, and maintain the security of the entire system.

The entire system is built with a "Guided Clarity" UX philosophy, ensuring that even complex cryptographic operations are presented to the user in a simple and understandable way.

### Built With

* [Python 3](https://www.python.org/)
* [PySide6 (Qt for Python)](https://www.qt.io/qt-for-python)
* [Cryptography](https://cryptography.io/en/latest/)

---

## ✨ Features

-   **Secure Registration:** User-guided process for key generation and Certificate Signing Request (CSR) submission.
-   **Hardware-Assisted Authentication:** Private keys are intended to be stored on and used from a hardware device, never leaving it.
-   **PDF & Detached Signing:** In-place signing for PDF documents and creation of detached `.sig` files for all other file types.
-   **CA Management:** A complete interface for the CA owner to approve, reject, or revoke user certificates.
-   **Audit Logging:** Comprehensive logging of all critical actions performed by users and administrators.
-   **Secure Backups:** Functionality for the CA owner to create and restore encrypted backups of the database.

---

## 🚀 Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

You will need Python 3.10 or newer installed on your system.

### Installation

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/saltyma/CertiFlow.git
    cd CertiFlow
    ```

2.  **Create and activate a virtual environment** (recommended):
    * Windows:
        ```sh
        python -m venv venv
        .\venv\Scripts\activate
        ```
    * macOS / Linux:
        ```sh
        python3 -m venv venv
        source venv/bin/activate
        ```

3.  **Install the required packages:**
    ```sh
    pip install -r requirements.txt
    ```

4.  **Run the initial setup scripts** to create the necessary databases and folder structures:
    ```sh
    python create_ca_db.py
    python create_user_cache.py
    ```

---

## 🏃‍♀️ Usage

The project is divided into two applications. You will need to run them in separate terminal windows.

1.  **Start the CA Owner Application:**
    ```sh
    python ca_app/main.py
    ```
    On the first run, this application will guide you through setting up the root CA administrator.

2.  **Start the User Application:**
    ```sh
    python user_app/main.py
    ```
    Users can then register and, once approved by the CA owner, log in and sign documents.

---

## 🗺️ Roadmap

The current version of CertiFlow uses standard USB drives as a stand-in for a true Hardware Security Module (HSM). The next major development phase involves integrating a dedicated microcontroller for enhanced security.

-   [ ] **Phase 1: Communication:** Establish USB communication with the STM32U585 board.
-   [ ] **Phase 2: TrustZone:** Implement a basic TrustZone secure/non-secure firmware.
-   [ ] **Phase 3: Crypto Core:** Move key generation and signing functions into the secure world of the MCU.
-   [ ] **Phase 4: Full Integration:** Update the Python application to communicate with the hardware HSM.

See the open issues for a full list of proposed features (and known issues).

---

## 📜 License

Distributed under the MIT License. See `LICENSE.txt` for more information.

---

## 📧 Contact

Salma - salmalemrazzeq@gmail.com 

Project Link: [CertiFlow](https://github.com/saltyma/CertiFlow)
"# CertiFlowV3" 
