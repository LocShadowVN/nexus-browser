# 🌐 N E X U S // B R O W S E R 
### ⚡ Elite Rust Edition — Hardened & Ultra-Lightweight Core

![Rust](https://img.shields.io/badge/language-Rust-hf4c5d?style=for-the-badge&logo=rust)
![License](https://img.shields.io/badge/license-MPL%202.0%20%7C%20Apache%202.0-00ffff?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Windows%20Native-ff007f?style=for-the-badge&logo=windows)
![Architecture](https://img.shields.io/badge/architecture-Single--File-matrix?style=for-the-badge)

---

Nexus is a hardened, resource-conscious embedded web browser core engineered entirely within a single-file architecture (`src/main.rs`). It is specifically architected to deliver a secure, secure-core browsing environment for low-end systems, optimizing memory and process overhead for legacy machines running on **4GB RAM** or traditional **HDD storage**.

---

## ⚡ Core Engine & Features

### 🛡️ Autonomous Shield Matrix
* **Ad & Tracker Suppression:** Built-in string-matching filtering matrix that instantly intercepts malicious ad networks (`adsystem`, `adnxs`) and analytical telemetry tracking scripts (`segment.io`, `fingerprint`).
* **Domain Sinkholing:** Hardcoded network sinkhole to capture and neutralize heavy tracking domains (`doubleclick`, `adsense`, `hotjar`) before they consume system bandwidth.
* **Privacy & Anti-Fingerprinting:** Standardizes browser identity by masking headers, applying explicit `Do Not Track (DNT)` configurations, and disabling WebKit compositing modes to minimize the system’s unique hardware fingerprint.

### 🔒 Multi-Protocol Routing & Stealth Mode
* **Flexible Proxy Gateway:** Native routing support allowing users to easily toggle traffic through a custom global proxy setup.
* **Tor Network Integration:** Instant single-click SOCKS5h routing (`socks5h://127.0.0.1:9050`) to pass traffic through local Tor instances for anonymous requests.
* **Cloudflare WARP Support:** Built-in network profiles pre-configured to utilize local WARP endpoints for quick encryption layers.
* **Stealth Incognito Theme:** An isolated browsing profile that dynamically switches the UI to a dedicated cyber-stealth aesthetic, modifies input placeholders for private querying, and wipes sensitive session traces.

### 🚀 High-Performance Utility Modules
* **16-Part Segmented Downloader:** A high-speed concurrent file downloader (`dl::turbo`) utilizing asynchronous semaphores to execute parallel byte-range requests, maximizing bandwidth efficiency on low-resource machines.
* **Embedded AI Interface:** A direct FIFO-bounded chat component linked straight to the Google Gemini API, capable of managing memory rotation within a 40-message context boundary.
* **Hardened Memory Safety:** Implements automated memory scrubbing on drop. When the application terminates, critical state logs, history records, and API key strings are explicitly cleared and written over in memory to prevent cold-boot memory scraping.

---

## 🛠️ Technological Architecture

Nexus links lightweight cross-platform system windowing with an embedded rendering engine to maximize responsiveness without the heavy bloat of a full Chromium profile.

* **UI Rendering Context:** `wry` (v0.45) & `tao` (v0.30) for native OS harmonization and low-level IPC event-loop communication.
* **Asynchronous Runtime:** `tokio` multi-threaded task management, explicitly bound to a fixed worker pool to separate UI operations from I/O execution.
* **Network Stack:** `reqwest` & `futures-util` handling raw byte-streams and direct TLS client construction.

---

## ⚖️ Dual-License Framework

This project is distributed as open-source software under a dual-licensing model, giving developers full flexibility based on their deployment environment:

* **[Mozilla Public License 2.0 (MPL-2.0)](./LICENSE-MPL)**
* **[Apache License 2.0 (Apache-2.0)](./LICENSE-APACHE)**

Users and contributors are legally permitted to choose either license to govern their use of this software. For closed-source commercial compositions, the permissive terms of **Apache 2.0** can be selected. For standard core modifications where isolated file-level open-source contributions are preferred, the **MPL 2.0** rules apply.

*Full legal documentations are maintained in the accompanying `LICENSE-MPL` and `LICENSE-APACHE` files.*
