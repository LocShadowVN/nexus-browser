# 🌐 Nexus Browser (Rust Edition)

![License](https://img.shields.io/badge/License-MPL_2.0-brightgreen?style=for-the-badge)
![Language](https://img.shields.io/badge/Language-Rust-orange?style=for-the-badge&logo=rust)
![RAM Usage](https://img.shields.io/badge/RAM_Footprint-Ultra__Low-cyan?style=for-the-badge)

**Nexus Browser** is a next-generation, open-source web browser completely rewritten from Python into **Rust**. Built from the ground up to eradicate resource hogging, ensure absolute memory safety, and achieve sub-millisecond execution speeds, Nexus packs high-end security tools and a hyper-modern Fluent/Cyberpunk interface into a highly streamlined Single-File Architecture (`main.rs`).

---

## ⚡ Core Features

### 🛠️ Hardware & Memory Optimization
* **Smart RAM Freezing:** Automatically suspends and flushes memory assets of hidden tabs after 5 minutes of inactivity, bringing dynamic tab resource usage down to near 0.
* **Rust-Native Safety:** Runs entirely without a Garbage Collector, eliminating memory leaks and freeing allocation bytes immediately back to the OS the moment a task finishes.

### 🛡️ Premium Cyber-Security Suite
* **Premium Adblocker:** A high-performance content blocking sub-engine hooked directly into the webview request pipeline, dropping malicious trackers and ad domains before the page loads.
* **Tor & SOCKS5 Proxy Integration:** Toggles complete onion routing (via 127.0.0.1:9050) and encrypted proxies to encapsulate all browser traffic, isolating your digital footprint.
* **Incognito Mode:** Spawns completely sandboxed, in-memory private sessions that leave zero persistent logs, cache, or cookies behind.
* **Password Vault:** Secure identity manager equipped with a cryptographically secure, high-entropy randomized strong password generator.

### 🤖 Nexus AI Sidebar
* **40-Turn Persistent Memory:** A fully asynchronous, non-blocking sidebar assistant running on background workers. Features a strict rolling FIFO mechanism to lock conversation memory at exactly 40 turns without ever stuttering the active UI thread.

### 🚀 64-Thread Turbo Downloader
* An IDM-style native download accelerator. It reads HTTP `Content-Length`, splits remote files into exactly 64 concurrent chunk segments utilizing `tokio` and `reqwest`, and merges them sequentially with absolute data integrity and real-time speed tracking.

### 🎨 Fluent Localization & Custom Navigation
* **Dynamic Theme Switcher:** Hot-swappable toggle between **Dark Cyberpunk** (`#0a0a0c`, neon cyan glow, neon pink highlights) and **Light Modern** (`#f5f6f8`, fluent blue, deep slate text matrices).
* **UI Interface Language (EN/VI):** Seamlessly swap all interface components, menus, and buttons between English and Vietnamese on the fly.
* **Web Page Translator:** Translate foreign-language web nodes into Vietnamese with a single click.
* **Smart Search Router:** Displays an aesthetic native Nexus Start Page with real-time browser CPU/RAM diagnostic widgets. Typing a search query into the address bar automatically parses and redirects the tab seamlessly to Google Search.
* **Developer Mode:** An integrated debugging panel featuring live DOM logs, a compact network request inspector, and an interactive JavaScript execution console.

---

## 🏗️ Project Architecture

To maximize testability, compilation speed, and audit efficiency, the entire codebase utilizes a rigid **Single-File Architecture**:

```text
├── Cargo.toml        # Crate declarations (tokio, reqwest, webview, etc.)
└── src
    └── main.rs       # Single source of truth containing all inline modules & logic
