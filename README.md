<p align="center">
  <img src="https://img.shields.io/badge/LICENSE-MPL--2.0-ff007f?style=for-the-badge" />
  <img src="https://img.shields.io/badge/RUST-ELITE-orange?style=for-the-badge&logo=rust" />
  <img src="https://img.shields.io/badge/ARCHITECTURE-SINGLE%20FILE-green?style=for-the-badge" />
</p>

<pre align="center" style="color: #00f0ff; font-weight: bold;">
███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
       E L I T E   R U S T   E D I T I O N
</pre>

<h3 align="center">
  The Ultra-Optimized, Zero-Bloat, Cyberpunk Web Browser.<br>
  <i>Engineered strictly for extreme low-spec environments (4GB DDR3 RAM) without sacrificing modern web capabilities.</i>
</h3>

---

## 🧬 // SYSTEM PHILOSOPHY

Modern browsers are bloated memory hogs. **Nexus** rejects this paradigm. Built entirely in a **single `src/main.rs` file**, Nexus leverages the raw power of Rust, `tao`, and `wry` (WebKit2GTK) to deliver a secure, high-performance browsing experience that compiles down to a microscopic binary and runs flawlessly on legacy hardware.

No crypto wallets. No heavy AI sidebars. No telemetry. Just pure, unadulterated web rendering protected by an elite privacy shield.

---

## ⚡ // CORE FEATURES

### 🚀 32-Thread Backpressure Turbo Downloader
Forget standard HTTP downloads. Nexus splits files into 32 concurrent chunks, utilizing strict backpressure and asynchronous disk streaming. 
* **Zero RAM Spikes:** Chunks are flushed instantly via 4KB micro-buffers.
* **IDM-Level Speeds:** Saturates network bandwidth without choking the CPU or causing OOM crashes on 4GB systems.

### 🛡️ Aggressive Domain Sinkholing
A multi-layered defense system intercepts network requests before they hit the WebKit engine.
* **Local Blocklists:** Instantly drops Ads, Trackers, and Intrusive Cookies.
* **Regex Sinkhole:** Hardcoded regex patterns neutralize `doubleclick`, `mixpanel`, and `facebook/tr` at the rust-level pipeline.

### 🧊 Automated Inactive Tab Freeze (RAM Reclamation)
Nexus monitors DOM interaction. If a tab sits idle for >60 seconds, the background worker injects an eviction script, wiping the DOM tree and replacing it with a lightweight "FROZEN" placeholder, instantly returning megabytes of RAM to the OS.

### 🕵️ True Incognito Isolation
Boots WebKit in strict incognito mode. No persistent cache, no local storage, no cookie leakage. When you close Nexus, your digital footprint evaporates.

### 🎨 Neon Cyberpunk GUI
A hyper-minimalist HTML/CSS/JS shell injected directly into the WebKit context.
* **Dark Mode:** Deep void black (`#0a0a0c`) with Cyan (`#00f0ff`) and Pink (`#ff007f`) neon accents.
* **Light Mode:** Fluent design fallback for high-contrast environments.
* **Live Metrics:** Real-time flashing counters for blocked malicious requests.

---

## 🏗️ // ARCHITECTURE OVERVIEW

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Windowing** | `tao` | Cross-platform window creation and event loop. |
| **Rendering** | `wry` | Lightweight WebKit2GTK bindings. |
| **Async Core** | `tokio` | Multi-threaded runtime for network & I/O. |
| **Networking** | `reqwest` (rustls) | TLS-encrypted HTTP client with SOCKS5/Tor proxy support. |
| **State** | `Arc<RwLock<State>>` | Thread-safe, lock-free global state management. |

---

## 🤖 // AI DEVELOPMENT STACK

Nexus Browser was architected through a specialized multi-model AI collaboration pipeline. Each model was assigned a distinct role to ensure maximum code quality, architectural integrity, and validation:

| AI Model | Role | Contribution |
| :--- | :--- | :--- |
| **Qwen** | **Elite Systems Engineer** | Authored the entire single-file Rust architecture, implemented the 32-thread backpressure downloader, optimized WebKit2GTK memory hooks, and performed aggressive code compression for 4GB DDR3 targets. |
| **Gemini** | **Systems Architect & Planner** | Designed the initial Brave-inspired feature set, planned the domain sinkholing logic, structured the IPC protocol between Rust and WebKit, and defined the extreme release optimization profile. |
| **Replit Agent** | **QA & Validation Tester** | Executed real-time compilation checks, validated async deadlock safety in the turbo downloader, tested GUI responsiveness under memory pressure, and verified MPL-2.0 license compliance. |

> *"This project represents the convergence of human intent and distributed artificial intelligence, pushing Rust to its absolute limits on constrained hardware."*

---

## 🎮 // INTERFACE CONTROLS

| Action | Trigger | Description |
| :--- | :--- | :--- |
| **Navigate** | `Enter` in URL bar | Routes through Nexus Search or direct HTTP. |
| **Turbo Download** | `⬇ TURBO` button | Fires the 32-thread backpressure engine on the current URL. |
| **Dev Console** | `⚙ DEV` button | Slides out the Neon Dev Panel with live network logs. |
| **Theme Toggle** | `🌓` button | Hot-swaps CSS variables between Cyberpunk Dark and Fluent Light. |
| **Shield Toggles** | Sidebar Switches | Enable/Disable Ads, Trackers, and Sinkhole routing on the fly. |

---

## ⚖️ // LICENSE

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**. 

You are free to use, modify, and distribute this software. However, any modifications made to the original source files must be made available under the same MPL-2.0 license. See the `LICENSE` file in the repository root for full legal terms.

---
<p align="center">
  <b>⟁ NEXUS BROWSER ⟁</b><br>
  <sub>Forged by Qwen • Planned by Gemini • Validated by Replit</sub>
</p>
