
<div align="center">
  <img src="nexus-banner.svg" alt="Nexus Browser Banner" width="600"/>
  
  <h3>The Next-Generation Browser: Ultra-Secure, High-Performance, and AI-Native.</h3>
  <p>Built entirely from the ground up in Rust, Nexus is not just a browser—it is your personal digital fortress.</p>

  [![Rust](https://img.shields.io/badge/Built_with-Rust-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
  [![License](https://img.shields.io/badge/License-MPL%202.0%20OR%20Apache--2.0-blue)](LICENSE)
  [![AI Architected](https://img.shields.io/badge/Architected%20by-Claude%20%7C%20Qwen%20%7C%20GLM%205.2-8A2BE2)](#-ai-assistant)
</div>

---

## 🚀 Introduction

Nexus Browser was created with a single goal: **to return absolute control of data and privacy to the user.** 

While traditional browsers are becoming bloated, resource-heavy, and increasingly intrusive, Nexus is built with `wry` and `tao` to deliver a lightweight, silky-smooth experience. We combine a military-grade security layer with a deeply integrated AI engine, powered by the world's leading models.

### 🧠 Architected & Built By
This entire project was architected, coded, and refined through the collaboration of the world's most advanced AI models:
- **Anthropic Claude** (Deep architectural analysis & nuanced system design)
- **Alibaba Qwen** (Lightning-fast code generation & multi-language mastery)
- **Zhipu AI GLM 5.2** (Advanced logic reasoning & mathematical optimization)

---

## ⚖️ Nexus vs. Chrome vs. Brave

Why switch to Nexus?

| Feature | 🌌 Nexus Browser | 🌐 Google Chrome | 🦁 Brave Browser |
| :--- | :---: | :---: | :---: |
| **Core Language** | 🦀 **Rust** (Memory-safe) | C++ (Prone to memory leaks) | C++ (Chromium base) |
| **Telemetry / Tracking** | ❌ **Absolutely NONE** | ✅ Heavy | ⚠️ Anonymized |
| **RAM / Resource Usage** | 🟢 **Extremely Low** (~50-100MB) | 🔴 Very High | 🟡 High |
| **Adblock (YouTube)** | ✅ Built-in (Deep JS Injection) | ❌ Needs Extension | ✅ Built-in (Shields) |
| **Anti-Fingerprint (Canvas/WebGL)**| ✅ **Built-in** | ❌ None | ✅ Basic |
| **Password Vault** | ✅ **AES-256-GCM + Argon2id** | ❌ Weak/Plain | ⚠️ Basic |
| **Tab Freezing** | ✅ **Auto-freeze after 5 mins** | ✅ Yes (Laggy) | ✅ Yes |
| **Tor / WARP Integration** | ✅ **1-Click Native Proxy** | ❌ Needs external app | ❌ No WARP |
| **Built-in AI Assistant** | ✅ **Claude, Qwen, GLM 5.2** | ❌ None | ⚠️ Brave Leo |
| **Multi-thread Download** | ✅ **16 Threads (Parts)** | ❌ 1 Thread | ❌ 1 Thread |

---

## 🛡️ Key Features

### 1. Nexus Shield (Comprehensive Security)
- **Adblock & YouTube Ad-Killer:** Blocks ads entirely and auto-clicks "Skip Ad" on YouTube.
- **Tracker Blocker:** Intercepts `fetch`, `XMLHttpRequest`, and `sendBeacon` to prevent data exfiltration.
- **Cookie Shield:** Filters and blocks cross-site tracking cookies (`_ga`, `fbp`).
- **Anti-Fingerprint:** Spoofs Canvas, WebGL, Hardware Concurrency, and Device Memory to make your browser "invisible."
- **Domain Sinkhole:** Blocks DNS requests to known adware/malware domains.

### 2. Nexus Vault (Unbreakable Password Manager)
- Passwords are encrypted using military-grade **AES-256-GCM**.
- Utilizes **Argon2id** (Password Hashing Competition winner) to protect against brute-force attacks.
- 100% local storage. Your data never touches the cloud.

### 3. AI Assistant (Always at your fingertips)
- Integrated directly into the toolbar. No need to open a new tab.
- Fully customizable API Endpoint to connect to Claude, Qwen, GLM 5.2, or any OpenAI-compatible LLM.
- Retains conversation context (memory) up to 40 messages.

### 4. Maximum Performance
- **Tab Freezing:** Background tabs inactive for 5 minutes are automatically "frozen" to free up RAM and CPU.
- **Turbo Downloader:** Automatically splits downloads into 16 concurrent chunks, boosting download speeds by up to 500%.
- **Rust Async Core:** Uses `Tokio` runtime for non-blocking UI and lightning-fast network requests.

### 5. Anonymity Layer (1-Click Cloaking)
- Instantly route traffic through the **Tor Network**.
- Instantly switch to **Cloudflare WARP**.
- Enforces HTTPS (HSTS) and strips tracking parameters (`utm_*`, `gclid`, `fbclid`) from URLs.

---

## 💻 System Requirements

To run Nexus Browser smoothly, your machine should meet the following minimum specifications:

| Component | Minimum Requirements |
| :--- | :--- |
| **Operating System** | Windows 10/11 (64-bit), macOS 11.0 (Big Sur) or later, Linux (Ubuntu 20.04+, Fedora 34+, Arch) |
| **Processor (CPU)** | Dual-core 64-bit processor (Intel Core i3 / AMD Ryzen 3 equivalent) |
| **Memory (RAM)** | 2 GB RAM (Nexus itself uses ~100MB, but web pages require memory) |
| **Storage** | 150 MB of free disk space |
| **Graphics** | Graphics card with WebGL support (Integrated graphics like Intel UHD are fine) |

---

## 📥 Prerequisites for Tor & WARP Integration

To use the 1-click Tor and Cloudflare WARP proxy features inside Nexus, you need to have their official clients installed and running on your machine:

1. **For Tor Network:** Please download and install the [Tor Browser](https://www.torproject.org/download/). Ensure the Tor service is running in the background (listening on `127.0.0.1:9050`).
2. **For Cloudflare WARP:** Please download and install [Cloudflare WARP VPN](https://1.1.1.1/). Ensure the WARP local proxy mode is active (listening on `127.0.0.1:2053`).

Once they are running, simply toggle the switches in the Nexus sidebar to route your browser traffic through them!

---

## ⚙️ AI Configuration

To use the AI Assistant in Nexus:
1. Open Nexus and click the 🤖 icon in the toolbar.
2. Enter the API Endpoint (e.g., `https://api.openai.com/v1/chat/completions` or your local server).
3. Enter your API Key.
4. Enter the Model Name (e.g., `claude-3-5-sonnet-20241022`, `qwen-max`, `glm-5.2`).
5. Save and start chatting!

---

## 🤝 Contributing

Nexus is an open project and welcomes contributions from the Rust community and privacy enthusiasts alike. If you find a bug or want to propose a new feature, please open an Issue or Pull Request.

## 📜 License

This project is distributed under the **MPL-2.0 OR Apache-2.0** license. See the `LICENSE` file for details.

<div align="center">
Made with ❤️, 🐉, and 🦀 Rust.
</div>
```
