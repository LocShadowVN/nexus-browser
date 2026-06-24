use std::sync::Arc;
use std::time::Instant;
use tao::{
    event::{Event, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::WebViewBuilder;
use tokio::runtime::Builder;
use tokio::sync::RwLock;

pub mod state {
    use super::*;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Clone, Debug, PartialEq)]
    pub enum Theme { Dark, Light }

    #[derive(Clone, Debug, PartialEq)]
    pub enum Lang { EN, VI }

    #[derive(Clone, Debug, Default)]
    pub struct Cfg {
        pub proxy: bool,
        pub proxy_url: String,
        pub tor: bool,
        pub warp: bool,
        pub dev: bool,
        pub ad: bool,
        pub trk: bool,
        pub sinkhole: bool,
        pub cookie: bool,
        pub anti_fp: bool,
    }

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultEntry {
        pub domain: String,
        pub user: String,
        pub pass: String,
        pub nonce: String,
        pub salt: String,
    }

    // AI config do người dùng tự nhập, chỉ giữ trong RAM (phương án A)
    #[derive(Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
    pub struct AiCfg {
        pub endpoint: String,
        pub key: String,
        pub model: String,
    }

    #[derive(Debug)]
    pub struct State {
        pub hist: Vec<String>,
        pub hist_pos: usize,
        pub cfg: Cfg,
        pub theme: Theme,
        pub lang: Lang,
        pub blocked: u64,
        pub last_active: Instant,
        pub ai: AiCfg,
        pub ai_mem: Vec<(String, String)>,
        pub vault: Vec<VaultEntry>,
    }

    impl State {
        pub fn new() -> Self {
            // .env chỉ là tùy chọn mặc định, không bắt buộc
            let ai = AiCfg {
                endpoint: std::env::var("NEXUS_AI_ENDPOINT").unwrap_or_default(),
                key: std::env::var("NEXUS_AI_KEY").unwrap_or_default(),
                model: std::env::var("NEXUS_AI_MODEL").unwrap_or_default(),
            };
            Self {
                hist: Vec::with_capacity(32),
                hist_pos: 0,
                cfg: Cfg {
                    proxy_url: "socks5h://127.0.0.1:1080".into(),
                    ad: true,
                    trk: true,
                    sinkhole: true,
                    cookie: true,
                    anti_fp: true,
                    warp: false,
                    tor: false,
                    ..Default::default()
                },
                theme: Theme::Dark,
                lang: Lang::EN,
                blocked: 0,
                last_active: Instant::now(),
                ai,
                ai_mem: Vec::with_capacity(40),
                vault: Vec::new(),
            }
        }

        #[inline]
        pub fn push_ai(&mut self, r: String, c: String) {
            self.ai_mem.push((r, c));
            if self.ai_mem.len() > 40 {
                self.ai_mem.remove(0);
            }
        }

        pub fn push_hist(&mut self, url: String) {
            if self.hist.get(self.hist_pos).map(|u| u == &url).unwrap_or(false) {
                return;
            }
            if !self.hist.is_empty() && self.hist_pos + 1 < self.hist.len() {
                self.hist.truncate(self.hist_pos + 1);
            }
            self.hist.push(url);
            if self.hist.len() > 100 {
                self.hist.remove(0);
            }
            self.hist_pos = self.hist.len().saturating_sub(1);
            self.last_active = Instant::now();
        }

        pub fn go_back(&mut self) -> Option<String> {
            if self.hist_pos > 0 {
                self.hist_pos -= 1;
                self.hist.get(self.hist_pos).cloned()
            } else { None }
        }

        pub fn go_fwd(&mut self) -> Option<String> {
            if self.hist_pos + 1 < self.hist.len() {
                self.hist_pos += 1;
                self.hist.get(self.hist_pos).cloned()
            } else { None }
        }

        pub fn current(&self) -> Option<String> {
            self.hist.get(self.hist_pos).cloned()
        }
    }
}

mod net {
    use super::state::Cfg;

    pub fn client(c: &Cfg) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Nexus/1.0")
            .cookie_store(!c.cookie)
            .danger_accept_invalid_certs(false)
            .timeout(std::time::Duration::from_secs(30));

        if c.tor {
            if let Ok(p) = reqwest::Proxy::all("socks5h://127.0.0.1:9050") { b = b.proxy(p); }
        } else if c.warp {
            if let Ok(p) = reqwest::Proxy::all("socks5h://127.0.0.1:4018") { b = b.proxy(p); }
        } else if c.proxy {
            if let Ok(p) = reqwest::Proxy::all(&c.proxy_url) { b = b.proxy(p); }
        }
        b.build().unwrap_or_else(|_| reqwest::Client::new())
    }
}

mod sinkhole {
    #[inline]
    pub fn check(u: &str) -> bool {
        u.contains("doubleclick") || u.contains("adsense") || u.contains("mixpanel") ||
        u.contains("hotjar") || u.contains("facebook.com/tr") || u.contains("google-analytics")
    }
}

mod injection {
    use super::state::Cfg;

    pub fn get_security_payload(cfg: &Cfg) -> String {
        let mut css = String::new();
        let mut js = String::new();

        if cfg.ad {
            css.push_str(r#"
                [class*="ad-"], [id*="ad-"], .adsbygoogle, #google_ads, iframe[src*="doubleclick"],
                [class*="sponsor"], [id*="banner"], .ad-container, .adsbox {
                    display: none !important; height: 0 !important; width: 0 !important; overflow: hidden !important;
                }
            "#);
        }

        // Mỗi lần shield chặn 1 request, báo về Rust để đồng bộ counter qua ipc 'inc'
        if cfg.trk {
            js.push_str(r#"
                (function() {
                    const trackers = ['analytics', 'segment.io', 'mixpanel', 'hotjar', 'facebook.com/tr', 'trackcmp'];
                    const isTracker = (url) => trackers.some(t => (''+url).includes(t));
                    const notify = () => { try { if(window.top && window.top.nexusBlocked) window.top.nexusBlocked(); } catch(e){} };
                    const origFetch = window.fetch;
                    window.fetch = function(url, opts) { if(isTracker(url)){ notify(); return Promise.reject('Blocked'); } return origFetch.apply(this, arguments); };
                    const origOpen = XMLHttpRequest.prototype.open;
                    XMLHttpRequest.prototype.open = function(method, url) { if(isTracker(url)){ notify(); throw new Error('Blocked'); } return origOpen.apply(this, arguments); };
                    navigator.sendBeacon = () => false;
                })();
            "#);
        }

        if cfg.cookie {
            js.push_str(r#"
                (function() {
                    const origCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
                    if(!origCookie) return;
                    Object.defineProperty(document, 'cookie', {
                        set: function(val) {
                            if(!val.includes('_ga') && !val.includes('track') && !val.includes('fbp')) {
                                origCookie.set.call(this, val);
                            }
                        },
                        get: function() { return origCookie.get.call(this); }
                    });
                })();
            "#);
        }

        if cfg.anti_fp {
            js.push_str(r#"
                (function() {
                    HTMLCanvasElement.prototype.toDataURL = function() { return 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg=='; };
                    const getParam = WebGLRenderingContext.prototype.getParameter;
                    WebGLRenderingContext.prototype.getParameter = function(p) { if(p===37445) return 'Nexus'; if(p===37446) return 'Nexus'; return getParam.apply(this, arguments); };
                    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 4 });
                    Object.defineProperty(navigator, 'deviceMemory', { get: () => 4 });
                })();
            "#);
        }

        format!(r#"<style id="nexus-shield-css">{}</style><script id="nexus-shield-js">{}</script>"#, css, js)
    }
}
mod vault {
    use super::state::VaultEntry;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    use argon2::{Argon2, Algorithm, Version, Params};
    use base64::{Engine as _, engine::general_purpose};
    use rand::RngCore;

    const VAULT_FILE: &str = "nexus_vault.dat";

    // Argon2id với params rõ ràng (memory 64MiB, 3 iterations, 1 lane)
    fn argon2() -> Argon2<'static> {
        let params = Params::new(64 * 1024, 3, 1, Some(32))
            .unwrap_or_else(|_| Params::default());
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
    }

    fn derive_key(master: &str, salt: &[u8]) -> Option<[u8; 32]> {
        let mut key = [0u8; 32];
        argon2().hash_password_into(master.as_bytes(), salt, &mut key).ok()?;
        Some(key)
    }

    // Trả Option thay vì .expect() để tránh abort toàn app
    pub fn encrypt(data: &str, master: &str) -> Option<(String, String, String)> {
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);

        let key = derive_key(master, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;

        let mut nonce_bytes = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, data.as_bytes()).ok()?;

        Some((
            general_purpose::STANDARD.encode(&ciphertext),
            general_purpose::STANDARD.encode(nonce_bytes),
            general_purpose::STANDARD.encode(salt),
        ))
    }

    pub fn decrypt(enc: &str, enc_nonce: &str, enc_salt: &str, master: &str) -> Option<String> {
        let ciphertext = general_purpose::STANDARD.decode(enc).ok()?;
        let nonce_bytes = general_purpose::STANDARD.decode(enc_nonce).ok()?;
        let salt = general_purpose::STANDARD.decode(enc_salt).ok()?;

        if nonce_bytes.len() != 12 || salt.len() != 16 {
            return None;
        }

        let key = derive_key(master, &salt)?;
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;

        String::from_utf8(plaintext).ok()
    }

    pub fn generate(len: usize) -> String {
        use rand::Rng;
        const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut r = rand::thread_rng();
        (0..len).map(|_| C[r.gen_range(0..C.len())] as char).collect()
    }

    // Persist: mỗi entry đã tự mã hóa độc lập, file chỉ là JSON các entry đã mã hóa
    pub fn load() -> Vec<VaultEntry> {
        match std::fs::read(VAULT_FILE) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Vec::new(),
        }
    }

    pub fn save(entries: &[VaultEntry]) -> bool {
        match serde_json::to_vec(entries) {
            Ok(bytes) => std::fs::write(VAULT_FILE, bytes).is_ok(),
            Err(_) => false,
        }
    }
}

mod ai {
    use super::state::State;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use super::net;

    // Gọi endpoint kiểu OpenAI-compatible. Key/endpoint/model do người dùng tự nhập.
    pub async fn ask(prompt: String, st: Arc<RwLock<State>>) -> String {
        let (cfg, ai, history) = {
            let g = st.read().await;
            (g.cfg.clone(), g.ai.clone(), g.ai_mem.clone())
        };

        if ai.endpoint.is_empty() || ai.key.is_empty() {
            return "⚠ Chưa cấu hình AI. Nhập Endpoint + API Key + Model trong panel AI.".into();
        }
        let model = if ai.model.is_empty() { "gpt-4o-mini".to_string() } else { ai.model.clone() };

        // Build messages từ bộ nhớ FIFO
        let mut messages: Vec<serde_json::Value> = history
            .iter()
            .map(|(role, content)| serde_json::json!({"role": role, "content": content}))
            .collect();
        messages.push(serde_json::json!({"role": "user", "content": prompt}));

        let body = serde_json::json!({
            "model": model,
            "messages": messages,
            "stream": false
        });

        let client = net::client(&cfg);
        let resp = client
            .post(&ai.endpoint)
            .bearer_auth(&ai.key)
            .json(&body)
            .send()
            .await;

        let reply = match resp {
            Ok(r) => match r.json::<serde_json::Value>().await {
                Ok(v) => v["choices"][0]["message"]["content"]
                    .as_str()
                    .map(String::from)
                    .unwrap_or_else(|| "⚠ Phản hồi AI không hợp lệ.".into()),
                Err(_) => "⚠ Không đọc được phản hồi AI.".into(),
            },
            Err(_) => "⚠ Gọi AI thất bại (kiểm tra endpoint/mạng).".into(),
        };

        {
            let mut g = st.write().await;
            g.push_ai("user".into(), prompt);
            g.push_ai("assistant".into(), reply.clone());
        }
        reply
    }
}

mod dl {
    use super::{net, state::State};
    use std::sync::Arc;
    use tokio::{sync::Semaphore, task, io::{AsyncWriteExt, AsyncSeekExt, SeekFrom}};
    use futures_util::StreamExt;
    use tokio::sync::RwLock;

    pub async fn turbo(url: String, st: Arc<RwLock<State>>) {
        let cfg = { st.read().await.cfg.clone() };
        let c = net::client(&cfg);

        // Kiểm tra server có hỗ trợ Range không
        let head = c.head(&url).send().await.ok();
        let len = head.as_ref().and_then(|r| r.content_length()).unwrap_or(0);
        let accept_ranges = head
            .as_ref()
            .and_then(|r| r.headers().get("accept-ranges"))
            .and_then(|v| v.to_str().ok())
            .map(|v| v.contains("bytes"))
            .unwrap_or(false);

        let f_name = url.split('/').last().filter(|s| !s.is_empty()).unwrap_or("nxdl.bin").to_string();

        // Fallback: server không hỗ trợ Range hoặc không biết kích thước -> tải đơn luồng
        if len == 0 || !accept_ranges {
            if let Ok(r) = c.get(&url).send().await {
                if let Ok(bytes) = r.bytes().await {
                    let _ = tokio::fs::write(&f_name, &bytes).await;
                }
            }
            return;
        }

        const PARTS: usize = 16;
        let chunk = (len + PARTS as u64 - 1) / PARTS as u64;

        let file = match tokio::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).open(&f_name).await {
            Ok(f) => Arc::new(tokio::sync::Mutex::new(f)),
            Err(_) => return,
        };

        let sem = Arc::new(Semaphore::new(PARTS));
        let mut set = task::JoinSet::new();

        for i in 0..PARTS {
            let (cl, u, p, fl) = (c.clone(), url.clone(), sem.clone(), file.clone());
            let s = i as u64 * chunk;
            let e = (s + chunk).saturating_sub(1).min(len.saturating_sub(1));
            if s > e { continue; }

            set.spawn(async move {
                if let Ok(_permit) = p.acquire().await {
                    if let Ok(r) = cl.get(&u).header("Range", format!("bytes={}-{}", s, e)).send().await {
                        let mut stream = r.bytes_stream();
                        let mut off = s;
                        while let Some(Ok(b)) = stream.next().await {
                            let mut g = fl.lock().await;
                            if g.seek(SeekFrom::Start(off)).await.is_err() { break; }
                            if g.write_all(&b).await.is_err() { break; }
                            off += b.len() as u64;
                        }
                    }
                }
            });
        }
        while set.join_next().await.is_some() {}
    }
}

mod search {
    pub fn resolve(i: &str) -> String {
        let t = i.trim();
        if t.starts_with("http") {
            t.into()
        } else if t.contains('.') && !t.contains(' ') {
            format!("https://{}", t)
        } else {
            format!("https://www.google.com/search?q={}", url::form_urlencoded::byte_serialize(t.as_bytes()).collect::<String>())
        }
    }
}
fn html() -> String {
    r###"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--t1);height:100vh;display:flex;flex-direction:column;overflow:hidden}
:root{--bg:#000;--panel:#0a0a0a;--input:#111;--brd:#00ffff;--acc:#ff007f;--t1:#f8fafc;--t2:#94a3b8;--glow:0 0 15px rgba(0,255,255,.3)}
body.light{--bg:#fff;--panel:#f8fafc;--input:#f1f5f9;--brd:#005f73;--acc:#b7094c;--t1:#0f172a;--t2:#475569;--glow:0 4px 6px -1px rgba(0,0,0,.1)}
#app{display:flex;flex-direction:column;height:100vh}
header{display:flex;align-items:center;gap:8px;padding:10px;background:var(--panel);border-bottom:1px solid var(--brd);box-shadow:var(--glow);z-index:10}
.btn{width:36px;height:36px;display:flex;align-items:center;justify-content:center;border:1px solid var(--brd);background:0 0;color:var(--t1);cursor:pointer;font-weight:700;transition:all .2s;border-radius:6px}
.btn:hover{background:var(--brd);color:var(--bg);box-shadow:var(--glow)}
.btn-acc{border-color:var(--acc);color:var(--acc)}.btn-acc:hover{background:var(--acc);color:#fff}
#url{flex:1;background:var(--input);border:1px solid var(--brd);color:var(--t1);padding:10px 14px;outline:0;border-radius:6px}
#url:focus{box-shadow:var(--glow);border-color:var(--acc)}
#workspace{display:flex;flex:1;overflow:hidden}
main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px;position:relative}
.logo{font-size:5rem;font-weight:900;color:var(--brd);text-shadow:0 0 30px var(--brd);letter-spacing:12px;margin-bottom:10px}
.sub{color:var(--acc);text-shadow:0 0 15px var(--acc);font-size:1rem;letter-spacing:6px;margin-bottom:40px;font-weight:600}
#search{width:60%;max-width:600px;padding:16px;font-size:1.2rem;text-align:center;border-width:2px;background:var(--input);border:2px solid var(--brd);color:var(--t1);border-radius:30px}
aside{width:320px;background:var(--panel);border-left:1px solid var(--brd);display:flex;flex-direction:column;overflow:hidden}
.side-hd{padding:18px;border-bottom:1px solid var(--brd);font-weight:700;color:var(--brd);letter-spacing:2px;font-size:14px}
.side-scroll{flex:1;overflow-y:auto;padding:20px}
.side-scroll::-webkit-scrollbar{width:8px}.side-scroll::-webkit-scrollbar-thumb{background:var(--brd);border-radius:4px}
.sec-title{font-size:.8rem;color:var(--acc);margin:20px 0 12px;letter-spacing:2px;border-bottom:1px dashed var(--acc);padding-bottom:6px;font-weight:700;text-transform:uppercase}
.row{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;font-size:.85rem;color:var(--t1);font-weight:500}
.sw{position:relative;width:40px;height:20px}.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;cursor:pointer;inset:0;background:var(--input);border:1px solid var(--t2);transition:.3s;border-radius:20px}
.sl:before{position:absolute;content:"";height:14px;width:14px;left:2px;bottom:2px;background:var(--t2);transition:.3s;border-radius:50%}
input:checked+.sl{background:var(--brd);border-color:var(--brd);box-shadow:var(--glow)}
input:checked+.sl:before{transform:translateX(20px);background:var(--bg)}
.stat{font-size:1.5rem;color:var(--brd);font-weight:800;text-shadow:0 0 10px var(--brd);text-align:center;margin:10px 0}
#dp{position:fixed;right:-400px;top:0;width:400px;height:100vh;background:var(--panel);border-left:2px solid var(--acc);z-index:99;padding:20px;overflow-y:auto;transition:right .3s}
#dp.o{right:0}.le{font-size:12px;margin-bottom:5px}.le.error{color:var(--acc)}.le.info{color:var(--brd)}
.modal{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:420px;max-width:92vw;background:var(--panel);border:2px solid var(--brd);padding:30px;z-index:1000;display:none;border-radius:12px;box-shadow:var(--glow)}
.modal.show{display:block}
.v-in{width:100%;padding:10px;margin:8px 0;background:var(--input);border:1px solid var(--brd);color:var(--t1);border-radius:6px;outline:0}
.v-btn{width:100%;padding:10px;margin:5px 0;background:var(--brd);color:var(--bg);border:0;cursor:pointer;font-weight:700;border-radius:6px}
.v-btn:hover{background:var(--acc);color:#fff}
#ai-log{margin-top:12px;max-height:200px;overflow-y:auto;font-size:13px;text-align:left}
.ai-msg{margin:6px 0;padding:8px;border-radius:6px;background:var(--input)}
.ai-msg.u{border-left:3px solid var(--acc)}.ai-msg.a{border-left:3px solid var(--brd)}
</style></head><body>
<div id="app">
  <header>
    <button class="btn" onclick="sr('back')">⟵</button><button class="btn" onclick="sr('fwd')">⟶</button><button class="btn" onclick="sr('ref')">⟳</button>
    <input type="text" id="url" placeholder="nexus://home" onkeydown="if(event.key==='Enter')sr('nav',this.value)">
    <button class="btn btn-acc" onclick="toggleModal('vault')">🔐</button>
    <button class="btn btn-acc" onclick="toggleModal('aip')">🤖</button>
    <button class="btn" onclick="sr('dev')">⚙</button>
    <button class="btn" onclick="sr('theme')">🌓</button>
  </header>
  <div id="workspace">
    <main>
      <div class="logo">NEXUS</div>
      <div class="sub">ELITE RUST // AES-256 ENCRYPTED</div>
      <input type="text" id="search" placeholder="Search Google or type URL..." onkeydown="if(event.key==='Enter')sr('nav',this.value)">
    </main>
    <aside>
      <div class="side-hd">🛡 SECURITY MATRIX</div>
      <div class="side-scroll">
        <div class="sec-title">DOM & Network Shield</div>
        <div class="row"><span>Cosmetic Adblock</span><label class="sw"><input type="checkbox" checked onchange="ts('ad',this.checked)"><span class="sl"></span></label></div>
        <div class="row"><span>JS Tracker Block</span><label class="sw"><input type="checkbox" checked onchange="ts('trk',this.checked)"><span class="sl"></span></label></div>
        <div class="row"><span>Cookie Shield</span><label class="sw"><input type="checkbox" checked onchange="ts('cookie',this.checked)"><span class="sl"></span></label></div>
        <div class="row"><span>Domain Sinkhole</span><label class="sw"><input type="checkbox" checked onchange="ts('sink',this.checked)"><span class="sl"></span></label></div>
        <div class="sec-title">Anti-Fingerprint</div>
        <div class="row"><span>Canvas/WebGL Spoof</span><label class="sw"><input type="checkbox" checked onchange="ts('anti_fp',this.checked)"><span class="sl"></span></label></div>
        <div class="sec-title">Live Statistics</div>
        <div class="stat" id="tc">0 Blocked</div>
      </div>
    </aside>
  </div>
  <div id="dp"><h2 style="color:var(--acc);border-bottom:1px solid var(--acc)">DEV CONSOLE</h2><div id="dl"></div></div>

  <div id="vault" class="modal">
    <h2 style="color:var(--brd);margin-bottom:15px">🔐 NEXUS VAULT (AES-256-GCM)</h2>
    <input type="password" id="v-master" class="v-in" placeholder="Master Password">
    <input type="text" id="v-domain" class="v-in" placeholder="Domain (github.com)">
    <input type="text" id="v-user" class="v-in" placeholder="Username">
    <input type="password" id="v-pass" class="v-in" placeholder="Password">
    <button class="v-btn" onclick="vAct('save')">SAVE ENCRYPTED</button>
    <button class="v-btn" onclick="vAct('get')">RETRIEVE</button>
    <button class="v-btn" onclick="vAct('gen')">GENERATE 16 CHARS</button>
    <button class="v-btn" onclick="toggleModal('vault')" style="background:var(--acc);color:#fff">CLOSE</button>
    <div id="v-res" style="margin-top:10px;font-size:12px;color:var(--brd);word-break:break-all"></div>
  </div>

  <div id="aip" class="modal">
    <h2 style="color:var(--brd);margin-bottom:15px">🤖 AI (BYO Key)</h2>
    <input type="text" id="ai-endpoint" class="v-in" placeholder="Endpoint (https://api.openai.com/v1/chat/completions)">
    <input type="password" id="ai-key" class="v-in" placeholder="API Key (chỉ giữ trong phiên này)">
    <input type="text" id="ai-model" class="v-in" placeholder="Model (gpt-4o-mini)">
    <button class="v-btn" onclick="aiCfg()">SAVE CONFIG (RAM ONLY)</button>
    <textarea id="ai-prompt" class="v-in" rows="3" placeholder="Hỏi AI..."></textarea>
    <button class="v-btn" onclick="aiAsk()">ASK</button>
    <button class="v-btn" onclick="toggleModal('aip')" style="background:var(--acc);color:#fff">CLOSE</button>
    <div id="ai-log"></div>
  </div>
</div>
<script>
function sr(a,p){if(window.chrome&&window.chrome.webview)window.chrome.webview.postMessage(JSON.stringify({a:a,p:(p===undefined?"":p)}));}
function ts(k,v){sr('shld',{s:k,v:v})}
function uc(c){document.getElementById('tc').textContent=c+' Blocked';}
window.nexusBlocked=function(){sr('inc');};
function toggleDev(){document.getElementById('dp').classList.toggle('o');}
function toggleModal(id){document.getElementById(id).classList.toggle('show');}
function setUrl(u){document.getElementById('url').value=u;}
function vAct(a){sr('vault',{a:a,m:v('v-master'),d:v('v-domain'),u:v('v-user'),p:v('v-pass')});}
function vRes(t){document.getElementById('v-res').textContent=t;}
function aiCfg(){sr('ai_cfg',{e:v('ai-endpoint'),k:v('ai-key'),m:v('ai-model')});}
function aiAsk(){var q=v('ai-prompt');if(q){addAi('u',q);sr('ai',q);document.getElementById('ai-prompt').value='';}}
function addAi(role,txt){var l=document.getElementById('ai-log'),e=document.createElement('div');e.className='ai-msg '+role;e.textContent=(role==='u'?'You: ':'AI: ')+txt;l.appendChild(e);l.scrollTop=l.scrollHeight;}
function lg(m,t){let l=document.getElementById('dl'),e=document.createElement('div');e.className='le '+(t||'info');e.textContent='['+new Date().toTimeString().split(' ')[0]+'] '+m;l.prepend(e);}
function at(m){m==='light'?document.body.classList.add('light'):document.body.classList.remove('light');}
function v(id){return document.getElementById(id).value;}
</script></body></html>"###.into()
}

#[derive(Debug, Clone)]
enum Ev { Js(String) }

fn render_page(html_out: &str, url: &str, px: &tao::event_loop::EventLoopProxy<Ev>) {
    if let Ok(esc) = serde_json::to_string(html_out) {
        let _ = px.send_event(Ev::Js(format!(
            "{{var f=document.createElement('iframe');f.style.cssText='width:100%;height:100%;border:none;';f.srcdoc={};var m=document.querySelector('main');m.innerHTML='';m.appendChild(f);}}",
            esc
        )));
    }
    if let Ok(u) = serde_json::to_string(url) {
        let _ = px.send_event(Ev::Js(format!("setUrl({});", u)));
    }
}

async fn load_url(url: String, st: Arc<RwLock<state::State>>, px: tao::event_loop::EventLoopProxy<Ev>, record: bool) {
    let cfg = { st.read().await.cfg.clone() };

    if cfg.sinkhole && sinkhole::check(&url) {
        if let Ok(u) = serde_json::to_string(&url) {
            let _ = px.send_event(Ev::Js(format!("lg('SINKHOLE: '+{},'error');", u)));
        }
        let blocked = {
            let mut g = st.write().await;
            g.blocked += 1;
            g.blocked
        };
        let _ = px.send_event(Ev::Js(format!("uc({});", blocked)));
        return;
    }

    let client = net::client(&cfg);
    if let Ok(r) = client.get(&url).header("Referer", "").header("DNT", "1").send().await {
        if let Ok(h) = r.text().await {
            let shield = injection::get_security_payload(&cfg);
            let inj = format!(r#"<base href="{}">{}"#, url, shield);

            // Chèn ngay sau thẻ <head ...> đầu tiên, xử lý cả hoa/thường và có thuộc tính
            let lower = h.to_lowercase();
            let html_out = if let Some(start) = lower.find("<head") {
                if let Some(rel_end) = lower[start..].find('>') {
                    let pos = start + rel_end + 1;
                    let mut s = String::with_capacity(h.len() + inj.len());
                    s.push_str(&h[..pos]);
                    s.push_str(&inj);
                    s.push_str(&h[pos..]);
                    s
                } else {
                    format!("{}{}", inj, h)
                }
            } else {
                format!("{}{}", inj, h)
            };

            render_page(&html_out, &url, &px);

            if record {
                let mut g = st.write().await;
                g.push_hist(url);
            }
        }
    }
}

fn main() {
    dotenvy::dotenv().ok();
    std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");

    let el = EventLoopBuilder::<Ev>::with_user_event().build();
    let w = match WindowBuilder::new()
        .with_title("NEXUS")
        .with_inner_size(tao::dpi::LogicalSize::new(1024, 768))
        .build(&el) {
        Ok(w) => w,
        Err(_) => return,
    };

    let mut initial = state::State::new();
    initial.vault = vault::load(); // persist: nạp vault đã mã hóa
    let st = Arc::new(RwLock::new(initial));
    let px = el.create_proxy();

    let tokio_rt = Arc::new(Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .unwrap_or_else(|_| std::process::exit(1)));
    let tokio_handle = tokio_rt.handle().clone();

    let ist = st.clone();
    let ipx = px.clone();
    let rth = tokio_handle.clone();

    let mut wb = WebViewBuilder::new();
    wb = wb.with_html(html())
        .with_back_forward_navigation_gestures(false)
        .with_zoom_hotkeys(false)
        .with_ipc_handler(move |req: wry::http::Request<String>| {
            let msg = req.into_body();
            let p: serde_json::Value = match serde_json::from_str(&msg) { Ok(v) => v, Err(_) => return };
            let a = p["a"].as_str().unwrap_or("");
            let d = p["p"].clone();
            let ist = ist.clone();
            let ipx = ipx.clone();
            let rth = rth.clone();

            match a {
                "nav" => if let Some(u) = d.as_str() {
                    let u = search::resolve(u);
                    rth.spawn(async move { load_url(u, ist, ipx, true).await; });
                },
                "back" => {
                    rth.spawn(async move {
                        let target = { ist.write().await.go_back() };
                        if let Some(u) = target { load_url(u, ist, ipx, false).await; }
                    });
                },
                "fwd" => {
                    rth.spawn(async move {
                        let target = { ist.write().await.go_fwd() };
                        if let Some(u) = target { load_url(u, ist, ipx, false).await; }
                    });
                },
                "ref" => {
                    rth.spawn(async move {
                        let target = { ist.read().await.current() };
                        if let Some(u) = target { load_url(u, ist, ipx, false).await; }
                    });
                },
                "inc" => {
                    rth.spawn(async move {
                        let c = { let mut g = ist.write().await; g.blocked += 1; g.blocked };
                        let _ = ipx.send_event(Ev::Js(format!("uc({});", c)));
                    });
                },
                "shld" => {
                    if let (Some(s), Some(v)) = (d["s"].as_str().map(String::from), d["v"].as_bool()) {
                        rth.spawn(async move {
                            let mut g = ist.write().await;
                            match s.as_str() {
                                "ad" => g.cfg.ad = v,
                                "trk" => g.cfg.trk = v,
                                "sink" => g.cfg.sinkhole = v,
                                "cookie" => g.cfg.cookie = v,
                                "anti_fp" => g.cfg.anti_fp = v,
                                _ => {}
                            }
                        });
                    }
                },
                "ai_cfg" => {
                    let e = d["e"].as_str().unwrap_or("").to_string();
                    let k = d["k"].as_str().unwrap_or("").to_string();
                    let m = d["m"].as_str().unwrap_or("").to_string();
                    rth.spawn(async move {
                        let mut g = ist.write().await;
                        g.ai.endpoint = e;
                        g.ai.key = k;
                        g.ai.model = m;
                        let _ = ipx.send_event(Ev::Js("lg('AI config saved (RAM only)','info');".into()));
                    });
                },
                "ai" => if let Some(prompt) = d.as_str() {
                    let prompt = prompt.to_string();
                    rth.spawn(async move {
                        let reply = ai::ask(prompt, ist).await;
                        if let Ok(esc) = serde_json::to_string(&reply) {
                            let _ = ipx.send_event(Ev::Js(format!("addAi('a',{});", esc)));
                        }
                    });
                },
                "vault" => {
                    let act = d["a"].as_str().unwrap_or("").to_string();
                    let m = d["m"].as_str().unwrap_or("").to_string();
                    let dom = d["d"].as_str().unwrap_or("").to_string();
                    let u = d["u"].as_str().unwrap_or("").to_string();
                    let pw = d["p"].as_str().unwrap_or("").to_string();

                    rth.spawn(async move {
                        if act == "save" && !m.is_empty() && !dom.is_empty() {
                            match vault::encrypt(&pw, &m) {
                                Some((enc, nonce, salt)) => {
                                    let entries = {
                                        let mut g = ist.write().await;
                                        g.vault.push(state::VaultEntry { domain: dom, user: u, pass: enc, nonce, salt });
                                        g.vault.clone()
                                    };
                                    let ok = vault::save(&entries);
                                    let _ = ipx.send_event(Ev::Js(
                                        if ok { "vRes('✅ AES-256-GCM Encrypted & Saved');".into() }
                                        else { "vRes('⚠ Encrypted nhưng không ghi được file');".to_string() }
                                    ));
                                },
                                None => { let _ = ipx.send_event(Ev::Js("vRes('❌ Encryption failed');".into())); }
                            }
                        } else if act == "get" {
                            let found = {
                                let g = ist.read().await;
                                g.vault.iter().find(|e| e.domain == dom)
                                    .map(|e| (e.user.clone(), e.pass.clone(), e.nonce.clone(), e.salt.clone()))
                            };
                            match found {
                                Some((user, pass, nonce, salt)) => {
                                    match vault::decrypt(&pass, &nonce, &salt, &m) {
                                        Some(dec) => {
                                            // điền thẳng vào ô password, không in plaintext ra log
                                            if let Ok(d) = serde_json::to_string(&dec) {
                                                let _ = ipx.send_event(Ev::Js(format!(
                                                    "document.getElementById('v-pass').value={};vRes('🔓 User: {} (đã điền mật khẩu)');",
                                                    d, user.replace('\'', "")
                                                )));
                                            }
                                        },
                                        None => { let _ = ipx.send_event(Ev::Js("vRes('❌ Wrong master password');".into())); }
                                    }
                                },
                                None => { let _ = ipx.send_event(Ev::Js("vRes('❌ Not found');".into())); }
                            }
                        } else if act == "gen" {
                            let gpw = vault::generate(16);
                            if let Ok(g) = serde_json::to_string(&gpw) {
                                let _ = ipx.send_event(Ev::Js(format!("document.getElementById('v-pass').value={};vRes('🎲 Generated');", g)));
                            }
                        }
                    });
                },
                "dev" => { let _ = ipx.send_event(Ev::Js("toggleDev();".into())); },
                "theme" => {
                    rth.spawn(async move {
                        let t = {
                            let mut g = ist.write().await;
                            g.theme = if g.theme == state::Theme::Dark { state::Theme::Light } else { state::Theme::Dark };
                            if g.theme == state::Theme::Dark { "dark" } else { "light" }
                        };
                        let _ = ipx.send_event(Ev::Js(format!("at('{}');", t)));
                    });
                },
                _ => {}
            }
        });

    let wv = match wb.build(&w) { Ok(w) => w, Err(_) => return };
    let _rt_guard = tokio_rt.clone();

    el.run(move |ev, _, cf| {
        *cf = ControlFlow::Wait;
        match ev {
            Event::NewEvents(StartCause::Init) => {
                let _ = px.send_event(Ev::Js("lg('NEXUS CORE INITIALIZED','info');lg('AES-256-GCM Vault Ready','info');".into()));
            },
            Event::UserEvent(Ev::Js(j)) => { let _ = wv.evaluate_script(&j); },
            Event::WindowEvent { event: tao::event::WindowEvent::CloseRequested, .. } => *cf = ControlFlow::Exit,
            _ => {}
        }
    });
}
