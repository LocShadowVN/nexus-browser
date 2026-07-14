#![allow(dead_code, unused_imports, unused_variables, unreachable_code)]

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};
use wry::application::{
    dpi::LogicalSize,
    event::{Event, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use tokio::{
    runtime::Builder,
    sync::{RwLock, Semaphore, Mutex as TokioMutex},
    task::JoinSet,
    io::{AsyncSeekExt, AsyncWriteExt},
};
use uuid::Uuid;
use wry::webview::WebViewBuilder;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use reqwest::RequestBuilder;
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::RngCore;
use url::Url;

#[macro_export]
macro_rules! json {
    ($($tt:tt)*) => { serde_json::json!($($tt)*) };
}

#[derive(Debug, Clone)]
enum Ev {
    Js(String),
    NewTab(usize),
    CloseTab(usize),
}

// ======================
// MODULE: STATE
// ======================
mod state {
    use super::*;
    
    #[derive(Clone, Debug, PartialEq)]
    pub enum TabMode { Normal, Incognito, Tor }
    
    #[derive(Clone, Debug, Default)]
    pub struct TabConfig {
        pub proxy: bool, pub proxy_url: String,
        pub tor: bool, pub warp: bool,
        pub ad: bool, pub trk: bool,
        pub sinkhole: bool, pub cookie: bool,
        pub anti_fp: bool,
    }
    
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultEntry {
        pub domain: String, pub user: String, pub pass: String,
        pub nonce: String, pub salt: String,
        pub created: u64, pub last_used: u64,
    }
    
    #[derive(Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
    pub struct AiCfg { pub endpoint: String, pub key: String, pub model: String }
    
    #[derive(Clone, Debug, Default)]
    pub struct SyncConfig { pub chrome: bool, pub firefox: bool, pub edge: bool }
    
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct Bookmark { pub title: String, pub url: String }
    
    #[derive(Debug)]
    pub struct TabState {
        pub id: Uuid, pub name: String, pub url: String,
        pub hist: Vec<String>, pub hist_pos: usize,
        pub cfg: TabConfig, pub mode: TabMode,
        pub last_active: Instant,
        pub frozen: bool, // TÍNH NĂNG ĐÓNG BĂNG TAB
        pub ai: AiCfg, pub ai_mem: VecDeque<(String, String)>,
        pub client: Option<reqwest::Client>,
        pub client_cfg_hash: u64,
        pub vault: Option<Vec<VaultEntry>>,
    }
    
    impl TabState {
        pub fn new(mode: TabMode) -> Self {
            let is_incog = matches!(mode, TabMode::Incognito | TabMode::Tor);
            Self {
                id: Uuid::new_v4(),
                name: match mode { 
                    TabMode::Normal => "New Tab", 
                    TabMode::Incognito => "Private Tab", 
                    TabMode::Tor => "Tor Tab" 
                }.into(),
                url: "nexus://home".into(),
                hist: Vec::with_capacity(32),
                hist_pos: 0,
                cfg: TabConfig {
                    proxy_url: "socks5h://127.0.0.1:1080".into(),
                    ad: true, trk: true, sinkhole: true,
                    cookie: !is_incog, anti_fp: true,
                    tor: matches!(mode, TabMode::Tor),
                    ..Default::default()
                },
                mode, last_active: Instant::now(),
                frozen: false,
                ai: AiCfg::default(),
                ai_mem: VecDeque::with_capacity(40),
                client: None,
                client_cfg_hash: 0,
                vault: if is_incog { None } else { Some(Vec::new()) },
            }
        }
        
        #[inline] pub fn push_ai(&mut self, r: String, c: String) {
            self.ai_mem.push_back((r, c));
            if self.ai_mem.len() > 40 { self.ai_mem.pop_front(); }
        }
        
        pub fn push_hist(&mut self, url: String) {
            if self.hist.get(self.hist_pos).map(|u| u == &url).unwrap_or(false) { return; }
            if !self.hist.is_empty() && self.hist_pos + 1 < self.hist.len() {
                self.hist.truncate(self.hist_pos + 1);
            }
            self.hist.push(url);
            if self.hist.len() > 100 { self.hist.remove(0); }
            self.hist_pos = self.hist.len().saturating_sub(1);
            self.last_active = Instant::now();
        }
        
        pub fn go_back(&mut self) -> Option<String> {
            (self.hist_pos > 0).then(|| { self.hist_pos -= 1; self.hist[self.hist_pos].clone() })
        }
        
        pub fn go_fwd(&mut self) -> Option<String> {
            (self.hist_pos + 1 < self.hist.len()).then(|| { 
                self.hist_pos += 1; self.hist[self.hist_pos].clone() 
            })
        }
        
        pub fn current(&self) -> Option<String> {
            self.hist.get(self.hist_pos).cloned()
        }
        
        pub fn update_client(&mut self) {
            let new_hash = self.cfg_hash();
            if self.client_cfg_hash != new_hash {
                self.client = Some(super::net::build_client(&self.cfg));
                self.client_cfg_hash = new_hash;
            }
        }
        
        fn cfg_hash(&self) -> u64 {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            self.cfg.proxy.hash(&mut h);
            self.cfg.proxy_url.hash(&mut h);
            self.cfg.tor.hash(&mut h);
            self.cfg.warp.hash(&mut h);
            self.cfg.cookie.hash(&mut h);
            h.finish()
        }
    }
    
    #[derive(Debug)]
    pub struct State {
        pub active_tab: usize,
        pub tabs: Vec<TabState>,
        pub blocked: u64,
        pub global_cfg: GlobalConfig,
        pub sync: SyncState,
        pub bookmarks: Vec<Bookmark>,
    }
    
    impl State {
        pub fn new() -> Self {
            let mut tabs = Vec::new();
            tabs.push(TabState::new(TabMode::Normal));
            
            Self {
                active_tab: 0,
                tabs,
                blocked: 0,
                global_cfg: GlobalConfig::default(),
                sync: SyncState::default(),
                bookmarks: Vec::new(),
            }
        }
        
        #[inline] pub fn active_tab(&self) -> &TabState { &self.tabs[self.active_tab] }
        #[inline] pub fn active_tab_mut(&mut self) -> &mut TabState { &mut self.tabs[self.active_tab] }
        
        pub fn new_tab(&mut self, mode: TabMode) -> usize {
            let idx = self.tabs.len();
            self.tabs.push(TabState::new(mode));
            self.active_tab = idx;
            idx
        }
        
        pub fn close_tab(&mut self, idx: usize) -> bool {
            (self.tabs.len() > 1).then(|| {
                self.tabs.remove(idx);
                if self.active_tab >= idx && self.active_tab > 0 { self.active_tab -= 1; }
            }).is_some()
        }
        
        pub fn switch_tab(&mut self, idx: usize) {
            (idx < self.tabs.len()).then(|| self.active_tab = idx);
        }
    }
    
    #[derive(Clone, Debug, Default)]
    pub struct GlobalConfig {
        pub ad: bool, pub trk: bool, pub sinkhole: bool, pub anti_fp: bool,
        pub auto_save_passwords: bool, pub show_password_suggestions: bool,
    }
    
    #[derive(Debug, Default)]
    pub struct SyncState {
        pub config: SyncConfig,
        pub chrome_vault: Vec<VaultEntry>,
        pub firefox_vault: Vec<VaultEntry>,
    }
    
    impl SyncState {
        pub fn import_from_browser(&mut self, browser: &str) -> usize {
            let entries = match browser {
                "chrome" => super::sync::import_from_chrome(),
                "firefox" => super::sync::import_from_firefox(),
                "edge" => super::sync::import_from_edge(),
                _ => Ok(Vec::new()),
            }.unwrap_or_default();
            
            match browser {
                "chrome" => self.chrome_vault = entries,
                "firefox" => self.firefox_vault = entries,
                "edge" => self.chrome_vault.extend(entries),
                _ => {}
            }
            self.chrome_vault.len() + self.firefox_vault.len()
        }
        
        pub fn sync_to_active_tab(&self, tab: &mut TabState) {
            if let Some(vault) = &mut tab.vault {
                let mut all = vault.clone();
                all.extend(self.chrome_vault.clone());
                all.extend(self.firefox_vault.clone());
                all.sort_by(|a, b| a.domain.cmp(&b.domain));
                all.dedup_by(|a, b| a.domain == b.domain && a.user == b.user);
                *vault = all;
            }
        }
    }
}

// ======================
// MODULE: NET (SECURE & GOOGLE LOGIN)
// ======================
mod net {
    use super::*;
    pub fn build_client(c: &state::TabConfig) -> reqwest::Client {
        let jar = Arc::new(reqwest::cookie::Jar::default());
        let mut b = reqwest::Client::builder()
            // SPOOFING: Giả mạo Chrome xịn nhất để qua mặt Google Login Block
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
            .cookie_provider(jar)
            .danger_accept_invalid_certs(false)
            .timeout(Duration::from_secs(30));
        
        if c.tor { b = b.proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050").unwrap()); }
        else if c.warp { b = b.proxy(reqwest::Proxy::all("socks5h://127.0.0.1:2053").unwrap()); }
        else if c.proxy { b = b.proxy(reqwest::Proxy::all(&c.proxy_url).unwrap()); }
        
        b.build().unwrap_or_else(|_| reqwest::Client::new())
    }
}

// ======================
// MODULE: SINKHOLE
// ======================
mod sinkhole {
    #[inline] pub fn check(u: &str) -> bool {
        u.contains("doubleclick") || u.contains("adsense") || u.contains("mixpanel") ||
        u.contains("hotjar") || u.contains("facebook.com/tr") || u.contains("google-analytics")
    }
}

// ======================
// MODULE: INJECTION (YOUTUBE AD-KILLER & CSP)
// ======================
mod injection {
    use super::*;
    
    lazy_static::lazy_static! {
        static ref PAYLOAD_CACHE: StdMutex<HashMap<u64, String>> = StdMutex::new(HashMap::new());
    }
    
    pub fn get_security_payload(cfg: &state::TabConfig) -> String {
        let hash = cfg_hash(cfg);
        if let Some(cached) = PAYLOAD_CACHE.lock().unwrap().get(&hash) { return cached.clone(); }
        
        let (mut css, mut js) = (String::new(), String::new());
        
        if cfg.ad { 
            css.push_str(r#"[class*="ad-"],[id*="ad-"],.adsbygoogle,#google_ads,iframe[src*="doubleclick"],[class*="sponsor"],[id*="banner"],.ad-container,.adsbox{display:none!important;height:0!important;width:0!important;overflow:hidden!important}"#); 
            
            // YOUTUBE AD-KILLER JS
            js.push_str(r#"
            if (window.location.hostname.includes('youtube.com')) {
                setInterval(() => {
                    const skipBtn = document.querySelector('.ytp-ad-skip-button, .ytp-ad-skip-button-modern, .ytp-skip-ad-button');
                    if (skipBtn) { skipBtn.click(); }
                    const ad = document.querySelector('.ad-showing video');
                    if (ad && !isNaN(ad.duration)) { ad.currentTime = ad.duration; }
                    document.querySelectorAll('ytd-ad-slot-renderer, ytd-promoted-sparkles-web-renderer, ytd-banner-promo-renderer, ytd-player-legacy-desktop-watch-ads-renderer').forEach(e => e.remove());
                }, 300);
            }
            "#);
        }
        
        if cfg.trk { js.push_str(r#"!function(){const t=['analytics','segment.io','mixpanel','hotjar','facebook.com/tr','trackcmp'],n=t=>t.some(t=>(""+t).includes(t)),o=()=>{try{window.top.postMessage(JSON.stringify({a:'inc',p:''}),'*')}catch(t){}},e=window.fetch;window.fetch=function(t,r){return n(t)?(o(),Promise.reject("Blocked")):e.apply(this,arguments)};const i=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(t,n){return n(t)?(o(),undefined):i.apply(this,arguments)},navigator.sendBeacon=()=>!1}()"#); }
        if cfg.cookie { js.push_str(r#"!function(){const t=Object.getOwnPropertyDescriptor(Document.prototype,"cookie");t&&(Object.defineProperty(document,"cookie",{set(n){/(_ga|track|fbp)/.test(n)||t.set.call(this,n)},get(){return t.get.call(this)}}))}()"#); }
        if cfg.anti_fp { js.push_str(r#"!function(){HTMLCanvasElement.prototype.toDataURL=()=>"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==";const t=WebGLRenderingContext.prototype.getParameter;WebGLRenderingContext.prototype.getParameter=function(n){return 37445===n?"Nexus":37446===n?"Nexus":t.apply(this,arguments)},Object.defineProperty(navigator,"hardwareConcurrency",{get:()=>4}),Object.defineProperty(navigator,"deviceMemory",{get:()=>4})}()"#); }
        
        js.push_str(r#"
        !function(){
            const t=()=>{
                document.querySelectorAll("form").forEach(n=>{
                    if(!n.dataset.nexusMonitored){
                        let o=!1,e=!1,r=null,s=null;
                        n.querySelectorAll("input").forEach(t=>{
                            "password"===t.type&&(e=!0,s=t);
                            (/text|email/.test(t.type)||/user|email/i.test(t.name))&&(o=!0,r=t);
                        });
                        if(o&&e){
                            n.dataset.nexusMonitored="true";
                            n.addEventListener("submit",function(t){
                                window.top.postMessage(JSON.stringify({a:"password-detected",p:{url:window.location.href,username:r?r.value:"",password:s?s.value:""}}),'*');
                            });
                        }
                    }
                });
            };
            const n=new MutationObserver(t);
            n.observe(document.body,{childList:!0,subtree:!0});
            t();
            window.nexusGeneratePassword=()=>{const t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";return Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>t[n%t.length]).join("")};
            window.nexusFillPassword=(t,n)=>{let o=null,e=null;for(const n of document.querySelectorAll("input"))"password"===n.type&&!e&&(e=n),(/text|email/.test(n.type)||/user|email/i.test(n.name))&&(o=n);o&&(o.value=t);e&&(e.value=n)};
        }();
        
        document.addEventListener('click', function(e) {
            let a = e.target.closest('a');
            if (a && a.href && !a.href.startsWith('javascript:') && !a.href.startsWith('#')) {
                if (a.target === '_blank') {
                    e.preventDefault();
                    window.top.postMessage(JSON.stringify({a: 'new-tab-url', p: a.href}), '*');
                } else {
                    e.preventDefault();
                    window.top.postMessage(JSON.stringify({a: 'nav-internal', p: a.href}), '*');
                }
            }
        }, true);
        
        document.addEventListener('submit', function(e) {
            let form = e.target;
            let method = (form.method || 'get').toLowerCase();
            e.preventDefault();
            let url = new URL(form.action || window.location.href);
            if (method === 'get') {
                let formData = new FormData(form);
                for (let [key, value] of formData.entries()) {
                    url.searchParams.append(key, value);
                }
                window.top.postMessage(JSON.stringify({a: 'nav-internal', p: url.href}), '*');
            } else {
                let formData = new FormData(form);
                let body = {};
                for (let [key, value] of formData.entries()) {
                    body[key] = value;
                }
                window.top.postMessage(JSON.stringify({a: 'nav-post', p: {url: url.href, body: body}}), '*');
            }
        }, true);
        
        window.open = function(url) {
            window.top.postMessage(JSON.stringify({a: 'new-tab-url', p: url}), '*');
            return null;
        };
        
        const oldLog = console.log;
        console.log = function(...args) {
            window.top.postMessage(JSON.stringify({a: 'console-log', p: args.join(' ')}), '*');
            oldLog.apply(console, args);
        };
        "#);
        
        // BẢO MẬT: Content Security Policy (CSP)
        let csp = r#"<meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; object-src 'none';">"#;
        let payload = format!(r#"{}<style id="nexus-shield-css">{}</style><script id="nexus-shield-js">{}</script>"#, csp, css, js);
        PAYLOAD_CACHE.lock().unwrap().insert(hash, payload.clone());
        payload
    }
    
    fn cfg_hash(cfg: &state::TabConfig) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        cfg.ad.hash(&mut h); cfg.trk.hash(&mut h);
        cfg.cookie.hash(&mut h); cfg.anti_fp.hash(&mut h);
        h.finish()
    }
}

// ======================
// MODULE: VAULT
// ======================
mod vault {
    use super::*;
    use rand::RngCore;
    
    const VAULT_FILE: &str = "nexus_vault.dat";
    lazy_static::lazy_static! {
        static ref VAULT_LOCK: StdMutex<()> = StdMutex::new(());
    }
    
    fn argon2() -> Argon2<'static> {
        let m_cost = if num_cpus::get() > 4 { 192 * 1024 } else { 128 * 1024 };
        Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, 
            Params::new(m_cost, 3, std::cmp::min(4, num_cpus::get().try_into().unwrap_or(4)), None).unwrap())
    }
    
    fn derive_key(master: &str, salt: &[u8]) -> Option<[u8; 32]> {
        let mut key = [0u8; 32];
        argon2().hash_password_into(master.as_bytes(), salt, &mut key).ok()?;
        Some(key)
    }
    
    pub fn encrypt(data: &str, master: &str) -> Option<(String, String, String)> {
        let salt = SaltString::generate(rand::thread_rng());
        let mut raw_salt = [0u8; 64];
        let salt_bytes = salt.decode_b64(&mut raw_salt).ok()?;
        let key = derive_key(master, salt_bytes)?;
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).ok()?;
        
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), data.as_bytes()).ok()?;
        
        Some((
            general_purpose::STANDARD.encode(&ciphertext),
            general_purpose::STANDARD.encode(&nonce),
            salt.as_str().to_string(),
        ))
    }
    
    pub fn decrypt(enc: &str, nonce: &str, salt: &str, master: &str) -> Option<String> {
        let (ciphertext, nonce) = (
            general_purpose::STANDARD.decode(enc).ok()?,
            general_purpose::STANDARD.decode(nonce).ok()?,
        );
        
        let salt_value = SaltString::from_b64(salt).ok()?;
        let mut raw_salt = [0u8; 64];
        let salt_bytes = salt_value.decode_b64(&mut raw_salt).ok()?;
        
        (nonce.len() == 12).then(|| {
            let key = derive_key(master, salt_bytes)?;
            let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
            String::from_utf8(cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice()).ok()?).ok()
        })?
    }
    
    pub fn generate(len: usize) -> String {
        const CHARSET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
        let mut rng = rand::thread_rng();
        (0..len)
            .map(|_| {
                let idx = (rng.next_u32() as usize) % CHARSET.len();
                CHARSET[idx] as char
            })
            .collect()
    }
    
    pub fn load() -> Vec<state::VaultEntry> {
        std::fs::read(VAULT_FILE).ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    
    pub fn save(entries: &[state::VaultEntry]) -> bool {
        let _guard = VAULT_LOCK.lock().unwrap();
        let temp = format!("{}.tmp", VAULT_FILE);
        serde_json::to_vec(entries)
            .map(|b| std::fs::write(&temp, b).is_ok())
            .unwrap_or(false)
            && std::fs::rename(temp, VAULT_FILE).is_ok()
    }
}

// ======================
// MODULE: SYNC
// ======================
mod sync {
    use super::*;
    
    pub fn import_from_chrome() -> Result<Vec<state::VaultEntry>, String> { Ok(Vec::new()) }
    pub fn import_from_firefox() -> Result<Vec<state::VaultEntry>, String> { Ok(Vec::new()) }
    pub fn import_from_edge() -> Result<Vec<state::VaultEntry>, String> { Ok(Vec::new()) }
}

// ======================
// MODULE: AI
// ======================
mod ai {
    use super::*;
    
    pub async fn ask(prompt: String, st: Arc<RwLock<state::State>>) -> String {
        let (cfg, ai, history) = {
            let g = st.read().await;
            let t = g.active_tab();
            (t.cfg.clone(), t.ai.clone(), t.ai_mem.clone())
        };
        
        if ai.endpoint.is_empty() || ai.key.is_empty() {
            return "⚠ Chưa cấu hình AI. Nhập Endpoint + API Key + Model trong panel AI.".into();
        }
        
        let client = {
            let mut g = st.write().await;
            let t = g.active_tab_mut();
            t.update_client();
            t.client.clone().unwrap_or_else(reqwest::Client::new)
        };
        
        let model = if ai.model.is_empty() { "gpt-4o-mini" } else { &ai.model } .to_string();
        let mut messages: Vec<JsonValue> = history
            .iter()
            .map(|(r,c)| json!({"role":r,"content":c}))
            .collect();
        messages.push(json!({"role":"user","content":prompt}));
        
        let body = json!({ "model": model, "messages": messages, "stream": false });
        
        let reply = match client
            .post(&ai.endpoint)
            .bearer_auth(&ai.key)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(serde_json::to_vec(&body).unwrap_or_default())
            .send()
            .await
        {
            Ok(response) => match response.text().await {
                Ok(text) => serde_json::from_str::<JsonValue>(&text)
                    .ok()
                    .and_then(|v| v["choices"][0]["message"]["content"].as_str().map(String::from))
                    .unwrap_or_else(|| "⚠ Phản hồi AI không hợp lệ.".into()),
                Err(_) => "⚠ Phản hồi AI không hợp lệ.".into(),
            },
            Err(_) => "⚠ Phản hồi AI không hợp lệ.".into(),
        };
        
        {
            let mut g = st.write().await;
            let t = g.active_tab_mut();
            t.push_ai("user".into(), prompt);
            t.push_ai("assistant".into(), reply.clone());
        }
        reply
    }
}

// ======================
// MODULE: DL
// ======================
mod dl {
    use super::*;
    
    const PARTS: usize = 16;
    
    pub async fn turbo(url: String, st: Arc<RwLock<state::State>>) {
        let client = {
            let mut g = st.write().await;
            let t = g.active_tab_mut();
            t.update_client();
            t.client.clone().unwrap_or_else(reqwest::Client::new)
        };
        
        let (len, accept_ranges) = client.head(&url).send().await
            .ok()
            .map(|r| (r.content_length().unwrap_or(0), 
                r.headers().get("accept-ranges")
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.contains("bytes"))
                    .unwrap_or(false)))
            .unwrap_or((0, false));
        
        let f_name = url.split('/').last().filter(|s| !s.is_empty()).unwrap_or("nxdl.bin").to_string();
        let f_name = format!("./{}", f_name);
        
        if len == 0 || !accept_ranges {
            if let Ok(r) = client.get(&url).send().await {
                if let Ok(b) = r.bytes().await {
                    let _ = tokio::fs::write(&f_name, &b).await;
                }
            }
            return;
        }
        
        let chunk = (len + PARTS as u64 - 1) / PARTS as u64;
        
        let file = match tokio::fs::OpenOptions::new()
            .write(true).create(true).truncate(true)
            .open(&f_name).await {
                Ok(f) => Arc::new(TokioMutex::new(f)),
                Err(_) => return,
            };
        
        let (sem, failed) = (Arc::new(Semaphore::new(PARTS)), Arc::new(AtomicUsize::new(0)));
        let mut set = JoinSet::new();
        
        for i in 0..PARTS {
            let (client, url, sem, file, failed) = (client.clone(), url.clone(), sem.clone(), file.clone(), failed.clone());
            let (s, e) = (i as u64 * chunk, (i as u64 * chunk + chunk - 1).min(len - 1));
            if s > e { continue; }
            
            set.spawn(async move {
                if sem.acquire().await.is_err() { return; }
                let response = client.get(&url).header("Range", format!("bytes={}-{}", s, e)).send().await;
                if let Ok(mut response) = response {
                    let bytes = response.bytes().await.ok();
                    if let Some(bytes) = bytes {
                        let mut f = file.lock().await;
                        if f.seek(std::io::SeekFrom::Start(s)).await.is_ok() {
                            f.write_all(&bytes).await.ok();
                        }
                    } else {
                        failed.fetch_add(1, Ordering::SeqCst);
                    }
                } else {
                    failed.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
        
        while set.join_next().await.is_some() {}
        if failed.load(Ordering::SeqCst) > 0 {
            let _ = tokio::fs::remove_file(&f_name).await;
        }
    }
}

// ======================
// MODULE: SEARCH
// ======================
mod search {
    pub fn resolve(i: &str) -> String {
        let t = i.trim();
        if t.starts_with("http") || t.starts_with("nexus://") { t.into() }
        else if t.contains('.') && !t.contains(' ') { format!("https://{}", t) }
        else { format!("https://www.google.com/search?q={}", url::form_urlencoded::byte_serialize(t.as_bytes()).collect::<String>()) }
    }
}

// ======================
// MODULE: EXTENSIONS
// ======================
mod extensions {
    use super::*;
    use std::path::PathBuf;
    use tokio::fs;
    
    const EXTENSIONS_DIR: &str = "nexus_extensions";
    const MANIFEST_FILE: &str = "manifest.json";
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct ExtensionManifest {
        pub name: String,
        pub version: String,
        pub description: String,
        pub permissions: Vec<String>,
        pub content_scripts: Option<Vec<ContentScript>>,
        pub background: Option<BackgroundScript>,
        pub icons: Option<std::collections::HashMap<String, String>>,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct ContentScript {
        pub matches: Vec<String>,
        pub js: Vec<String>,
        pub css: Option<Vec<String>>,
        pub run_at: Option<String>,
    }
    
    #[derive(Debug, Clone, serde::Deserialize)]
    pub struct BackgroundScript {
        pub service_worker: Option<String>,
        pub scripts: Option<Vec<String>>,
    }
    
    #[derive(Debug)]
    pub struct Extension {
        pub id: String,
        pub path: PathBuf,
        pub manifest: ExtensionManifest,
        pub enabled: bool,
    }
    
    impl Extension {
        pub async fn load(id: &str) -> Result<Self, String> {
            let path = PathBuf::from(EXTENSIONS_DIR).join(id);
            let manifest_path = path.join(MANIFEST_FILE);
            
            let manifest_content = fs::read_to_string(&manifest_path)
                .await
                .map_err(|e| format!("Failed to read manifest: {}", e))?;
                
            let manifest: ExtensionManifest = serde_json::from_str(&manifest_content)
                .map_err(|e| format!("Invalid manifest.json: {}", e))?;
                
            Ok(Self {
                id: id.to_string(),
                path,
                manifest,
                enabled: !path.join("DISABLED").exists(),
            })
        }
        
        pub async fn get_content_script_injection(&self, url: &str) -> Option<String> {
            if !self.enabled { return None; }
            
            let scripts = self.manifest.content_scripts.as_ref()?
                .iter()
                .filter(|cs| 
                    cs.matches.iter().any(|pattern| 
                        url_matches_pattern(url, pattern)
                    )
                )
                .flat_map(|cs| cs.js.iter().map(|js| (js, cs.run_at.clone())))
                .collect::<Vec<_>>();
                
            if scripts.is_empty() { return None; }
            
            let mut js_injection = String::new();
            for (js_file, run_at) in scripts {
                let js_path = self.path.join(js_file);
                if let Ok(js_content) = fs::read_to_string(&js_path).await {
                    let run_condition = match run_at.as_deref() {
                        Some("document_start") => "document.readyState !== 'loading'",
                        Some("document_end") => "document.readyState === 'interactive' || document.readyState === 'complete'",
                        Some("document_idle") => "document.readyState === 'complete'",
                        _ => "true",
                    };
                    
                    js_injection.push_str(&format!(
                        r#"(function() {{
                            if ({}) {{
                                {}
                            }}
                            document.addEventListener('readystatechange', function() {{
                                if ({}) {{
                                    {}
                                }}
                            }});
                        }})();"#,
                        run_condition,
                        js_content,
                        run_condition,
                        js_content
                    ));
                }
            }
            
            Some(js_injection)
        }
        
        pub async fn get_css_injection(&self, url: &str) -> Option<String> {
            if !self.enabled { return None; }
            
            let css_files = self.manifest.content_scripts.as_ref()?
                .iter()
                .filter(|cs| 
                    cs.matches.iter().any(|pattern| 
                        url_matches_pattern(url, pattern)
                    )
                )
                .flat_map(|cs| cs.css.as_deref().unwrap_or(&[]).iter())
                .collect::<Vec<_>>();
                
            if css_files.is_empty() { return None; }
            
            let mut css_injection = String::new();
            for css_file in css_files {
                let css_path = self.path.join(css_file);
                if let Ok(css_content) = fs::read_to_string(&css_path).await {
                    css_injection.push_str(&css_content);
                }
            }
            
            Some(css_injection)
        }
        
        pub async fn get_background_script(&self) -> Option<String> {
            if !self.enabled { return None; }
            
            let bg_script = match &self.manifest.background {
                Some(bg) => {
                    if let Some(worker) = &bg.service_worker {
                        Some(self.path.join(worker))
                    } else if let Some(scripts) = &bg.scripts {
                        if let Some(first_script) = scripts.first() {
                            Some(self.path.join(first_script))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
                None => None,
            };
            
            match bg_script {
                Some(path) => fs::read_to_string(&path).await.ok(),
                None => None,
            }
        }
    }
    
    fn url_matches_pattern(url: &str, pattern: &str) -> bool {
        if pattern == "<all_urls>" { return true; }
        
        let pattern = pattern
            .replace("*", ".*")
            .replace(".", r"\.")
            .replace("://", r"://");
            
        Regex::new(&pattern)
            .map(|re| re.is_match(url))
            .unwrap_or(false)
    }
    
    pub async fn load_all_extensions() -> Vec<Extension> {
        let mut extensions = Vec::new();
        
        if let Ok(entries) = fs::read_dir(EXTENSIONS_DIR).await {
            let mut stream = entries;
            while let Some(entry) = stream.next_entry().await.ok().flatten() {
                let path = if entry.file_type().await.ok().map(|ft| ft.is_dir()).unwrap_or(false) {
                    entry.path()
                } else {
                    continue;
                };
                if let Some(id) = path.file_name().and_then(|s| s.to_str()) {
                    if let Ok(ext) = Extension::load(id).await {
                        extensions.push(ext);
                    }
                }
            }
        }
        
        extensions
    }
    
    pub async fn get_injections_for_url(url: &str, extensions: &[Extension]) -> (Option<String>, Option<String>) {
        let mut js_injections = Vec::new();
        let mut css_injections = Vec::new();
        
        for ext in extensions {
            if let Some(js) = ext.get_content_script_injection(url).await {
                js_injections.push(js);
            }
            if let Some(css) = ext.get_css_injection(url).await {
                css_injections.push(css);
            }
        }
        
        (
            if js_injections.is_empty() { None } else { Some(js_injections.join("\n")) },
            if css_injections.is_empty() { None } else { Some(css_injections.join("\n")) }
        )
    }
    
    pub mod api {
        use super::*;
        
        pub fn setup_extension_apis(webview: &wry::webview::WebView) {
            webview.evaluate_script(r#"
                if (typeof chrome === 'undefined') {
                    window.chrome = {
                        runtime: {
                            getManifest: function() {
                                return {
                                    name: "Nexus Browser",
                                    version: "1.0",
                                };
                            },
                            sendMessage: function(message, responseCallback) {
                                if (window.chrome && window.chrome.webview) {
                                    window.chrome.webview.postMessage(JSON.stringify({
                                        a: 'ext-msg',
                                        p: message
                                    }));
                                }
                            }
                        }
                    };
                }
            "#).ok();
        }
    }
}

// ======================
// MODULE: AUTOCONFIG
// ======================
mod autoconfig {
    use super::*;
    
    pub fn detect_warp() -> bool {
        #[cfg(target_os = "windows")]
        {
            std::process::Command::new("sc")
                .args(&["query", "CloudflareWARP"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        
        #[cfg(target_os = "macos")]
        {
            std::process::Command::new("launchctl")
                .args(&["list", "com.cloudflare.1.1.1.1"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        
        #[cfg(target_os = "linux")]
        {
            std::process::Command::new("systemctl")
                .args(&["is-active", "cloudflare-warp"])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
    }
    
    pub fn detect_tor() -> bool {
        std::net::TcpStream::connect("127.0.0.1:9050").is_ok()
    }
    
    pub fn update_ui(px: &wry::application::event_loop::EventLoopProxy<Ev>) {
        let warp_detected = detect_warp();
        let tor_detected = detect_tor();
        
        let _ = px.send_event(Ev::Js(format!(
            "document.getElementById('warp-toggle').checked = {}; \
             document.getElementById('tor-toggle').checked = {};",
            warp_detected, tor_detected
        )));
    }
}

// ======================
// MAIN HTML (UI)
// ======================
fn html() -> String {
    r###"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--t1);height:100vh;display:flex;flex-direction:column;transition:background 0.3s, color 0.3s;}
:root{--bg:#000;--panel:#0a0a0a;--input:#111;--brd:#00ffff;--acc:#ff007f;--t1:#f8fafc;--t2:#94a3b8}
body.light{--bg:#f0f2f5;--panel:#ffffff;--input:#e4e6eb;--brd:#005f73;--acc:#b7094c;--t1:#1c1e21;--t2:#606770}
body.incognito{--brd:#9d4edd;--acc:#9d4edd}body.tor{--brd:#0d6efd;--acc:#0d6efd}
#app{display:flex;flex-direction:column;height:100vh}
header{display:flex;align-items:center;gap:8px;padding:10px;background:var(--panel);border-bottom:1px solid var(--brd)}
.btn{width:36px;height:36px;display:flex;align-items:center;justify-content:center;border:1px solid var(--brd);background:0 0;color:var(--t1);cursor:pointer;border-radius:6px;transition:0.2s}
.btn:hover{background:var(--brd);color:var(--bg)}
.btn-acc{border-color:var(--acc);color:var(--acc)}.btn-acc:hover{background:var(--acc);color:#fff}
#url{flex:1;background:var(--input);border:1px solid var(--brd);color:var(--t1);padding:10px 14px;outline:0;border-radius:6px}
#workspace{display:flex;flex:1;overflow:hidden;background:#fff}
aside{width:320px;background:var(--panel);border-left:1px solid var(--brd);display:flex;flex-direction:column;overflow:hidden}
.side-hd{padding:18px;border-bottom:1px solid var(--brd);font-weight:700;color:var(--brd);letter-spacing:2px;font-size:14px}
.side-scroll{flex:1;overflow-y:auto;padding:20px}
.sec-title{font-size:.8rem;color:var(--acc);margin:20px 0 12px;letter-spacing:2px;border-bottom:1px dashed var(--acc);padding-bottom:6px;font-weight:700;text-transform:uppercase}
.row{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;font-size:.85rem;color:var(--t1);font-weight:500}
.sw{position:relative;width:40px;height:20px}.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;cursor:pointer;inset:0;background:var(--input);border:1px solid var(--t2);transition:.3s;border-radius:20px}
.sl:before{position:absolute;content:"";height:14px;width:14px;left:2px;bottom:2px;background:var(--t2);border-radius:50%}
input:checked+.sl{background:var(--brd);border-color:var(--brd)}
input:checked+.sl:before{transform:translateX(20px);background:var(--bg)}
.stat{font-size:1.5rem;color:var(--brd);font-weight:800;text-align:center;margin:10px 0}
#dp{position:fixed;right:-400px;top:0;width:400px;height:100vh;background:var(--panel);border-left:2px solid var(--acc);z-index:99;padding:20px;overflow-y:auto;transition:right .3s}
#dp.o{right:0}.le{font-size:12px;margin-bottom:5px;word-break:break-all}.le.error{color:var(--acc)}.le.info{color:var(--brd)}
.modal{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:420px;max-width:92vw;background:var(--panel);border:2px solid var(--brd);padding:30px;z-index:1000;display:none;border-radius:12px}
.modal.show{display:block}
.v-in{width:100%;padding:10px;margin:8px 0;background:var(--input);border:1px solid var(--brd);color:var(--t1);border-radius:6px;outline:0}
.v-btn{width:100%;padding:10px;margin:5px 0;background:var(--brd);color:var(--bg);border:0;cursor:pointer;font-weight:700;border-radius:6px}
.v-btn:hover{background:var(--acc);color:#fff}
#ai-log{margin-top:12px;max-height:200px;overflow-y:auto;font-size:13px;text-align:left}
.ai-msg{margin:6px 0;padding:8px;border-radius:6px;background:var(--input)}
.ai-msg.u{border-left:3px solid var(--acc)}.ai-msg.a{border-left:3px solid var(--brd)}
#tabs{display:flex;gap:4px;padding:0 10px;height:40px;align-items:center;overflow-x:auto;background:var(--panel);border-bottom:1px solid var(--brd)}
.tab{padding:6px 16px;border-radius:6px 6px 0 0;cursor:pointer;background:var(--input);color:var(--t1);white-space:nowrap;position:relative;display:flex;align-items:center;gap:6px;}
.tab.active{background:var(--panel);color:var(--brd);border-top:2px solid var(--brd)}
.tab.frozen{opacity:0.6; font-style:italic;}
.tab-close{display:inline-flex;width:18px;height:18px;align-items:center;justify-content:center;border-radius:50%;color:var(--t2)}
.tab-close:hover{background:var(--brd);color:var(--bg)}
#sidebar{position:fixed;right:-320px;top:0;width:320px;height:100vh;background:var(--panel);border-left:1px solid var(--brd);transition:right .3s;z-index:100;overflow-y:auto}
#sidebar-toggle{position:fixed;right:0;top:10px;width:24px;height:40px;background:var(--brd);color:var(--bg);display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:101;border-radius:6px 0 0 6px}
#sidebar-toggle:hover{transform:translateX(-5px)}
#sidebar.o{right:0}
#password-suggestion{position:fixed;bottom:20px;right:20px;background:var(--panel);border:1px solid var(--brd);border-radius:8px;padding:15px;box-shadow:0 4px 20px rgba(0,0,0,.2);z-index:2000;max-width:400px;display:none}
.p-suggest-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}
.p-suggest-title{font-weight:600;color:var(--brd)}
.p-suggest-close{background:0 0;border:0;color:var(--t2);cursor:pointer;font-size:1.2rem}
.p-suggest-content{margin-bottom:15px}
.p-suggest-pass{background:var(--input);border:1px solid var(--brd);border-radius:6px;padding:8px 12px;margin:8px 0;font-family:monospace}
.p-suggest-actions{display:flex;gap:8px}
.p-suggest-btn{flex:1;padding:8px;border:0;border-radius:6px;cursor:pointer;font-weight:500}
.p-suggest-btn.save{background:var(--brd);color:var(--bg)}
.p-suggest-btn.generate{background:var(--input);color:var(--brd)}
#extensions-list{display:flex;flex-direction:column;gap:15px}
.extension{padding:15px;background:var(--input);border-radius:8px}
.extension-header{display:flex;gap:10px;align-items:center;margin-bottom:10px}
.extension-icon{width:40px;height:40px;background:var(--panel);border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:700}
.extension-name{font-weight:600;color:var(--brd)}
.extension-version{color:var(--t2);font-size:0.85rem}
.extension-description{color:var(--t2);margin-bottom:10px}
.extension-actions{display:flex;gap:10px}
.extension-toggle{width:40px;height:20px;position:relative}
.extension-toggle input{opacity:0;width:0;height:0}
.extension-toggle .slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:var(--input);border:1px solid var(--t2);transition:.3s;border-radius:20px}
.extension-toggle .slider:before{position:absolute;content:"";height:14px;width:14px;left:2px;bottom:2px;background:var(--t2);transition:.3s;border-radius:50%}
.extension-toggle input:checked + .slider{background:var(--brd);border-color:var(--brd)}
.extension-toggle input:checked + .slider:before{transform:translateX(20px);background:var(--bg)}
.ext-btn { background: var(--input); border: 1px solid var(--brd); color: var(--brd); padding: 8px; width: 100%; border-radius: 6px; cursor: pointer; margin-top: 10px; font-weight: bold; }
.ext-btn:hover { background: var(--brd); color: var(--bg); }
</style></head><body>
<div id="app">
  <div id="tabs"></div>
  <header>
    <button class="btn" onclick="sr('back')">⟵</button>
    <button class="btn" onclick="sr('fwd')">⟶</button>
    <button class="btn" onclick="sr('ref')">⟳</button>
    <input type="text" id="url" data-i18n-placeholder="search_ph" placeholder="Search or enter address" onkeydown="if(event.key==='Enter')sr('nav',this.value)">
    <button class="btn" onclick="sr('nav', 'https://accounts.google.com')" title="Google Login">G</button>
    <button class="btn" onclick="sr('bookmark', v('url'))" title="Bookmark">⭐</button>
    <button class="btn" onclick="toggleModal('vault')" title="Vault">🔐</button>
    <button class="btn" onclick="toggleModal('aip')" title="AI Assistant">🤖</button>
    <button class="btn" onclick="document.getElementById('dp').classList.toggle('o')" title="Dev Console">💻</button>
    <button class="btn" onclick="toggleTheme()" title="Toggle Theme" id="theme-btn">🌙</button>
    <button class="btn" onclick="toggleLang()" title="Language" id="lang-btn">🇻🇳</button>
    <button class="btn btn-acc" onclick="sr('new-tab', 'normal')" data-i18n="new_tab">+ Tab</button>
    <button class="btn" id="sidebar-toggle">≡</button>
  </header>
  <div id="workspace"></div>
  <div id="dp"><h2 style="color:var(--acc);border-bottom:1px solid var(--acc)">DEV CONSOLE</h2><div id="dl"></div></div>

  <div id="sidebar">
    <div style="padding:20px 0;text-align:center">
      <div style="font-size:1.5rem;margin-bottom:10px">≡</div>
      <div style="font-weight:600;margin-bottom:20px;color:var(--brd)">NEXUS MENU</div>
      <div class="row" style="margin-bottom:15px"><button class="btn btn-acc" style="width:100%" onclick="sr('new-tab', 'normal')" data-i18n="new_tab">+ New Tab</button></div>
      <div class="row" style="margin-bottom:15px"><button class="btn" style="width:100%" onclick="sr('new-tab', 'incognito')" data-i18n="private_tab">+ Private Tab</button></div>
      <div class="row" style="margin-bottom:15px"><button class="btn" style="width:100%" onclick="sr('new-tab', 'tor')" data-i18n="tor_tab">+ Tor Tab</button></div>
    </div>
    
    <div class="side-hd" data-i18n="security">🛡 SECURITY</div>
    <div class="side-scroll">
      <div class="sec-title" data-i18n="connection">CONNECTION</div>
      <div class="row" style="margin-bottom:15px">
        <span>Cloudflare WARP</span>
        <label class="sw">
          <input type="checkbox" id="warp-toggle" onchange="ts('warp',this.checked)">
          <span class="sl"></span>
        </label>
      </div>
      <div class="row" style="margin-bottom:15px">
        <span>Tor Network</span>
        <label class="sw">
          <input type="checkbox" id="tor-toggle" onchange="ts('tor',this.checked)">
          <span class="sl"></span>
        </label>
      </div>
      
      <div class="sec-title" data-i18n="shields">SHIELDS</div>
      <div class="row"><span>Adblock (Inc. YouTube)</span><label class="sw"><input type="checkbox" checked onchange="ts('ad',this.checked)"><span class="sl"></span></label></div>
      <div class="row"><span>Tracker Block</span><label class="sw"><input type="checkbox" checked onchange="ts('trk',this.checked)"><span class="sl"></span></label></div>
      <div class="row"><span>Cookie Shield</span><label class="sw"><input type="checkbox" checked onchange="ts('cookie',this.checked)"><span class="sl"></span></label></div>
      <div class="row"><span>Domain Sinkhole</span><label class="sw"><input type="checkbox" checked onchange="ts('sink',this.checked)"><span class="sl"></span></label></div>
      <div class="row"><span>Anti-Fingerprint</span><label class="sw"><input type="checkbox" checked onchange="ts('anti_fp',this.checked)"><span class="sl"></span></label></div>
      
      <div class="sec-title">PASSWORDS</div>
      <div class="row" style="margin-bottom:15px">
        <span>Auto Save</span>
        <label class="sw">
          <input type="checkbox" checked onchange="ts('auto-save',this.checked)">
          <span class="sl"></span>
        </label>
      </div>
      <div class="row" style="margin-bottom:15px">
        <span>Password Suggest</span>
        <label class="sw">
          <input type="checkbox" checked onchange="ts('pass-suggest',this.checked)">
          <span class="sl"></span>
        </label>
      </div>
      
      <div class="sec-title">EXTENSIONS</div>
      <div id="extensions-list"></div>
      <p style="font-size:12px; color:var(--t2); margin-top:10px;">Native .crx install is not supported. Use custom JS extensions.</p>
      <button class="ext-btn" onclick="sr('nav', 'https://chrome.google.com/webstore')">🌐 Open Chrome Web Store</button>
      
      <div class="sec-title">SYNC</div>
      <div class="row" style="margin-bottom:15px">
        <span>Chrome</span>
        <label class="sw">
          <input type="checkbox" onchange="ts('sync-chrome',this.checked)">
          <span class="sl"></span>
        </label>
      </div>
      <div class="row" style="margin-bottom:15px">
        <span>Firefox</span>
        <label class="sw">
          <input type="checkbox" onchange="ts('sync-firefox',this.checked)">
          <span class="sl"></span>
        </label>
      </div>
      <div class="row" style="margin-bottom:15px">
        <span>Edge</span>
        <label class="sw">
          <input type="checkbox" onchange="ts('sync-edge',this.checked)">
          <span class="sl"></span>
        </label>
      </div>
      <div class="row" style="margin-top:10px">
        <button class="v-btn" onclick="sr('sync-now')">SYNC NOW</button>
      </div>
      
      <div class="sec-title" data-i18n="stats">STATS</div>
      <div class="stat" id="tc">0 Blocked</div>
    </div>
  </div>

  <div id="vault" class="modal">
    <h2 style="color:var(--brd);margin-bottom:15px" data-i18n="vault_title">🔐 NEXUS VAULT</h2>
    <input type="password" id="v-master" class="v-in" placeholder="Master Password">
    <input type="text" id="v-domain" class="v-in" placeholder="Domain">
    <input type="text" id="v-user" class="v-in" placeholder="Username">
    <input type="password" id="v-pass" class="v-in" placeholder="Password">
    <button class="v-btn" onclick="vAct('save')" data-i18n="save">SAVE</button>
    <button class="v-btn" onclick="vAct('get')" data-i18n="retrieve">RETRIEVE</button>
    <button class="v-btn" onclick="vAct('gen')">GENERATE</button>
    <button class="v-btn" onclick="toggleModal('vault')" style="background:var(--acc);color:#fff" data-i18n="close">CLOSE</button>
    <div id="v-res" style="margin-top:10px;font-size:12px;color:var(--brd)"></div>
  </div>

  <div id="aip" class="modal">
    <h2 style="color:var(--brd);margin-bottom:15px">🤖 AI Assistant</h2>
    <input type="text" id="ai-endpoint" class="v-in" placeholder="Endpoint">
    <input type="password" id="ai-key" class="v-in" placeholder="API Key">
    <input type="text" id="ai-model" class="v-in" placeholder="Model">
    <button class="v-btn" onclick="aiCfg()" data-i18n="save">SAVE</button>
    <textarea id="ai-prompt" class="v-in" rows="3" placeholder="Ask AI..."></textarea>
    <button class="v-btn" onclick="aiAsk()">ASK</button>
    <button class="v-btn" onclick="toggleModal('aip')" style="background:var(--acc);color:#fff" data-i18n="close">CLOSE</button>
    <div id="ai-log"></div>
  </div>
  
  <div id="password-suggestion">
    <div class="p-suggest-header">
      <div class="p-suggest-title">Save Password?</div>
      <button class="p-suggest-close" onclick="hidePasswordSuggestion()">&times;</button>
    </div>
    <div class="p-suggest-content">
      <div>Save for <span id="suggest-domain" style="font-weight:600"></span>?</div>
      <div class="p-suggest-pass" id="suggest-password"></div>
    </div>
    <div class="p-suggest-actions">
      <button class="p-suggest-btn save" onclick="savePasswordSuggestion()">Save</button>
      <button class="p-suggest-btn generate" onclick="generateStrongPassword()">Generate</button>
    </div>
  </div>
</div>
<script>
// --- ĐA NGÔN NGỮ (i18n) ---
const dict = {
  en: {
    search_ph: "Search Google or type URL...", new_tab: "+ Tab", private_tab: "+ Private Tab", tor_tab: "+ Tor Tab",
    security: "🛡 SECURITY", connection: "CONNECTION", shields: "SHIELDS", stats: "STATS",
    vault_title: "🔐 NEXUS VAULT", save: "SAVE", retrieve: "RETRIEVE", close: "CLOSE"
  },
  vi: {
    search_ph: "Tìm kiếm hoặc nhập URL...", new_tab: "+ Tab Mới", private_tab: "+ Tab Ẩn Danh", tor_tab: "+ Tab Tor",
    security: "🛡 BẢO MẬT", connection: "KẾT NỐI", shields: "LÁ CHẮN", stats: "THỐNG KÊ",
    vault_title: "🔐 KHO LƯU TRỮ", save: "LƯU", retrieve: "LẤY MẬT KHẨU", close: "ĐÓNG"
  }
};
let lang = localStorage.getItem('nexus_lang') || 'en';
let theme = localStorage.getItem('nexus_theme') || 'dark';

function applyLang() {
  document.querySelectorAll('[data-i18n]').forEach(el => { el.textContent = dict[lang][el.getAttribute('data-i18n')]; });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(el => { el.placeholder = dict[lang][el.getAttribute('data-i18n-placeholder')]; });
  document.getElementById('lang-btn').textContent = lang === 'en' ? '🇻🇳' : '🇬🇧';
}
function toggleLang() { lang = lang === 'en' ? 'vi' : 'en'; localStorage.setItem('nexus_lang', lang); applyLang(); }

function applyTheme() {
  if(theme === 'light') { document.body.classList.add('light'); document.getElementById('theme-btn').textContent = '☀️'; }
  else { document.body.classList.remove('light'); document.getElementById('theme-btn').textContent = '🌙'; }
}
function toggleTheme() { theme = theme === 'dark' ? 'light' : 'dark'; localStorage.setItem('nexus_theme', theme); applyTheme(); }

applyLang(); applyTheme();

let tabs = [{id:'home',name:'Home',url:'nexus://home',mode:'normal', frozen: false}];
let activeTab = 0;
let extensions = [];

function initTabs() { renderTabs(); }
function renderTabs() {
  document.getElementById('tabs').innerHTML = tabs.map((t,i)=>`
    <div class="tab ${i===activeTab?'active':''} ${t.frozen?'frozen':''}" onclick="switchTab(${i})">
      ${t.frozen ? '❄️ ' : ''}${t.name}
      <span class="tab-close" onclick="closeTab(${i},event)">&times;</span>
    </div>`).join('');
}

function newTab(m) { sr('new-tab',m); }
function closeTab(i,e) { e.stopPropagation(); tabs.length>1 && sr('close-tab',i); }
function switchTab(i) { 
  if(i!==activeTab) {
    if(tabs[i].frozen) { sr('unfreeze-tab', i); }
    else { activeTab=i; sr('switch-tab',i); renderTabs(); }
  }
}

function sr(a,p){window.chrome?.webview?.postMessage(JSON.stringify({a,p}))}
function ts(k,v){sr('shld',{s:k,v:v})}
function uc(c){document.getElementById('tc').textContent=c+(lang==='vi'?' Đã chặn':' Blocked')}
function toggleModal(id){document.getElementById(id).classList.toggle('show')}
function setUrl(u){document.getElementById('url').value=u}
function vAct(a){sr('vault',{a,m:v('v-master'),d:v('v-domain'),u:v('v-user'),p:v('v-pass')})}
function vRes(t){document.getElementById('v-res').textContent=t}
function aiCfg(){sr('ai_cfg',{e:v('ai-endpoint'),k:v('ai-key'),m:v('ai-model')})}
function aiAsk(){const q=v('ai-prompt');q&&(addAi('u',q),sr('ai',q),document.getElementById('ai-prompt').value='')}
function addAi(r,t){const l=document.getElementById('ai-log');l.innerHTML+=`<div class="ai-msg ${r}">${r==='u'?'You':'AI'}: ${t}</div>`;l.scrollTop=l.scrollHeight}
function lg(m,t){const l=document.getElementById('dl');l.innerHTML=`<div class="le ${t||'info'}">[${new Date().toTimeString().split(' ')[0]}] ${m}</div>`+l.innerHTML}
function v(id){return document.getElementById(id).value}

document.getElementById('v-master').addEventListener('input',e=>setTimeout(()=>e.target.value='',5000));
document.getElementById('sidebar-toggle').addEventListener('click',()=>document.getElementById('sidebar').classList.toggle('o'));

function showPasswordSuggestion(d) {
  document.getElementById('suggest-domain').textContent = new URL(d.url).hostname;
  document.getElementById('suggest-password').textContent = '•'.repeat(d.password.length);
  document.getElementById('password-suggestion').style.display = 'block';
}

function hidePasswordSuggestion() { document.getElementById('password-suggestion').style.display = 'none'; }
function savePasswordSuggestion() { 
  if (window.passwordSuggestionData) {
    sr('save-password', window.passwordSuggestionData);
    hidePasswordSuggestion();
  }
}
function generateStrongPassword() {
  if (window.passwordSuggestionData) {
    const p = window.nexusGeneratePassword(16);
    document.getElementById('suggest-password').textContent = p;
    window.passwordSuggestionData.password = p;
    sr('fill-password', {
      url: window.passwordSuggestionData.url,
      username: window.passwordSuggestionData.username,
      password: p
    });
  }
}

function renderExtensions(extensions) {
  const list = document.getElementById('extensions-list');
  list.innerHTML = '';
  
  extensions.forEach(ext => {
    const extEl = document.createElement('div');
    extEl.className = 'extension';
    extEl.innerHTML = `
      <div class="extension-header">
        <div class="extension-icon">${ext.name.charAt(0)}</div>
        <div>
          <div class="extension-name">${ext.name} <span class="extension-version">${ext.version}</span></div>
          <div class="extension-description">${ext.description}</div>
        </div>
      </div>
      <div class="extension-actions">
        <label class="extension-toggle">
          <input type="checkbox" ${ext.enabled ? 'checked' : ''} onchange="toggleExtension('${ext.id}', this.checked)">
          <span class="slider"></span>
        </label>
      </div>
    `;
    list.appendChild(extEl);
  });
}

function toggleExtension(id, enabled) {
  sr('ext-toggle', {id, enabled});
}

document.addEventListener('DOMContentLoaded',function() {
  initTabs();
  sr('ext-list', '');
});

window.addEventListener('message',function(event) {
  try {
    const data = JSON.parse(event.data);
    if (data.a === 'update-tabs') {
      updateTabs(data.p);
    } else if (data.a === 'password-detected') {
      window.passwordSuggestionData = data.p;
      showPasswordSuggestion(data.p);
    } else if (data.a === 'ext-list-response') {
      extensions = data.p;
      renderExtensions(extensions);
    } else if (data.a === 'ext-toggle-response') {
      const ext = extensions.find(e => e.id === data.p.id);
      if (ext) ext.enabled = data.p.enabled;
      renderExtensions(extensions);
    } else if (data.a === 'nav-internal') {
      sr('nav-internal', data.p);
    } else if (data.a === 'nav-post') {
      sr('nav-post', data.p);
    } else if (data.a === 'new-tab-url') {
      sr('new-tab-url', data.p);
    } else if (data.a === 'console-log') {
      sr('console-log', data.p);
    } else if (data.a === 'inc') {
      sr('inc', '');
    }
  } catch (e) {}
});

window.updateTabs = function(d) {
  tabs = d.tabs;
  activeTab = d.activeTab;
  renderTabs();
  let currentUrl = tabs[activeTab].url;
  document.getElementById('url').value = currentUrl === 'nexus://home' ? '' : currentUrl;
}
</script></body></html>"###.into()
}

// ======================
// RENDER PAGE (SECURE IFRAME)
// ======================
fn render_page(html_out: &str, url: &str, px: &wry::application::event_loop::EventLoopProxy<Ev>) {
    if let (Ok(h), Ok(u)) = (serde_json::to_string(html_out), serde_json::to_string(url)) {
        // BẢO MẬT: Thêm sandbox attribute để ngăn chặn popup và script độc hại thoát ra ngoài
        // Cho phép allow-presentation để YouTube có thể chạy video
        let _ = px.send_event(Ev::Js(format!(
            "{{let w=document.getElementById('workspace');w.innerHTML='';let f=document.createElement('iframe');f.sandbox='allow-scripts allow-same-origin allow-forms allow-presentation';f.style='width:100%;height:100%;border:none;background:#fff;';f.srcdoc={};w.appendChild(f);}}",
            h
        )));
        let _ = px.send_event(Ev::Js(format!("setUrl({});", u)));
    }
}

// ======================
// LOAD URL (WITH TRACKING STRIPPER)
// ======================
async fn load_url(url: String, st: Arc<RwLock<state::State>>, px: &wry::application::event_loop::EventLoopProxy<Ev>, record: bool) {
    load_url_method(url, "GET", None, st, px, record).await;
}

async fn load_url_method(url: String, method: &str, body: Option<serde_json::Value>, st: Arc<RwLock<state::State>>, px: &wry::application::event_loop::EventLoopProxy<Ev>, record: bool) {
    let cfg = { let g = st.read().await; g.active_tab().cfg.clone() };
    
    if url == "nexus://home" {
        let home_html = r#"
        <!DOCTYPE html><html><head><style>
        body { background: var(--bg, #0a0a0a); color: var(--t1, #00ffff); font-family: 'Segoe UI', sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; }
        h1 { font-size: 5rem; letter-spacing: 12px; margin-bottom: 10px; font-weight: 900; }
        p { color: var(--acc, #ff007f); letter-spacing: 6px; font-weight: 600; margin-bottom: 40px; }
        .search { width: 60%; max-width: 600px; padding: 16px; border-radius: 30px; border: 2px solid var(--t1, #00ffff); background: var(--input, #111); color: #fff; font-size: 1.2rem; text-align: center; outline: none; }
        </style></head><body>
        <h1>NEXUS</h1>
        <p>SECURE EDITION // AES-256 ENCRYPTED</p>
        <input type="text" class="search" placeholder="Search Google or type URL..." onkeydown="if(event.key==='Enter') window.top.postMessage(JSON.stringify({a:'nav-internal', p: this.value}), '*')">
        </body></html>
        "#;
        render_page(home_html, &url, px);
        if record {
            let mut g = st.write().await;
            let t = g.active_tab_mut();
            t.push_hist(url.clone());
            t.url = url;
            t.name = "Home".into();
            update_tabs(&g, px);
        }
        return;
    }

    if cfg.sinkhole && sinkhole::check(&url) {
        let _ = px.send_event(Ev::Js(format!("lg('SINKHOLE: {}','error');", url)));
        let blocked = { let mut g = st.write().await; g.blocked += 1; g.blocked };
        let _ = px.send_event(Ev::Js(format!("uc({});", blocked)));
        return;
    }
    
    let client = {
        let mut g = st.write().await;
        let t = g.active_tab_mut();
        t.update_client();
        t.client.clone().unwrap_or_else(reqwest::Client::new)
    };
    
    // BẢO MẬT 1: Ép buộc HTTPS (HSTS cơ bản)
    let secure_url = if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
        url.replace("http://", "https://")
    } else { url.clone() };
    
    // BẢO MẬT 2: Xóa tham số theo dõi (Tracking Stripper)
    let clean_url = if let Ok(mut parsed_url) = Url::parse(&secure_url) {
        let mut query_pairs: Vec<(String, String)> = Vec::new();
        for (k, v) in parsed_url.query_pairs() {
            // Xóa các tham số theo dõi phổ biến
            if !k.starts_with("utm_") && k != "fbclid" && k != "gclid" && k != "msclkid" {
                query_pairs.push((k.into_owned(), v.into_owned()));
            }
        }
        parsed_url.query_pairs_mut().clear().extend_pairs(query_pairs);
        parsed_url.to_string()
    } else {
        secure_url.clone()
    };
    
    let req = if method == "POST" {
        let mut form = HashMap::new();
        if let Some(b) = body {
            if let Some(obj) = b.as_object() {
                for (k, v) in obj {
                    form.insert(k.clone(), v.as_str().unwrap_or("").to_string());
                }
            }
        }
        client.post(&clean_url).form(&form)
    } else {
        client.get(&clean_url)
    };
    
    if let Ok(r) = req.header("Referer", "").header("DNT", "1").send().await {
        let content_type = r.headers().get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("text/html")
            .to_lowercase();

        if content_type.contains("text/html") || content_type.contains("text/plain") {
            if let Ok(h) = r.text().await {
                let safe_url = clean_url.replace('&', "&amp;").replace('"', "&quot;");
                let shield = injection::get_security_payload(&cfg);
                let inj = format!(r#"<base href="{}">{}"#, safe_url, shield);
                
                // FIX BUG PANIC: Sử dụng to_ascii_lowercase()
                let lower_h = h.to_ascii_lowercase();
                let mut html_out = if let Some(start) = lower_h.find("<head") {
                    h[..start].to_string() + &h[start..].find('>').map_or_else(
                        || format!("{}{}", inj, h),
                        |end| {
                            let pos = start + end + 1;
                            format!("{}{}{}", &h[..pos], inj, &h[pos..])
                        }
                    )
                } else { format!("{}{}", inj, h) };
                
                let extensions = extensions::load_all_extensions().await;
                if let (Some(js), Some(css)) = extensions::get_injections_for_url(&clean_url, &extensions).await {
                    let ext_api = r#"<script>if(typeof chrome==='undefined'){window.chrome={runtime:{sendMessage:function(m,c){window.top.postMessage(JSON.stringify({a:'ext-msg',p:m}),'*');}}}}</script>"#;
                    let ext_inj = format!(r#"{}<style id="nexus-ext-css">{}</style><script id="nexus-ext-js">{}</script>"#, ext_api, css, js);
                    if let Some(body_end) = html_out.rfind("</body>") {
                        html_out.insert_str(body_end, &ext_inj);
                    } else {
                        html_out.push_str(&ext_inj);
                    }
                }
                
                render_page(&html_out, &clean_url, px);
            }
        } else if content_type.contains("image/") {
            let html = format!(r#"<html><body style="margin:0;background:#0e0e0e;display:flex;justify-content:center;align-items:center;height:100vh;"><img src="{}" style="max-width:100%;max-height:100%;"></body></html>"#, clean_url);
            render_page(&html, &clean_url, px);
        } else {
            let _ = px.send_event(Ev::Js(format!("lg('Downloading: {}','info');", clean_url)));
            tokio::spawn(dl::turbo(clean_url.clone(), st.clone()));
            return;
        }
        
        if record {
            let mut g = st.write().await;
            let t = g.active_tab_mut();
            t.push_hist(clean_url.clone());
            t.url = clean_url.clone();
            if let Ok(parsed) = url::Url::parse(&clean_url) {
                t.name = parsed.host_str().unwrap_or("New Tab").to_string();
            }
            update_tabs(&g, px);
        }
    } else {
        let _ = px.send_event(Ev::Js(format!("lg('Failed to load: {}','error');", clean_url)));
    }
}

// ======================
// UPDATE TABS
// ======================
fn update_tabs(state: &state::State, px: &wry::application::event_loop::EventLoopProxy<Ev>) {
    let tabs = state.tabs.iter().map(|t| json!({
        "id": t.id, "name": t.name, "url": t.url,
        "frozen": t.frozen, // TÍNH NĂNG ĐÓNG BĂNG TAB
        "mode": match t.mode { state::TabMode::Normal => "normal", state::TabMode::Incognito => "incognito", state::TabMode::Tor => "tor" }
    })).collect::<Vec<_>>();
    
    if let Ok(t) = serde_json::to_string(&tabs) {
        let _ = px.send_event(Ev::Js(format!(r#"if(window.updateTabs)window.updateTabs({{"tabs":{},"activeTab":{}}})"#, t, state.active_tab)));
    }
}

// ======================
// MAIN FUNCTION
// ======================
fn main() {
    dotenvy::dotenv().ok();
    std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    
    let el = EventLoopBuilder::<Ev>::with_user_event().build();
    let w = WindowBuilder::new()
        .with_title("NEXUS SECURE")
        .with_inner_size(LogicalSize::new(1200, 800))
        .build(&el)
        .unwrap();
    
    let mut initial = state::State::new();
    initial.tabs[0].vault = Some(vault::load());
    let st = Arc::new(RwLock::new(initial));
    let px = el.create_proxy();
    
    let rt = Builder::new_multi_thread()
        .worker_threads(std::cmp::max(2, num_cpus::get() - 1))
        .thread_stack_size(2 * 1024 * 1024)
        .enable_all()
        .build()
        .unwrap();
    
    let handle = rt.handle().clone();
    let handle_for_loop = handle.clone();
    let (ist, ipx) = (st.clone(), px.clone());
    
    // --- TÍNH NĂNG ĐÓNG BĂNG TAB (BACKGROUND TASK) ---
    let freeze_st = st.clone();
    let freeze_px = px.clone();
    rt.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut g = freeze_st.write().await;
            let active_idx = g.active_tab;
            let mut changed = false;
            
            for (i, tab) in g.tabs.iter_mut().enumerate() {
                // Nếu không phải tab hiện tại, chưa bị đóng băng, và không hoạt động > 5 phút
                if i != active_idx && !tab.frozen && tab.last_active.elapsed() > Duration::from_secs(300) {
                    tab.frozen = true;
                    tab.client = None; // Giải phóng bộ nhớ reqwest client
                    changed = true;
                }
            }
            if changed {
                update_tabs(&g, &freeze_px);
            }
        }
    });
    
    let wb = WebViewBuilder::new(w)
        .unwrap()
        // BẢO MẬT: Tắt DevTools để tránh bị inject script từ bên ngoài
        .with_devtools(false)
        // SPOOFING: Giả mạo User-Agent ở cấp độ WebView để Google Login không chặn
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
        .with_html(html())
        .unwrap()
        .with_back_forward_navigation_gestures(false)
        .with_hotkeys_zoom(false)
        .with_ipc_handler(move |_window, msg| {
            let (ist, ipx, handle) = (ist.clone(), ipx.clone(), handle.clone());
            let p: JsonValue = match serde_json::from_str(&msg) { Ok(v) => v, Err(_) => return };
            let (a, d) = (p["a"].as_str().unwrap_or("").to_string(), p["p"].clone());
            
            handle.spawn(async move {
                match a.as_str() {
                    "nav" | "nav-internal" => {
                        if let Some(u) = d.as_str().map(search::resolve) {
                            load_url(u, ist.clone(), &ipx, true).await;
                        }
                    }
                    "nav-post" => {
                        let url = d["url"].as_str().unwrap_or("").to_string();
                        let body = d["body"].clone();
                        load_url_method(url, "POST", Some(body), ist.clone(), &ipx, true).await;
                    }
                    "new-tab-url" => {
                        if let Some(url) = d.as_str() {
                            let mut g = ist.write().await;
                            let idx = g.new_tab(state::TabMode::Normal);
                            ipx.send_event(Ev::NewTab(idx)).ok();
                            update_tabs(&g, &ipx);
                            let u = url.to_string();
                            drop(g);
                            load_url(u, ist.clone(), &ipx, true).await;
                        }
                    }
                    "console-log" => {
                        if let Some(msg) = d.as_str() {
                            let safe_msg = msg.replace('\'', "\\'").replace('\n', " ");
                            ipx.send_event(Ev::Js(format!("lg('{}','info');", safe_msg))).ok();
                        }
                    }
                    "bookmark" => {
                        if let Some(url) = d.as_str() {
                            if url.is_empty() || url == "nexus://home" { return; }
                            let mut g = ist.write().await;
                            g.bookmarks.push(state::Bookmark { title: url.to_string(), url: url.to_string() });
                            ipx.send_event(Ev::Js("lg('⭐ Bookmark saved','info');".into())).ok();
                        }
                    }
                    "back" => {
                        let mut g = ist.write().await;
                        if let Some(u) = g.active_tab_mut().go_back() {
                            drop(g);
                            load_url(u, ist.clone(), &ipx, false).await;
                        }
                    }
                    "fwd" => {
                        let mut g = ist.write().await;
                        if let Some(u) = g.active_tab_mut().go_fwd() {
                            drop(g);
                            load_url(u, ist.clone(), &ipx, false).await;
                        }
                    }
                    "ref" => {
                        let g = ist.read().await;
                        if let Some(u) = g.active_tab().current() {
                            drop(g);
                            load_url(u, ist.clone(), &ipx, false).await;
                        }
                    }
                    "inc" => {
                        let c = { let mut g = ist.write().await; g.blocked += 1; g.blocked };
                        ipx.send_event(Ev::Js(format!("uc({});", c))).ok();
                    }
                    "shld" => if let (Some(s), Some(v)) = (d["s"].as_str(), d["v"].as_bool()) {
                        let mut g = ist.write().await;
                        {
                            let tab = g.active_tab_mut();
                            match s {
                                "ad" => tab.cfg.ad = v,
                                "trk" => tab.cfg.trk = v,
                                "sink" => tab.cfg.sinkhole = v,
                                "cookie" => tab.cfg.cookie = v,
                                "anti_fp" => tab.cfg.anti_fp = v,
                                "warp" => { 
                                    tab.cfg.warp = v; 
                                    if v { 
                                        tab.cfg.tor = false; 
                                        ipx.send_event(Ev::Js("document.getElementById('tor-toggle').checked = false;".into())).ok();
                                    } 
                                },
                                "tor" => { 
                                    tab.cfg.tor = v; 
                                    if v { 
                                        tab.cfg.warp = false; 
                                        ipx.send_event(Ev::Js("document.getElementById('warp-toggle').checked = false;".into())).ok();
                                    } 
                                },
                                _ => {}
                            }
                            if matches!(s, "ad" | "trk" | "sink" | "cookie" | "anti_fp" | "warp" | "tor") {
                                tab.update_client();
                            }
                        }
                        match s {
                            "auto-save" => g.global_cfg.auto_save_passwords = v,
                            "pass-suggest" => g.global_cfg.show_password_suggestions = v,
                            "sync-chrome" => g.sync.config.chrome = v,
                            "sync-firefox" => g.sync.config.firefox = v,
                            "sync-edge" => g.sync.config.edge = v,
                            _ => {}
                        }
                    },
                    "ai_cfg" => if let (Some(e), Some(k), Some(m)) = (d["e"].as_str(), d["k"].as_str(), d["m"].as_str()) {
                        let mut g = ist.write().await;
                        let tab = g.active_tab_mut();
                        tab.ai.endpoint = e.into(); tab.ai.key = k.into(); tab.ai.model = m.into();
                        ipx.send_event(Ev::Js("lg('AI config saved','info');".into())).ok();
                    },
                    "ai" => {
                        if let Some(p) = d.as_str() {
                            let r = ai::ask(p.into(), ist.clone()).await;
                            if let Ok(j) = serde_json::to_string(&r) {
                                ipx.send_event(Ev::Js(format!("addAi('a',{});", j))).ok();
                            }
                        }
                    }
                    "vault" => if let (Some(a), Some(m), Some(d), Some(u), Some(p)) = 
                        (d["a"].as_str(), d["m"].as_str(), d["d"].as_str(), d["u"].as_str(), d["p"].as_str()) 
                    {
                        let (act, m, d, u, p) = (a.to_string(), m.to_string(), d.to_string(), u.to_string(), p.to_string());
                        let master = zeroize::Zeroizing::new(m);
                        
                        if act == "save" && !master.is_empty() && !d.is_empty() {
                            if let Some((enc, nonce, salt)) = vault::encrypt(&p, &master) {
                                let entries = {
                                    let mut g = ist.write().await;
                                    let tab = g.active_tab_mut();
                                    if let Some(vault) = &mut tab.vault {
                                        vault.push(state::VaultEntry {
                                            domain: d, user: u, pass: enc, nonce, salt,
                                            created: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                                            last_used: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                                        });
                                        vault.clone()
                                    } else { Vec::new() }
                                };
                                let msg = if !entries.is_empty() && vault::save(&entries) {
                                    "vRes('✅ Saved');"
                                } else {
                                    "vRes('⚠ Save failed');"
                                };
                                ipx.send_event(Ev::Js(msg.into())).ok();
                            }
                        } else if act == "get" {
                            let found = {
                                let g = ist.read().await;
                                g.active_tab().vault.as_ref().and_then(|v| v.iter().find(|e| e.domain == d).map(|e| (e.user.clone(), e.pass.clone(), e.nonce.clone(), e.salt.clone())))
                            };
                            
                            if let Some((user, pass, nonce, salt)) = found {
                                if let Some(dec) = vault::decrypt(&pass, &nonce, &salt, &master) {
                                    if let Ok(d) = serde_json::to_string(&dec) {
                                        ipx.send_event(Ev::Js(format!(
                                            "document.getElementById('v-pass').value={};vRes('🔓 User: {}');",
                                            d, user.replace('\'', "")
                                        ))).ok();
                                    }
                                } else {
                                    ipx.send_event(Ev::Js("vRes('❌ Wrong password');".into())).ok();
                                }
                            } else {
                                ipx.send_event(Ev::Js("vRes('❌ Not found');".into())).ok();
                            }
                        } else if act == "gen" {
                            let gpw = vault::generate(16);
                            if let Ok(g) = serde_json::to_string(&gpw) {
                                ipx.send_event(Ev::Js(format!(
                                    "document.getElementById('v-pass').value={};vRes('🎲 Generated');",
                                    g
                                ))).ok();
                            }
                        }
                    },
                    "new-tab" => {
                        if let Some(m) = d.as_str() {
                            let mode = match m {
                                "incognito" => state::TabMode::Incognito,
                                "tor" => state::TabMode::Tor,
                                _ => state::TabMode::Normal,
                            };
                            let mut g = ist.write().await;
                            let idx = g.new_tab(mode);
                            ipx.send_event(Ev::NewTab(idx)).ok();
                            update_tabs(&g, &ipx);
                        }
                    }
                    "close-tab" => if let Some(i) = d.as_u64() {
                        let mut g = ist.write().await;
                        if g.close_tab(i as usize) {
                            ipx.send_event(Ev::CloseTab(i as usize)).ok();
                            update_tabs(&g, &ipx);
                        }
                    },
                    "switch-tab" => if let Some(i) = d.as_u64() {
                        let mut g = ist.write().await;
                        g.switch_tab(i as usize);
                        update_tabs(&g, &ipx);
                        if let Some(url) = g.active_tab().current() {
                            drop(g);
                            load_url(url, ist.clone(), &ipx, false).await;
                        }
                    },
                    "unfreeze-tab" => if let Some(i) = d.as_u64() {
                        let url = {
                            let mut g = ist.write().await;
                            let tab = &mut g.tabs[i as usize];
                            tab.frozen = false;
                            tab.last_active = Instant::now();
                            tab.url.clone()
                        };
                        let mut g = ist.write().await;
                        g.switch_tab(i as usize);
                        update_tabs(&g, &ipx);
                        drop(g);
                        load_url(url, ist.clone(), &ipx, false).await;
                    },
                    "password-detected" => {
                        let (url, user, pass) = (d["url"].as_str().unwrap_or(""), d["username"].as_str().unwrap_or(""), d["password"].as_str().unwrap_or(""));
                        if !url.is_empty() && ist.read().await.global_cfg.auto_save_passwords {
                            let url_js = serde_json::to_string(url).unwrap_or_default();
                            let user_js = serde_json::to_string(user).unwrap_or_default();
                            let pass_js = serde_json::to_string(pass).unwrap_or_default();
                            
                            ipx.send_event(Ev::Js(format!(
                                r#"if(window.showPasswordSuggestion)window.showPasswordSuggestion({{"url":{},"username":{},"password":{}}})"#,
                                url_js, user_js, pass_js
                            ))).ok();
                        }
                    },
                    "save-password" => {
                        let (url, user, pass) = (d["url"].as_str().unwrap_or(""), d["username"].as_str().unwrap_or(""), d["password"].as_str().unwrap_or(""));
                        if !url.is_empty() && !user.is_empty() && !pass.is_empty() {
                            let domain = {
                                if let Ok(parsed) = Url::parse(url) {
                                    parsed.domain().map(|d| d.to_string()).unwrap_or_else(|| url.to_string())
                                } else {
                                    url.split('/').next().unwrap_or(url).to_string()
                                }
                            };
                            
                            let mut g = ist.write().await;
                            if let Some(vault) = &mut g.active_tab_mut().vault {
                                if let Some(entry) = vault.iter_mut().find(|e| e.domain == domain && e.user == user) {
                                    entry.pass = pass.into();
                                    entry.last_used = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                                } else if let Some((enc, nonce, salt)) = vault::encrypt(pass, "") {
                                    vault.push(state::VaultEntry {
                                        domain: domain.clone(), 
                                        user: user.into(), 
                                        pass: enc, 
                                        nonce, 
                                        salt,
                                        created: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                                        last_used: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                                    });
                                }
                                vault::save(vault);
                            }
                        }
                    },
                    "fill-password" => {
                        let (user, pass) = (d["username"].as_str().unwrap_or(""), d["password"].as_str().unwrap_or(""));
                        if !user.is_empty() && !pass.is_empty() {
                            let user_js = serde_json::to_string(user).unwrap_or_default();
                            let pass_js = serde_json::to_string(pass).unwrap_or_default();
                            
                            ipx.send_event(Ev::Js(format!(
                                r#"if(window.nexusFillPassword)window.nexusFillPassword({},{});"#,
                                user_js, pass_js
                            ))).ok();
                        }
                    },
                    "sync-now" => {
                        let mut g = ist.write().await;
                        let (c, f, e) = (
                            g.sync.import_from_browser("chrome"),
                            g.sync.import_from_browser("firefox"),
                            g.sync.import_from_browser("edge"),
                        );
                        let active_tab = g.active_tab;
                        {
                            let tab = &mut g.tabs[active_tab];
                            g.sync.sync_to_active_tab(tab);
                        }
                        if let Some(vault) = &g.tabs[active_tab].vault { vault::save(vault); }
                        ipx.send_event(Ev::Js(format!(
                            r#"lg('Sync: Chrome({}), Firefox({}), Edge({})','info')"#,
                            c, f, e
                        ))).ok();
                    },
                    "ext-list" => {
                        let extensions = extensions::load_all_extensions().await;
                        let ext_data = extensions.iter().map(|e| json!({
                            "id": e.id,
                            "name": e.manifest.name,
                            "version": e.manifest.version,
                            "description": e.manifest.description,
                            "enabled": e.enabled
                        })).collect::<Vec<_>>();
                        
                        ipx.send_event(Ev::Js(format!(
                            r#"if(window.postMessage) window.postMessage(JSON.stringify({{a:'ext-list-response',p:{}}}));"#,
                            serde_json::to_string(&ext_data).unwrap_or_default()
                        ))).ok();
                    },
                    "ext-toggle" => {
                        if let (Some(id), Some(enabled)) = (d["id"].as_str(), d["enabled"].as_bool()) {
                            let ext_dir = std::path::Path::new("nexus_extensions").join(id);
                            if ext_dir.exists() {
                                if enabled {
                                    std::fs::remove_file(ext_dir.join("DISABLED")).ok();
                                } else {
                                    std::fs::write(ext_dir.join("DISABLED"), "").ok();
                                }
                                ipx.send_event(Ev::Js(format!(
                                    r#"if(window.postMessage) window.postMessage(JSON.stringify({{a:'ext-toggle-response',p:{{id:'{}',enabled:{}}}}}));"#,
                                    id, enabled
                                ))).ok();
                            }
                        }
                    },
                    "ext-msg" => {
                        ipx.send_event(Ev::Js(format!("lg('Extension message: {}','info');", d))).ok();
                    },
                    _ => {}
                }
            });
        });
    
    let wv = wb.build().unwrap();
    
    extensions::api::setup_extension_apis(&wv);
    autoconfig::update_ui(&px);
    
    let ext_list = rt.block_on(async { extensions::load_all_extensions().await });
    let ext_data = ext_list.iter().map(|e| json!({
        "id": e.id,
        "name": e.manifest.name,
        "version": e.manifest.version,
        "description": e.manifest.description,
        "enabled": e.enabled
    })).collect::<Vec<_>>();
    
    px.send_event(Ev::Js(format!(
        r#"if(window.postMessage) window.postMessage(JSON.stringify({{a:'ext-list-response',p:{}}}));"#,
        serde_json::to_string(&ext_data).unwrap_or_default()
    ))).ok();
    
    update_tabs(&st.blocking_read(), &px);
    
    let (mut js_queue, mut last_flush) = (Vec::new(), Instant::now());
    el.run(move |ev, _, cf| {
        *cf = ControlFlow::Wait;
        match ev {
            Event::NewEvents(StartCause::Init) => {
                px.send_event(Ev::Js("lg('NEXUS CORE INITIALIZED','info')".into())).ok();
                px.send_event(Ev::Js("lg('AES-256-GCM Vault Ready','info')".into())).ok();
                px.send_event(Ev::Js("lg('Extensions System Ready','info')".into())).ok();
                px.send_event(Ev::Js("lg('WARP/Tor auto-detection complete','info')".into())).ok();
                
                handle_for_loop.spawn({
                    let (st, px) = (st.clone(), px.clone());
                    async move { load_url("nexus://home".into(), st, &px, false).await; }
                });
            }
            Event::UserEvent(Ev::Js(j)) => {
                js_queue.push(j);
                if js_queue.len() >= 5 || last_flush.elapsed() > Duration::from_millis(16) {
                    let _ = wv.evaluate_script(&js_queue.drain(..).collect::<Vec<_>>().join(""));
                    last_flush = Instant::now();
                }
            }
            Event::UserEvent(Ev::NewTab(_)) | Event::UserEvent(Ev::CloseTab(_)) => {
                update_tabs(&st.blocking_read(), &px);
                if let Event::UserEvent(Ev::NewTab(_)) = ev {
                    handle_for_loop.spawn({
                        let (st, px) = (st.clone(), px.clone());
                        async move { load_url("nexus://home".into(), st, &px, false).await; }
                    });
                }
            }
            Event::WindowEvent { event: wry::application::event::WindowEvent::CloseRequested, .. } => *cf = ControlFlow::Exit,
            _ => {}
        }
    });
}
