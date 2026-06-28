#![allow(dead_code, unused_imports, unused_variables, unreachable_code)]

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex as StdMutex,
    },
    time::{Duration, Instant},
};
use tao::{
    dpi::LogicalSize,
    event::{Event, StartCause},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use tokio::{
    runtime::Builder,
    sync::{RwLock, Semaphore, Mutex as TokioMutex},
    task::JoinSet,
};
use uuid::Uuid;
use wry::WebViewBuilder;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params, Version,
};
use base64::engine::general_purpose;
use regex::Regex;
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
    
    #[derive(Debug)]
    pub struct TabState {
        pub id: Uuid, pub name: String, pub url: String,
        pub hist: Vec<String>, pub hist_pos: usize,
        pub cfg: TabConfig, pub mode: TabMode,
        pub last_active: Instant,
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
// MODULE: NET
// ======================
mod net {
    use super::*;
    
    pub fn build_client(c: &state::TabConfig) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Nexus/1.0")
            .cookie_store(!c.cookie)
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
// MODULE: INJECTION
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
        
        if cfg.ad { css.push_str(r#"[class*="ad-"],[id*="ad-"],.adsbygoogle,#google_ads,iframe[src*="doubleclick"],[class*="sponsor"],[id*="banner"],.ad-container,.adsbox{display:none!important;height:0!important;width:0!important;overflow:hidden!important}"#); }
        if cfg.trk { js.push_str(r#"!function(){const t=['analytics','segment.io','mixpanel','hotjar','facebook.com/tr','trackcmp'],n=t=>t.some(t=>(""+t).includes(t)),o=()=>{try{window.top&&window.top.nexusBlocked&&window.top.nexusBlocked()}catch(t){}},e=window.fetch;window.fetch=function(t,r){return n(t)?(o(),Promise.reject("Blocked")):e.apply(this,arguments)};const i=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(t,n){return n(t)?(o(),void throw new Error("Blocked")):i.apply(this,arguments)},navigator.sendBeacon=()=>!1}()"#); }
        if cfg.cookie { js.push_str(r#"!function(){const t=Object.getOwnPropertyDescriptor(Document.prototype,"cookie");t&&(Object.defineProperty(document,"cookie",{set(n){/(_ga|track|fbp)/.test(n)||t.set.call(this,n)},get(){return t.get.call(this)}}))}()"#); }
        if cfg.anti_fp { js.push_str(r#"!function(){HTMLCanvasElement.prototype.toDataURL=()=>"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==";const t=WebGLRenderingContext.prototype.getParameter;WebGLRenderingContext.prototype.getParameter=function(n){return 37445===n?"Nexus":37446===n?"Nexus":t.apply(this,arguments)},Object.defineProperty(navigator,"hardwareConcurrency",{get:()=>4}),Object.defineProperty(navigator,"deviceMemory",{get:()=>4})}()"#); }
        
        js.push_str(r#"!function(){const t=()=>{document.querySelectorAll("form").forEach(n=>{if(!n.dataset.nexusMonitored){let o=!1,e=!1,r=null,s=null;n.querySelectorAll("input").forEach(t=>{"password"===t.type&&(e=!0,s=t),/text|email/.test(t.type)||/user|email/i.test(t.name)&&(o=!0,r=t)}),o&&e&&(n.dataset.nexusMonitored="true",n.addEventListener("submit",function(t){t.preventDefault(),window.chrome&&window.chrome.webview&&window.chrome.webview.postMessage(JSON.stringify({a:"password-detected",p:{url:window.location.href,username:r?r.value:"",password:s?s.value:""}})),setTimeout(()=>n.submit(),100)}))}});const n=new MutationObserver(t);n.observe(document.body,{childList:!0,subtree:!0}),t()},o=()=>{const t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";return Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>t[n%t.length]).join("")};window.nexusGeneratePassword=o,window.nexusFillPassword=(t,n)=>{let o=null,e=null;for(const n of document.querySelectorAll("input"))"password"===n.type&&!e&&(e=n),/text|email/.test(n.type)||/user|email/i.test(n.name)&&(o=n);o&&(o.value=t),e&&(e.value=n)}}()"#);
        
        let payload = format!(r#"<style id="nexus-shield-css">{}</style><script id="nexus-shield-js">{}</script>"#, css, js);
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
    
    const VAULT_FILE: &str = "nexus_vault.dat";
    lazy_static::lazy_static! {
        static ref VAULT_LOCK: TokioMutex<()> = TokioMutex::new(());
    }
    
    fn argon2() -> Argon2<'static> {
        let m_cost = if num_cpus::get() > 4 { 192 * 1024 } else { 128 * 1024 };
        Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, 
            Params::new(m_cost, 3, std::cmp::min(4, num_cpus::get()), None).unwrap())
    }
    
    fn derive_key(master: &str, salt: &[u8]) -> Option<[u8; 32]> {
        let mut key = [0u8; 32];
        argon2().hash_password_into(master.as_bytes(), salt, &mut key).ok()?;
        Some(key)
    }
    
    pub fn encrypt(data: &str, master: &str) -> Option<(String, String, String)> {
        let salt = SaltString::generate(rand::thread_rng());
        let key = derive_key(master, salt.as_bytes())?;
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), data.as_bytes()).ok()?;
        
        Some((
            general_purpose::STANDARD.encode(&ciphertext),
            general_purpose::STANDARD.encode(&nonce),
            general_purpose::STANDARD.encode(salt.as_bytes()),
        ))
    }
    
    pub fn decrypt(enc: &str, nonce: &str, salt: &str, master: &str) -> Option<String> {
        let (ciphertext, nonce, salt) = (
            general_purpose::STANDARD.decode(enc).ok()?,
            general_purpose::STANDARD.decode(nonce).ok()?,
            general_purpose::STANDARD.decode(salt).ok()?,
        );
        
        (nonce.len() == 12 && salt.len() == 16).then(|| {
            let key = derive_key(master, &salt)?;
            let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
            String::from_utf8(cipher.decrypt(Nonce::from_slice(&nonce), &ciphertext).ok()?).ok()
        })?
    }
    
    pub fn generate(len: usize) -> String {
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
            .chars()
            .cycle()
            .take(len)
            .collect()
    }
    
    pub fn load() -> Vec<state::VaultEntry> {
        std::fs::read(VAULT_FILE).ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }
    
    pub fn save(entries: &[state::VaultEntry]) -> bool {
        let _guard = VAULT_LOCK.blocking_lock();
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
    
    pub fn import_from_chrome() -> Result<Vec<state::VaultEntry>, String> { 
        Ok(Vec::new()) 
    }
    
    pub fn import_from_firefox() -> Result<Vec<state::VaultEntry>, String> { 
        Ok(Vec::new()) 
    }
    
    pub fn import_from_edge() -> Result<Vec<state::VaultEntry>, String> { 
        Ok(Vec::new()) 
    }
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
        
        let reply = client
            .post(&ai.endpoint)
            .bearer_auth(&ai.key)
            .json(&body)
            .send()
            .await
            .ok()
            .and_then(|r| r.json::<JsonValue>().ok())
            .and_then(|v| v["choices"][0]["message"]["content"].as_str().map(String::from))
            .unwrap_or_else(|| "⚠ Phản hồi AI không hợp lệ.".into());
        
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
        
        if len == 0 || !accept_ranges {
            if let Ok(r) = client.get(&url).send().await {
                if let Ok(b) = r.bytes().await {
                    let _ = tokio::fs::write(url.split('/').last().unwrap_or("nxdl.bin"), &b).await;
                }
            }
            return;
        }
        
        let (chunk, f_name) = ((len + PARTS as u64 - 1) / PARTS as u64, 
            url.split('/').last().filter(|s| !s.is_empty()).unwrap_or("nxdl.bin").to_string());
        
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
                if client.get(&url).header("Range", format!("bytes={}-{}", s, e))
                    .send().await
                    .and_then(|r| r.bytes_stream().map(|b| b.unwrap()).collect::<Vec<_>>())
                    .is_ok()
                {
                    let mut f = file.lock().await;
                    f.seek(SeekFrom::Start(s)).await.ok();
                    f.write_all(&b).await.ok();
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
        if t.starts_with("http") { t.into() }
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
                enabled: true,
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
                .flat_map(|cs| cs.css.as_ref().map(|css| css.iter()).unwrap_or_else(|| [].iter()))
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
            
            bg_script.and_then(|path| {
                tokio::runtime::Handle::current().block_on(async {
                    fs::read_to_string(&path).await.ok()
                })
            })
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
            let mut entries = entries.filter_map(|entry| async {
                entry.ok().and_then(|e| {
                    if e.file_type().ok()?.is_dir() {
                        Some(e.path())
                    } else {
                        None
                    }
                })
            });
            
            while let Some(path) = entries.next().await {
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
        
        pub fn setup_extension_apis(webview: &wry::WebView) {
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
                                    if (responseCallback) {
                                        const listener = function(event) {
                                            try {
                                                const data = JSON.parse(event.data);
                                                if (data.a === 'ext-response') {
                                                    responseCallback(data.p);
                                                    window.removeEventListener('message', listener);
                                                }
                                            } catch (e) {}
                                        };
                                        window.addEventListener('message', listener);
                                    }
                                }
                            }
                        },
                        storage: {
                            local: {
                                get: function(keys, callback) {
                                    if (window.chrome && window.chrome.webview) {
                                        window.chrome.webview.postMessage(JSON.stringify({
                                            a: 'ext-storage-get',
                                            p: keys
                                        }));
                                        const listener = function(event) {
                                            try {
                                                const data = JSON.parse(event.data);
                                                if (data.a === 'ext-storage-response') {
                                                    callback(data.p);
                                                    window.removeEventListener('message', listener);
                                                }
                                            } catch (e) {}
                                        };
                                        window.addEventListener('message', listener);
                                    }
                                },
                                set: function(items, callback) {
                                    if (window.chrome && window.chrome.webview) {
                                        window.chrome.webview.postMessage(JSON.stringify({
                                            a: 'ext-storage-set',
                                            p: items
                                        }));
                                        if (callback) callback();
                                    }
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
    
    pub fn update_ui(px: &tao::event_loop::EventLoopProxy<Ev>) {
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
// MAIN HTML
// ======================
fn html() -> String {
    r###"<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:'Segoe UI',sans-serif;background:var(--bg);color:var(--t1);height:100vh;display:flex;flex-direction:column}
:root{--bg:#000;--panel:#0a0a0a;--input:#111;--brd:#00ffff;--acc:#ff007f;--t1:#f8fafc;--t2:#94a3b8}
body.light{--bg:#fff;--panel:#f8fafc;--input:#f1f5f9;--brd:#005f73;--acc:#b7094c;--t1:#0f172a;--t2:#475569}
body.incognito{--brd:#9d4edd;--acc:#9d4edd}body.tor{--brd:#0d6efd;--acc:#0d6efd}
#app{display:flex;flex-direction:column;height:100vh}
header{display:flex;align-items:center;gap:8px;padding:10px;background:var(--panel);border-bottom:1px solid var(--brd)}
.btn{width:36px;height:36px;display:flex;align-items:center;justify-content:center;border:1px solid var(--brd);background:0 0;color:var(--t1);cursor:pointer;border-radius:6px}
.btn:hover{background:var(--brd);color:var(--bg)}
.btn-acc{border-color:var(--acc);color:var(--acc)}.btn-acc:hover{background:var(--acc);color:#fff}
#url{flex:1;background:var(--input);border:1px solid var(--brd);color:var(--t1);padding:10px 14px;outline:0;border-radius:6px}
#workspace{display:flex;flex:1;overflow:hidden}
main{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:20px}
.logo{font-size:5rem;font-weight:900;color:var(--brd);letter-spacing:12px}
.sub{color:var(--acc);font-size:1rem;letter-spacing:6px;margin-bottom:40px;font-weight:600}
#search{width:60%;max-width:600px;padding:16px;font-size:1.2rem;text-align:center;border:2px solid var(--brd);color:var(--t1);border-radius:30px}
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
#dp.o{right:0}.le{font-size:12px;margin-bottom:5px}.le.error{color:var(--acc)}.le.info{color:var(--brd)}
.modal{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:420px;max-width:92vw;background:var(--panel);border:2px solid var(--brd);padding:30px;z-index:1000;display:none;border-radius:12px}
.modal.show{display:block}
.v-in{width:100%;padding:10px;margin:8px 0;background:var(--input);border:1px solid var(--brd);color:var(--t1);border-radius:6px;outline:0}
.v-btn{width:100%;padding:10px;margin:5px 0;background:var(--brd);color:var(--bg);border:0;cursor:pointer;font-weight:700;border-radius:6px}
.v-btn:hover{background:var(--acc);color:#fff}
#ai-log{margin-top:12px;max-height:200px;overflow-y:auto;font-size:13px;text-align:left}
.ai-msg{margin:6px 0;padding:8px;border-radius:6px;background:var(--input)}
.ai-msg.u{border-left:3px solid var(--acc)}.ai-msg.a{border-left:3px solid var(--brd)}
#tabs{display:flex;gap:4px;padding:0 10px;height:40px;align-items:center;overflow-x:auto;background:var(--panel);border-bottom:1px solid var(--brd)}
.tab{padding:6px 16px;border-radius:6px 6px 0 0;cursor:pointer;background:var(--input);color:var(--t1);white-space:nowrap;position:relative}
.tab.active{background:var(--panel);color:var(--brd);border-top:2px solid var(--brd)}
.tab-close{display:inline-flex;width:18px;height:18px;align-items:center;justify-content:center;border-radius:50%;margin-left:8px;color:var(--t2)}
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
</style></head><body>
<div id="app">
  <div id="tabs"></div>
  <header>
    <button class="btn" onclick="sr('back')">⟵</button><button class="btn" onclick="sr('fwd')">⟶</button><button class="btn" onclick="sr('ref')">⟳</button>
    <input type="text" id="url" placeholder="nexus://home" onkeydown="if(event.key==='Enter')sr('nav',this.value)">
    <button class="btn btn-acc" onclick="sr('new-tab', 'normal')">+ Tab</button>
    <button class="btn" id="sidebar-toggle">≡</button>
  </header>
  <div id="workspace">
    <main>
      <div class="logo">NEXUS</div>
      <div class="sub">ELITE RUST // AES-256 ENCRYPTED</div>
      <input type="text" id="search" placeholder="Search Google or type URL..." onkeydown="if(event.key==='Enter')sr('nav',this.value)">
    </main>
  </div>
  <div id="dp"><h2 style="color:var(--acc);border-bottom:1px solid var(--acc)">DEV CONSOLE</h2><div id="dl"></div></div>

  <div id="sidebar">
    <div style="padding:20px 0;text-align:center">
      <div style="font-size:1.5rem;margin-bottom:10px">≡</div>
      <div style="font-weight:600;margin-bottom:20px;color:var(--brd)">NEXUS MENU</div>
      <div class="row" style="margin-bottom:15px"><button class="btn btn-acc" style="width:100%" onclick="sr('new-tab', 'normal')">+ New Tab</button></div>
      <div class="row" style="margin-bottom:15px"><button class="btn" style="width:100%" onclick="sr('new-tab', 'incognito')">+ Private Tab</button></div>
      <div class="row" style="margin-bottom:15px"><button class="btn" style="width:100%" onclick="sr('new-tab', 'tor')">+ Tor Tab</button></div>
    </div>
    
    <div class="side-hd">🛡 SECURITY</div>
    <div class="side-scroll">
      <div class="sec-title">CONNECTION</div>
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
      
      <div class="sec-title">SHIELDS</div>
      <div class="row"><span>Adblock</span><label class="sw"><input type="checkbox" checked onchange="ts('ad',this.checked)"><span class="sl"></span></label></div>
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
      
      <div class="sec-title">STATS</div>
      <div class="stat" id="tc">0 Blocked</div>
    </div>
  </div>

  <div id="vault" class="modal">
    <h2 style="color:var(--brd);margin-bottom:15px">🔐 NEXUS VAULT</h2>
    <input type="password" id="v-master" class="v-in" placeholder="Master Password">
    <input type="text" id="v-domain" class="v-in" placeholder="Domain">
    <input type="text" id="v-user" class="v-in" placeholder="Username">
    <input type="password" id="v-pass" class="v-in" placeholder="Password">
    <button class="v-btn" onclick="vAct('save')">SAVE</button>
    <button class="v-btn" onclick="vAct('get')">RETRIEVE</button>
    <button class="v-btn" onclick="vAct('gen')">GENERATE</button>
    <button class="v-btn" onclick="toggleModal('vault')" style="background:var(--acc);color:#fff">CLOSE</button>
    <div id="v-res" style="margin-top:10px;font-size:12px;color:var(--brd)"></div>
  </div>

  <div id="aip" class="modal">
    <h2 style="color:var(--brd);margin-bottom:15px">🤖 AI (BYO Key)</h2>
    <input type="text" id="ai-endpoint" class="v-in" placeholder="Endpoint">
    <input type="password" id="ai-key" class="v-in" placeholder="API Key">
    <input type="text" id="ai-model" class="v-in" placeholder="Model">
    <button class="v-btn" onclick="aiCfg()">SAVE</button>
    <textarea id="ai-prompt" class="v-in" rows="3" placeholder="Hỏi AI..."></textarea>
    <button class="v-btn" onclick="aiAsk()">ASK</button>
    <button class="v-btn" onclick="toggleModal('aip')" style="background:var(--acc);color:#fff">CLOSE</button>
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
let tabs = [{id:'home',name:'Home',url:'nexus://home',mode:'normal'}];
let activeTab = 0;
let extensions = [];

function initTabs() { renderTabs(); }
function renderTabs() {
  document.getElementById('tabs').innerHTML = 
    tabs.map((t,i)=>`<div class="tab ${i===activeTab?'active':''}" onclick="switchTab(${i})">
      ${t.name}<span class="tab-close" onclick="closeTab(${i},event)">&times;</span>
    </div>`).join('');
}

function newTab(m) { sr('new-tab',m); }
function closeTab(i,e) { e.stopPropagation(); tabs.length>1 && sr('close-tab',i); }
function switchTab(i) { i!==activeTab && (activeTab=i, sr('switch-tab',i), renderTabs()); }

function sr(a,p){window.chrome?.webview?.postMessage(JSON.stringify({a,p}))}
function ts(k,v){sr('shld',{s:k,v:v})}
function uc(c){document.getElementById('tc').textContent=c+' Blocked'}
window.nexusBlocked=()=>sr('inc');
function toggleModal(id){document.getElementById(id).classList.toggle('show')}
function setUrl(u){document.getElementById('url').value=u}
function vAct(a){sr('vault',{a,m:v('v-master'),d:v('v-domain'),u:v('v-user'),p:v('v-pass')})}
function vRes(t){document.getElementById('v-res').textContent=t}
function aiCfg(){sr('ai_cfg',{e:v('ai-endpoint'),k:v('ai-key'),m:v('ai-model')})}
function aiAsk(){const q=v('ai-prompt');q&&(addAi('u',q),sr('ai',q),document.getElementById('ai-prompt').value='')}
function addAi(r,t){const l=document.getElementById('ai-log');l.innerHTML+=`<div class="ai-msg ${r}">${r==='u'?'You':'AI'}: ${t}</div>`;l.scrollTop=l.scrollHeight}
function lg(m,t){const l=document.getElementById('dl');l.innerHTML=`<div class="le ${t||'info'}">[${new Date().toTimeString().split(' ')[0]}] ${m}</div>`+l.innerHTML}
function at(m){m==='light'?document.body.classList.add('light'):document.body.classList.remove('light')}
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
  extensions::api::setup_extension_apis();
  
  // Yêu cầu danh sách extensions
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
      // Cập nhật local state
      const ext = extensions.find(e => e.id === data.p.id);
      if (ext) ext.enabled = data.p.enabled;
      renderExtensions(extensions);
    }
  } catch (e) {
    console.error('Error processing message:', e);
  }
});

function updateTabs(d) {
  tabs = d.tabs;
  activeTab = d.activeTab;
  renderTabs();
  document.getElementById('url').value = tabs[activeTab].url === 'nexus://home' ? 'nexus://home' : tabs[activeTab].url;
}
</script></body></html>"###.into()
}

// ======================
// RENDER PAGE
// ======================
fn render_page(html_out: &str, url: &str, px: &tao::event_loop::EventLoopProxy<Ev>) {
    if let (Ok(h), Ok(u)) = (serde_json::to_string(html_out), serde_json::to_string(url)) {
        let _ = px.send_event(Ev::Js(format!(
            "{{f=document.createElement('iframe');f.style='width:100%;height:100%;border:none';f.srcdoc={};m=document.querySelector('main');m.innerHTML='';m.appendChild(f)}}",
            h
        )));
        let _ = px.send_event(Ev::Js(format!("setUrl({});", u)));
    }
}

// ======================
// LOAD URL
// ======================
async fn load_url(url: String, st: Arc<RwLock<state::State>>, px: &tao::event_loop::EventLoopProxy<Ev>, record: bool) {
    let cfg = { let g = st.read().await; g.active_tab().cfg.clone() };
    
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
    
    if let Ok(r) = client.get(&url).header("Referer", "").header("DNT", "1").send().await {
        if let Ok(h) = r.text().await {
            let shield = injection::get_security_payload(&cfg);
            let inj = format!(r#"<base href="{}">{}"#, url, shield);
            
            let html_out = if let Some(start) = h.to_lowercase().find("<head") {
                h[..start].to_string() + &h[start..].find('>').map_or_else(
                    || format!("{}{}", inj, h),
                    |end| {
                        let pos = start + end + 1;
                        format!("{}{}{}", &h[..pos], inj, &h[pos..])
                    }
                )
            } else { format!("{}{}", inj, h) };
            
            // Thêm extensions injection
            let extensions = extensions::load_all_extensions().await;
            if let (Some(js), Some(css)) = extensions::get_injections_for_url(&url, &extensions).await {
                let ext_inj = format!(r#"<style id="nexus-ext-css">{}</style><script id="nexus-ext-js">{}</script>"#, css, js);
                
                // Chèn vào trước </body>
                if let Some(body_end) = html_out.rfind("</body>") {
                    let mut new_html = String::with_capacity(html_out.len() + ext_inj.len());
                    new_html.push_str(&html_out[..body_end]);
                    new_html.push_str(&ext_inj);
                    new_html.push_str(&html_out[body_end..]);
                    render_page(&new_html, &url, px);
                } else {
                    render_page(&format!("{}{}", html_out, ext_inj), &url, px);
                }
            } else {
                render_page(&html_out, &url, px);
            }
            
            if record {
                let mut g = st.write().await;
                let t = g.active_tab_mut();
                t.push_hist(url.clone());
                t.url = url;
                update_tabs(&g, px);
            }
        }
    }
}

// ======================
// UPDATE TABS
// ======================
fn update_tabs(state: &state::State, px: &tao::event_loop::EventLoopProxy<Ev>) {
    let tabs = state.tabs.iter().map(|t| json!({
        "id": t.id, "name": t.name, "url": t.url,
        "mode": match t.mode { state::TabMode::Normal => "normal", state::TabMode::Incognito => "incognito", state::TabMode::Tor => "tor" }
    })).collect::<Vec<_>>();
    
    if let Ok(t) = serde_json::to_string(&tabs) {
        let _ = px.send_event(Ev::Js(format!(r#"if(updateTabs)updateTabs({{"tabs":{},"activeTab":{}}})"#, t, state.active_tab)));
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
        .with_title("NEXUS")
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
    let (ist, ipx) = (st.clone(), px.clone());
    
    let mut wb = WebViewBuilder::new()
        .with_html(html())
        .with_back_forward_navigation_gestures(false)
        .with_zoom_hotkeys(false)
        .with_ipc_handler(move |req| {
            let (msg, ist, ipx, handle) = (req.into_body(), ist.clone(), ipx.clone(), handle.clone());
            let p: JsonValue = match serde_json::from_str(&msg) { Ok(v) => v, Err(_) => return };
            let (a, d) = (p["a"].as_str().unwrap_or(""), p["p"].clone());
            
            handle.spawn(async move {
                match a {
                    "nav" => d.as_str().map(|u| search::resolve(u)).map(|u| load_url(u, ist.clone(), &ipx, true)),
                    "back" => { let g = &mut ist.write().await; g.active_tab_mut().go_back().map(|u| load_url(u, ist.clone(), &ipx, false)); },
                    "fwd" => { let g = &mut ist.write().await; g.active_tab_mut().go_fwd().map(|u| load_url(u, ist.clone(), &ipx, false)); },
                    "ref" => { let g = &ist.read().await; g.active_tab().current().map(|u| load_url(u, ist.clone(), &ipx, false)); },
                    "inc" => { let c = { let mut g = ist.write().await; g.blocked += 1; g.blocked }; ipx.send_event(Ev::Js(format!("uc({});", c))).ok(); },
                    "shld" => if let (Some(s), Some(v)) = (d["s"].as_str(), d["v"].as_bool()) {
                        let mut g = ist.write().await;
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
                            "auto-save" => g.global_cfg.auto_save_passwords = v,
                            "pass-suggest" => g.global_cfg.show_password_suggestions = v,
                            "sync-chrome" => g.sync.config.chrome = v,
                            "sync-firefox" => g.sync.config.firefox = v,
                            "sync-edge" => g.sync.config.edge = v,
                            _ => {}
                        }
                        tab.update_client();
                    },
                    "ai_cfg" => if let (Some(e), Some(k), Some(m)) = (d["e"].as_str(), d["k"].as_str(), d["m"].as_str()) {
                        let mut g = ist.write().await;
                        let tab = g.active_tab_mut();
                        tab.ai.endpoint = e.into(); tab.ai.key = k.into(); tab.ai.model = m.into();
                        ipx.send_event(Ev::Js("lg('AI config saved','info');".into())).ok();
                    },
                    "ai" => d.as_str().map(|p| ai::ask(p.into(), ist.clone()).await).map(|r| {
                        if let Ok(j) = serde_json::to_string(&r) {
                            ipx.send_event(Ev::Js(format!("addAi('a',{});", j))).ok();
                        }
                    }),
                    "vault" => if let (Some(a), Some(m), Some(d), Some(u), Some(p)) = 
                        (d["a"].as_str(), d["m"].as_str(), d["d"].as_str(), d["u"].as_str(), d["p"].as_str()) 
                    {
                        let (act, m, d, u, p) = (a.to_string(), m.to_string(), d.to_string(), u.to_string(), p.to_string());
                        let mut master = zeroize::Zeroizing::new(m);
                        
                        if act == "save" && !master.is_empty() && !d.is_empty() {
                            if let Some((enc, nonce, salt)) = vault::encrypt(p, &master) {
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
                    "new-tab" => d.as_str().map(|m| {
                        let mode = match m {
                            "incognito" => state::TabMode::Incognito,
                            "tor" => state::TabMode::Tor,
                            _ => state::TabMode::Normal,
                        };
                        let mut g = ist.write().await;
                        let idx = g.new_tab(mode);
                        ipx.send_event(Ev::NewTab(idx)).ok();
                        update_tabs(&g, &ipx);
                    }),
                    "close-tab" => d.as_u64().map(|i| {
                        let mut g = ist.write().await;
                        if g.close_tab(i as usize) {
                            ipx.send_event(Ev::CloseTab(i as usize)).ok();
                            update_tabs(&g, &ipx);
                        }
                    }),
                    "switch-tab" => d.as_u64().map(|i| {
                        let mut g = ist.write().await;
                        g.switch_tab(i as usize);
                        update_tabs(&g, &ipx);
                        if let Some(url) = g.active_tab().current() {
                            load_url(url, ist.clone(), &ipx, false).await;
                        }
                    }),
                    "password-detected" => {
                        let (url, user, pass) = (d["url"].as_str().unwrap_or(""), d["username"].as_str().unwrap_or(""), d["password"].as_str().unwrap_or(""));
                        if !url.is_empty() && ist.read().await.global_cfg.auto_save_passwords {
                            ipx.send_event(Ev::Js(format!(
                                r#"if(showPasswordSuggestion)showPasswordSuggestion({{"url":"{}","username":"{}","password":"{}"}})"#,
                                url, user, pass
                            ))).ok();
                        }
                    },
                    "save-password" => {
                        let (url, user, pass) = (d["url"].as_str().unwrap_or(""), d["username"].as_str().unwrap_or(""), d["password"].as_str().unwrap_or(""));
                        if !url.is_empty() && !user.is_empty() && !pass.is_empty() {
                            let mut g = ist.write().await;
                            if let Some(vault) = &mut g.active_tab_mut().vault {
                                if let Some(entry) = vault.iter_mut().find(|e| e.domain == url && e.user == user) {
                                    entry.pass = pass.into();
                                    entry.last_used = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
                                } else if let Some((enc, nonce, salt)) = vault::encrypt(pass, "") {
                                    vault.push(state::VaultEntry {
                                        domain: url.into(), user: user.into(), pass: enc, nonce, salt,
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
                            ipx.send_event(Ev::Js(format!(
                                r#"if(nexusFillPassword)nexusFillPassword("{}","{}")"#,
                                user, pass
                            ))).ok();
                        }
                    },
                    "sync-now" => {
                        let mut g = ist.write().await;
                        let (c, f, e) = (g.sync.import_from_browser("chrome"), g.sync.import_from_browser("firefox"), g.sync.import_from_browser("edge"));
                        g.sync.sync_to_active_tab(g.active_tab_mut());
                        if let Some(vault) = &g.active_tab().vault { vault::save(vault); }
                        ipx.send_event(Ev::Js(format!(
                            r#"lg('Sync: Chrome({}), Firefox({}), Edge({})','info')"#,
                            c, f, e
                        ))).ok();
                    },
                    "ext-list" => {
                        let extensions = extensions::load_all_extensions().await;
                        let ext_data = extensions.iter().map(|e| json!({
                            "id": e.id,
                            "name": e.name,
                            "version": e.version,
                            "description": e.description,
                            "enabled": e.enabled
                        })).collect::<Vec<_>>();
                        
                        ipx.send_event(Ev::Js(format!(
                            r#"if(window.postMessage) window.postMessage(JSON.stringify({{a:'ext-list-response',p:{}}}));"#,
                            serde_json::to_string(&ext_data).unwrap_or_default()
                        ))).ok();
                    },
                    "ext-toggle" => {
                        if let (Some(id), Some(enabled)) = (d["id"].as_str(), d["enabled"].as_bool()) {
                            // Cập nhật trạng thái extension
                            let mut g = ist.write().await;
                            let ext_dir = std::path::Path::new("nexus_extensions").join(id);
                            if ext_dir.exists() {
                                // Tạo file trạng thái
                                if enabled {
                                    std::fs::remove_file(ext_dir.join("DISABLED")).ok();
                                } else {
                                    std::fs::write(ext_dir.join("DISABLED"), "").ok();
                                }
                                
                                // Phản hồi cho UI
                                ipx.send_event(Ev::Js(format!(
                                    r#"if(window.postMessage) window.postMessage(JSON.stringify({{a:'ext-toggle-response',p:{{id:'{}',enabled:{}}}}}));"#,
                                    id, enabled
                                ))).ok();
                            }
                        }
                    },
                    _ => {}
                }
            });
        });
    
    let wv = wb.build(&w).unwrap();
    
    // Tự động phát hiện WARP/Tor và cập nhật UI
    autoconfig::update_ui(&px);
    
    // Tải extensions
    let ext_list = extensions::load_all_extensions().await;
    let ext_data = ext_list.iter().map(|e| json!({
        "id": e.id,
        "name": e.name,
        "version": e.version,
        "description": e.description,
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
            }
            Event::UserEvent(Ev::Js(j)) => {
                js_queue.push(j);
                if js_queue.len() >= 5 || last_flush.elapsed() > Duration::from_millis(16) {
                    let _ = wv.evaluate_script(&js_queue.drain(..).collect::<Vec<_>>().join(""));
                    last_flush = Instant::now();
                }
            }
            Event::UserEvent(Ev::NewTab(idx)) | Event::UserEvent(Ev::CloseTab(idx)) => {
                update_tabs(&st.blocking_read(), &px);
                if let Event::UserEvent(Ev::NewTab(_)) = ev {
                    tokio::spawn({
                        let (st, px) = (st.clone(), px.clone());
                        async move { load_url("nexus://home".into(), st, &px, false).await; }
                    });
                }
            }
            Event::WindowEvent { event: tao::event::WindowEvent::CloseRequested, .. } => *cf = ControlFlow::Exit,
            _ => {}
        }
    });
}

// ======================
// HELPERS
// ======================
#[macro_export]
macro_rules! json {
    ($($tt:tt)*) => { serde_json::json!($($tt)*) };
}
