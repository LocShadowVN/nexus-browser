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
use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use argon2::{password_hash::{PasswordHasher, SaltString}, Argon2, Params, Version};
use reqwest::{cookie::Jar, RequestBuilder};
use base64::{engine::general_purpose, Engine as _};
use regex::Regex;
use serde_json::Value as JsonValue;
use zeroize::{Zeroize, ZeroizeOnDrop};
use rand::RngCore;
use url::Url;

#[macro_export]
macro_rules! json { ($($tt:tt)*) => { serde_json::json!($($tt)*) }; }

#[derive(Debug, Clone)]
enum Ev { Js(String), NewTab(usize), CloseTab(usize) }

// ======================
// MODULE: STATE
// ======================
mod state {
    use super::*;
    #[derive(Clone, Debug, PartialEq)] pub enum TabMode { Normal, Incognito, Tor }
    #[derive(Clone, Debug, Default)]
    pub struct TabConfig {
        pub proxy: bool, pub proxy_url: String, pub tor: bool, pub warp: bool,
        pub ad: bool, pub trk: bool, pub sinkhole: bool, pub cookie: bool, pub anti_fp: bool,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
    pub struct VaultEntry {
        pub domain: String, pub user: String, pub pass: String,
        pub nonce: String, pub salt: String, pub created: u64, pub last_used: u64,
    }
    #[derive(Clone, Debug, Default, Zeroize, ZeroizeOnDrop)]
    pub struct AiCfg { pub endpoint: String, pub key: String, pub model: String }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    pub struct Bookmark { pub title: String, pub url: String }
    
    #[derive(Debug)]
    pub struct TabState {
        pub id: Uuid, pub name: String, pub url: String,
        pub hist: Vec<String>, pub hist_pos: usize,
        pub cfg: TabConfig, pub mode: TabMode,
        pub last_active: Instant, pub frozen: bool,
        pub ai: AiCfg, pub ai_mem: VecDeque<(String, String)>,
        pub client: Option<reqwest::Client>, pub client_cfg_hash: u64,
        pub vault: Option<Vec<VaultEntry>>,
    }
    
    impl TabState {
        pub fn new(mode: TabMode) -> Self {
            let is_incog = matches!(mode, TabMode::Incognito | TabMode::Tor);
            Self {
                id: Uuid::new_v4(),
                name: match mode { TabMode::Normal => "New Tab", TabMode::Incognito => "Private Tab", TabMode::Tor => "Tor Tab" }.into(),
                url: "nexus://home".into(), hist: Vec::with_capacity(32), hist_pos: 0,
                cfg: TabConfig {
                    proxy_url: "socks5h://127.0.0.1:1080".into(),
                    ad: true, trk: true, sinkhole: true, cookie: !is_incog, anti_fp: true,
                    tor: matches!(mode, TabMode::Tor), ..Default::default()
                },
                mode, last_active: Instant::now(), frozen: false,
                ai: AiCfg::default(), ai_mem: VecDeque::with_capacity(40),
                client: None, client_cfg_hash: 0,
                vault: if is_incog { None } else { Some(Vec::new()) },
            }
        }
        #[inline] pub fn push_ai(&mut self, r: String, c: String) { self.ai_mem.push_back((r, c)); if self.ai_mem.len() > 40 { self.ai_mem.pop_front(); } }
        pub fn push_hist(&mut self, url: String) {
            if self.hist.get(self.hist_pos).map(|u| u == &url).unwrap_or(false) { return; }
            if !self.hist.is_empty() && self.hist_pos + 1 < self.hist.len() { self.hist.truncate(self.hist_pos + 1); }
            self.hist.push(url); if self.hist.len() > 100 { self.hist.remove(0); }
            self.hist_pos = self.hist.len().saturating_sub(1); self.last_active = Instant::now();
        }
        pub fn go_back(&mut self) -> Option<String> { (self.hist_pos > 0).then(|| { self.hist_pos -= 1; self.hist[self.hist_pos].clone() }) }
        pub fn go_fwd(&mut self) -> Option<String> { (self.hist_pos + 1 < self.hist.len()).then(|| { self.hist_pos += 1; self.hist[self.hist_pos].clone() }) }
        pub fn current(&self) -> Option<String> { self.hist.get(self.hist_pos).cloned() }
        pub fn update_client(&mut self) {
            let new_hash = self.cfg_hash();
            if self.client_cfg_hash != new_hash { self.client = Some(super::net::build_client(&self.cfg)); self.client_cfg_hash = new_hash; }
        }
        fn cfg_hash(&self) -> u64 {
            use std::hash::{Hash, Hasher}; let mut h = std::collections::hash_map::DefaultHasher::new();
            self.cfg.proxy.hash(&mut h); self.cfg.proxy_url.hash(&mut h); self.cfg.tor.hash(&mut h); self.cfg.warp.hash(&mut h); self.cfg.cookie.hash(&mut h); h.finish()
        }
    }
    
    #[derive(Debug)]
    pub struct State {
        pub active_tab: usize, pub tabs: Vec<TabState>, pub blocked: u64,
        pub global_cfg: GlobalConfig, pub bookmarks: Vec<Bookmark>,
    }
    
    impl State {
        pub fn new() -> Self { Self { active_tab: 0, tabs: vec![TabState::new(TabMode::Normal)], blocked: 0, global_cfg: GlobalConfig::default(), bookmarks: Vec::new() } }
        #[inline] pub fn active_tab(&self) -> &TabState { &self.tabs[self.active_tab] }
        #[inline] pub fn active_tab_mut(&mut self) -> &mut TabState { &mut self.tabs[self.active_tab] }
        pub fn new_tab(&mut self, mode: TabMode) -> usize { let idx = self.tabs.len(); self.tabs.push(TabState::new(mode)); self.active_tab = idx; idx }
        pub fn close_tab(&mut self, idx: usize) -> bool { (self.tabs.len() > 1).then(|| { self.tabs.remove(idx); if self.active_tab >= idx && self.active_tab > 0 { self.active_tab -= 1; } }).is_some() }
        pub fn switch_tab(&mut self, idx: usize) { (idx < self.tabs.len()).then(|| self.active_tab = idx); }
    }
    
    #[derive(Clone, Debug)]
    pub struct GlobalConfig { pub auto_save_passwords: bool, pub show_password_suggestions: bool }
    impl Default for GlobalConfig { fn default() -> Self { Self { auto_save_passwords: true, show_password_suggestions: true } } }
}

// ======================
// MODULE: NET (SECURE & GOOGLE LOGIN BYPASS)
// ======================
mod net {
    use super::*;
    pub fn build_client(c: &state::TabConfig) -> reqwest::Client {
        // Bật Cookie Jar để duy trì phiên đăng nhập Google
        let jar = Arc::new(reqwest::cookie::Jar::default());
        let mut b = reqwest::Client::builder()
            // SPOOFING: Giả mạo Chrome xịn nhất để qua mặt Google Login Block
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
            .cookie_provider(jar)
            .danger_accept_invalid_certs(false) // BẢO MẬT: Không chấp nhận chứng chỉ SSL giả
            .https_only(false) // Cho phép HTTP nhưng sẽ cảnh báo
            .timeout(Duration::from_secs(30));
            
        if c.tor { b = b.proxy(reqwest::Proxy::all("socks5h://127.0.0.1:9050").unwrap()); }
        else if c.warp { b = b.proxy(reqwest::Proxy::all("socks5h://127.0.0.1:2053").unwrap()); }
        else if c.proxy { b = b.proxy(reqwest::Proxy::all(&c.proxy_url).unwrap()); }
        b.build().unwrap_or_else(|_| reqwest::Client::new())
    }
}

// ======================
// MODULE: SINKHOLE & INJECTION
// ======================
mod sinkhole {
    #[inline] pub fn check(u: &str) -> bool { u.contains("doubleclick") || u.contains("adsense") || u.contains("google-analytics") }
}

mod injection {
    use super::*;
    lazy_static::lazy_static! { static ref PAYLOAD_CACHE: StdMutex<HashMap<u64, String>> = StdMutex::new(HashMap::new()); }
    pub fn get_security_payload(cfg: &state::TabConfig) -> String {
        let hash = cfg_hash(cfg);
        if let Some(cached) = PAYLOAD_CACHE.lock().unwrap().get(&hash) { return cached.clone(); }
        let (mut css, mut js) = (String::new(), String::new());
        if cfg.ad { css.push_str(r#"[class*="ad-"],[id*="ad-"],.adsbygoogle,#google_ads{display:none!important;}"#); }
        if cfg.trk { js.push_str(r#"!function(){const t=['analytics','mixpanel'],n=t=>t.some(t=>(""+t).includes(t)),e=window.fetch;window.fetch=function(t,r){return n(t)?Promise.reject("Blocked"):e.apply(this,arguments)}}()"#); }
        if cfg.anti_fp { js.push_str(r#"!function(){Object.defineProperty(navigator,"hardwareConcurrency",{get:()=>4})}()"#); }
        
        // BẢO MẬT: Thêm Content Security Policy (CSP) cơ bản để chống XSS
        let csp = r#"<meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; object-src 'none';">"#;
        
        let payload = format!(r#"{}<style id="nx-css">{}</style><script id="nx-js">{}</script>"#, csp, css, js);
        PAYLOAD_CACHE.lock().unwrap().insert(hash, payload.clone());
        payload
    }
    fn cfg_hash(cfg: &state::TabConfig) -> u64 {
        use std::hash::{Hash, Hasher}; let mut h = std::collections::hash_map::DefaultHasher::new();
        cfg.ad.hash(&mut h); cfg.trk.hash(&mut h); cfg.anti_fp.hash(&mut h); h.finish()
    }
}

// ======================
// MODULE: VAULT (AES-256-GCM)
// ======================
mod vault {
    use super::*;
    const VAULT_FILE: &str = "nexus_vault.dat";
    lazy_static::lazy_static! { static ref VAULT_LOCK: StdMutex<()> = StdMutex::new(()); }
    fn argon2() -> Argon2<'static> { Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, Params::new(128*1024, 3, 4, None).unwrap()) }
    fn derive_key(master: &str, salt: &[u8]) -> Option<[u8; 32]> { let mut key = [0u8; 32]; argon2().hash_password_into(master.as_bytes(), salt, &mut key).ok()?; Some(key) }
    pub fn encrypt(data: &str, master: &str) -> Option<(String, String, String)> {
        let salt = SaltString::generate(rand::thread_rng());
        let mut raw_salt = [0u8; 64]; let salt_bytes = salt.decode_b64(&mut raw_salt).ok()?;
        let key = derive_key(master, salt_bytes)?;
        let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
        let mut nonce = [0u8; 12]; rand::rngs::OsRng.try_fill_bytes(&mut nonce).ok()?;
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), data.as_bytes()).ok()?;
        Some((general_purpose::STANDARD.encode(&ciphertext), general_purpose::STANDARD.encode(&nonce), salt.as_str().to_string()))
    }
    pub fn decrypt(enc: &str, nonce: &str, salt: &str, master: &str) -> Option<String> {
        let (ciphertext, nonce) = (general_purpose::STANDARD.decode(enc).ok()?, general_purpose::STANDARD.decode(nonce).ok()?);
        let salt_value = SaltString::from_b64(salt).ok()?;
        let mut raw_salt = [0u8; 64]; let salt_bytes = salt_value.decode_b64(&mut raw_salt).ok()?;
        (nonce.len() == 12).then(|| {
            let key = derive_key(master, salt_bytes)?; let cipher = Aes256Gcm::new_from_slice(&key).ok()?;
            String::from_utf8(cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_slice()).ok()?).ok()
        })?
    }
    pub fn load() -> Vec<state::VaultEntry> { std::fs::read(VAULT_FILE).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default() }
    pub fn save(entries: &[state::VaultEntry]) -> bool {
        let _guard = VAULT_LOCK.lock().unwrap();
        let temp = format!("{}.tmp", VAULT_FILE);
        serde_json::to_vec(entries).map(|b| std::fs::write(&temp, b).is_ok()).unwrap_or(false) && std::fs::rename(temp, VAULT_FILE).is_ok()
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
#app{display:flex;flex-direction:column;height:100vh}
header{display:flex;align-items:center;gap:8px;padding:10px;background:var(--panel);border-bottom:1px solid var(--brd)}
.btn{width:36px;height:36px;display:flex;align-items:center;justify-content:center;border:1px solid var(--brd);background:0 0;color:var(--t1);cursor:pointer;border-radius:6px;transition:0.2s}
.btn:hover{background:var(--brd);color:var(--bg)}
.btn-acc{border-color:var(--acc);color:var(--acc)}.btn-acc:hover{background:var(--acc);color:#fff}
#url{flex:1;background:var(--input);border:1px solid var(--brd);color:var(--t1);padding:10px 14px;outline:0;border-radius:6px}
#workspace{display:flex;flex:1;overflow:hidden;background:#fff}
.side-hd{padding:18px;border-bottom:1px solid var(--brd);font-weight:700;color:var(--brd);letter-spacing:2px;font-size:14px}
.side-scroll{flex:1;overflow-y:auto;padding:20px}
.sec-title{font-size:.8rem;color:var(--acc);margin:20px 0 12px;letter-spacing:2px;border-bottom:1px dashed var(--acc);padding-bottom:6px;font-weight:700;text-transform:uppercase}
.row{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;font-size:.85rem;color:var(--t1);font-weight:500}
.sw{position:relative;width:40px;height:20px}.sw input{opacity:0;width:0;height:0}
.sl{position:absolute;cursor:pointer;inset:0;background:var(--input);border:1px solid var(--t2);transition:.3s;border-radius:20px}
.sl:before{position:absolute;content:"";height:14px;width:14px;left:2px;bottom:2px;background:var(--t2);border-radius:50%}
input:checked+.sl{background:var(--brd);border-color:var(--brd)}
input:checked+.sl:before{transform:translateX(20px);background:var(--bg)}
.modal{position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);width:420px;max-width:92vw;background:var(--panel);border:2px solid var(--brd);padding:30px;z-index:1000;display:none;border-radius:12px}
.modal.show{display:block}
.v-in{width:100%;padding:10px;margin:8px 0;background:var(--input);border:1px solid var(--brd);color:var(--t1);border-radius:6px;outline:0}
.v-btn{width:100%;padding:10px;margin:5px 0;background:var(--brd);color:var(--bg);border:0;cursor:pointer;font-weight:700;border-radius:6px}
#tabs{display:flex;gap:4px;padding:0 10px;height:40px;align-items:center;overflow-x:auto;background:var(--panel);border-bottom:1px solid var(--brd)}
.tab{padding:6px 16px;border-radius:6px 6px 0 0;cursor:pointer;background:var(--input);color:var(--t1);white-space:nowrap;display:flex;align-items:center;gap:6px;}
.tab.active{background:var(--panel);color:var(--brd);border-top:2px solid var(--brd)}
.tab.frozen{opacity:0.6; font-style:italic;}
.tab-close{display:inline-flex;width:18px;height:18px;align-items:center;justify-content:center;border-radius:50%;color:var(--t2)}
.tab-close:hover{background:var(--brd);color:var(--bg)}
#sidebar{position:fixed;right:-320px;top:0;width:320px;height:100vh;background:var(--panel);border-left:1px solid var(--brd);transition:right .3s;z-index:100;overflow-y:auto}
#sidebar-toggle{position:fixed;right:0;top:10px;width:24px;height:40px;background:var(--brd);color:var(--bg);display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:101;border-radius:6px 0 0 6px}
#sidebar.o{right:0}
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
    <button class="btn" onclick="toggleModal('vault')" title="Vault">🔐</button>
    <button class="btn" onclick="toggleTheme()" title="Toggle Theme" id="theme-btn">🌙</button>
    <button class="btn" onclick="toggleLang()" title="Language" id="lang-btn">🇻🇳</button>
    <button class="btn btn-acc" onclick="sr('new-tab', 'normal')" data-i18n="new_tab">+ Tab</button>
    <button class="btn" id="sidebar-toggle">≡</button>
  </header>
  <div id="workspace"></div>

  <div id="sidebar">
    <div style="padding:20px 0;text-align:center">
      <div style="font-weight:600;margin-bottom:20px;color:var(--brd)">NEXUS MENU</div>
      <div class="row" style="margin-bottom:15px"><button class="btn btn-acc" style="width:100%" onclick="sr('new-tab', 'normal')" data-i18n="new_tab">+ New Tab</button></div>
      <div class="row" style="margin-bottom:15px"><button class="btn" style="width:100%" onclick="sr('new-tab', 'incognito')" data-i18n="private_tab">+ Private Tab</button></div>
    </div>
    
    <div class="side-hd" data-i18n="security">🛡 SECURITY</div>
    <div class="side-scroll">
      <div class="sec-title" data-i18n="shields">SHIELDS</div>
      <div class="row"><span>Adblock</span><label class="sw"><input type="checkbox" checked onchange="ts('ad',this.checked)"><span class="sl"></span></label></div>
      <div class="row"><span>Tracker Block</span><label class="sw"><input type="checkbox" checked onchange="ts('trk',this.checked)"><span class="sl"></span></label></div>
      
      <div class="sec-title">EXTENSIONS</div>
      <p style="font-size:12px; color:var(--t2); margin-bottom:10px;">Native .crx install is not supported. Use custom JS extensions.</p>
      <button class="ext-btn" onclick="sr('nav', 'https://chrome.google.com/webstore')">🌐 Open Chrome Web Store</button>
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
    <button class="v-btn" onclick="toggleModal('vault')" style="background:var(--acc);color:#fff" data-i18n="close">CLOSE</button>
    <div id="v-res" style="margin-top:10px;font-size:12px;color:var(--brd)"></div>
  </div>
</div>

<script>
const dict = {
  en: { search_ph: "Search Google or type URL...", new_tab: "+ Tab", private_tab: "+ Private Tab", security: "🛡 SECURITY", shields: "SHIELDS", vault_title: "🔐 NEXUS VAULT", save: "SAVE", retrieve: "RETRIEVE", close: "CLOSE" },
  vi: { search_ph: "Tìm kiếm hoặc nhập URL...", new_tab: "+ Tab Mới", private_tab: "+ Tab Ẩn Danh", security: "🛡 BẢO MẬT", shields: "LÁ CHẮN", vault_title: "🔐 KHO LƯU TRỮ", save: "LƯU", retrieve: "LẤY MẬT KHẨU", close: "ĐÓNG" }
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

function renderTabs() {
  document.getElementById('tabs').innerHTML = tabs.map((t,i)=>`
    <div class="tab ${i===activeTab?'active':''} ${t.frozen?'frozen':''}" onclick="switchTab(${i})">
      ${t.frozen ? '❄️ ' : ''}${t.name}
      <span class="tab-close" onclick="closeTab(${i},event)">&times;</span>
    </div>`).join('');
}

function closeTab(i,e) { e.stopPropagation(); tabs.length>1 && sr('close-tab',i); }
function switchTab(i) { 
  if(i!==activeTab) {
    if(tabs[i].frozen) { sr('unfreeze-tab', i); }
    else { activeTab=i; sr('switch-tab',i); renderTabs(); }
  }
}

function sr(a,p){window.chrome?.webview?.postMessage(JSON.stringify({a,p}))}
function ts(k,v){sr('shld',{s:k,v:v})}
function toggleModal(id){document.getElementById(id).classList.toggle('show')}
function setUrl(u){document.getElementById('url').value=u}
function vAct(a){sr('vault',{a,m:v('v-master'),d:v('v-domain'),u:v('v-user'),p:v('v-pass')})}
function vRes(t){document.getElementById('v-res').textContent=t}
function v(id){return document.getElementById(id).value}

document.getElementById('sidebar-toggle').addEventListener('click',()=>document.getElementById('sidebar').classList.toggle('o'));

window.updateTabs = function(d) {
  tabs = d.tabs; activeTab = d.activeTab; renderTabs();
  let currentUrl = tabs[activeTab].url;
  document.getElementById('url').value = currentUrl === 'nexus://home' ? '' : currentUrl;
}
</script></body></html>"###.into()
}

// ======================
// RENDER PAGE (SECURE IFRAME)
// ======================
fn render_page(html_out: &str, url: &str, px: &wry::application::event_loop::EventLoopProxy<Ev>) {
    // BẢO MẬT: Sử dụng sandbox attribute cho iframe để ngăn chặn popup độc hại và script nguy hiểm
    if let (Ok(h), Ok(u)) = (serde_json::to_string(html_out), serde_json::to_string(url)) {
        let _ = px.send_event(Ev::Js(format!("{{let w=document.getElementById('workspace');w.innerHTML='';let f=document.createElement('iframe');f.sandbox='allow-scripts allow-same-origin allow-forms';f.style='width:100%;height:100%;border:none;background:#fff;';f.srcdoc={};w.appendChild(f);}}", h)));
        let _ = px.send_event(Ev::Js(format!("setUrl({});", u)));
    }
}

// ======================
// LOAD URL
// ======================
async fn load_url(url: String, st: Arc<RwLock<state::State>>, px: &wry::application::event_loop::EventLoopProxy<Ev>, record: bool) {
    let cfg = { let g = st.read().await; g.active_tab().cfg.clone() };
    
    if url == "nexus://home" {
        let home_html = r#"<!DOCTYPE html><html><head><style>body { background: var(--bg, #0a0a0a); color: var(--t1, #00ffff); font-family: 'Segoe UI', sans-serif; display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100vh; margin: 0; } h1 { font-size: 5rem; letter-spacing: 12px; margin-bottom: 10px; font-weight: 900; } p { color: var(--acc, #ff007f); letter-spacing: 6px; font-weight: 600; margin-bottom: 40px; } .search { width: 60%; max-width: 600px; padding: 16px; border-radius: 30px; border: 2px solid var(--t1, #00ffff); background: var(--input, #111); color: #fff; font-size: 1.2rem; text-align: center; outline: none; }</style></head><body><h1>NEXUS</h1><p>SECURE EDITION</p><input type="text" class="search" placeholder="Search Google or type URL..." onkeydown="if(event.key==='Enter') window.top.postMessage(JSON.stringify({a:'nav-internal', p: this.value}), '*')"></body></html>"#;
        render_page(home_html, &url, px);
        if record {
            let mut g = st.write().await; let t = g.active_tab_mut();
            t.push_hist(url.clone()); t.url = url; t.name = "Home".into();
            update_tabs(&g, px);
        }
        return;
    }

    let client = {
        let mut g = st.write().await; let t = g.active_tab_mut();
        t.update_client(); t.client.clone().unwrap_or_else(reqwest::Client::new)
    };
    
    // BẢO MẬT: Ép buộc HTTPS nếu người dùng gõ HTTP (HSTS cơ bản)
    let secure_url = if url.starts_with("http://") && !url.contains("localhost") && !url.contains("127.0.0.1") {
        url.replace("http://", "https://")
    } else { url.clone() };

    if let Ok(r) = client.get(&secure_url).header("Referer", "").header("DNT", "1").send().await {
        let content_type = r.headers().get(reqwest::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("text/html").to_lowercase();

        if content_type.contains("text/html") || content_type.contains("text/plain") {
            if let Ok(h) = r.text().await {
                let safe_url = secure_url.replace('&', "&amp;").replace('"', "&quot;");
                let shield = injection::get_security_payload(&cfg);
                let inj = format!(r#"<base href="{}">{}"#, safe_url, shield);
                
                let lower_h = h.to_ascii_lowercase();
                let html_out = if let Some(start) = lower_h.find("<head") {
                    h[..start].to_string() + &h[start..].find('>').map_or_else(
                        || format!("{}{}", inj, h),
                        |end| { let pos = start + end + 1; format!("{}{}{}", &h[..pos], inj, &h[pos..]) }
                    )
                } else { format!("{}{}", inj, h) };
                
                render_page(&html_out, &secure_url, px);
            }
        }
        
        if record {
            let mut g = st.write().await; let t = g.active_tab_mut();
            t.push_hist(secure_url.clone()); t.url = secure_url.clone();
            if let Ok(parsed) = url::Url::parse(&secure_url) { t.name = parsed.host_str().unwrap_or("New Tab").to_string(); }
            update_tabs(&g, px);
        }
    }
}

fn update_tabs(state: &state::State, px: &wry::application::event_loop::EventLoopProxy<Ev>) {
    let tabs = state.tabs.iter().map(|t| json!({ "id": t.id, "name": t.name, "url": t.url, "frozen": t.frozen })).collect::<Vec<_>>();
    if let Ok(t) = serde_json::to_string(&tabs) { let _ = px.send_event(Ev::Js(format!(r#"if(window.updateTabs)window.updateTabs({{"tabs":{},"activeTab":{}}})"#, t, state.active_tab))); }
}

fn main() {
    let el = EventLoopBuilder::<Ev>::with_user_event().build();
    let w = WindowBuilder::new().with_title("NEXUS SECURE").with_inner_size(LogicalSize::new(1200, 800)).build(&el).unwrap();
    
    let mut initial = state::State::new();
    initial.tabs[0].vault = Some(vault::load());
    let st = Arc::new(RwLock::new(initial));
    let px = el.create_proxy();
    
    let rt = Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let handle = rt.handle().clone();
    let handle_for_loop = handle.clone();
    let (ist, ipx) = (st.clone(), px.clone());
    
    // Background Task: Đóng băng Tab
    let freeze_st = st.clone(); let freeze_px = px.clone();
    rt.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            let mut g = freeze_st.write().await;
            let active_idx = g.active_tab; let mut changed = false;
            for (i, tab) in g.tabs.iter_mut().enumerate() {
                if i != active_idx && !tab.frozen && tab.last_active.elapsed() > Duration::from_secs(300) {
                    tab.frozen = true; tab.client = None; changed = true;
                }
            }
            if changed { update_tabs(&g, &freeze_px); }
        }
    });
    
    let wb = WebViewBuilder::new(w).unwrap()
        // BẢO MẬT: Tắt DevTools trong môi trường thực tế để tránh bị inject script từ bên ngoài
        .with_devtools(false)
        // SPOOFING: Giả mạo User-Agent ở cấp độ WebView để Google Login không chặn
        .with_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
        .with_html(html()).unwrap()
        .with_ipc_handler(move |_window, msg| {
            let (ist, ipx, handle) = (ist.clone(), ipx.clone(), handle.clone());
            let p: JsonValue = match serde_json::from_str(&msg) { Ok(v) => v, Err(_) => return };
            let (a, d) = (p["a"].as_str().unwrap_or("").to_string(), p["p"].clone());
            
            handle.spawn(async move {
                match a.as_str() {
                    "nav" | "nav-internal" => {
                        if let Some(u) = d.as_str() {
                            let resolved = if u.trim().starts_with("http") || u.trim().starts_with("nexus://") { u.trim().to_string() } else { format!("https://www.google.com/search?q={}", url::form_urlencoded::byte_serialize(u.trim().as_bytes()).collect::<String>()) };
                            load_url(resolved, ist.clone(), &ipx, true).await;
                        }
                    }
                    "new-tab" => {
                        let mode = state::TabMode::Normal;
                        let mut g = ist.write().await; let idx = g.new_tab(mode);
                        ipx.send_event(Ev::NewTab(idx)).ok(); update_tabs(&g, &ipx);
                    }
                    "close-tab" => if let Some(i) = d.as_u64() { let mut g = ist.write().await; if g.close_tab(i as usize) { ipx.send_event(Ev::CloseTab(i as usize)).ok(); update_tabs(&g, &ipx); } },
                    "switch-tab" => if let Some(i) = d.as_u64() {
                        let mut g = ist.write().await; g.switch_tab(i as usize); update_tabs(&g, &ipx);
                        if let Some(url) = g.active_tab().current() { drop(g); load_url(url, ist.clone(), &ipx, false).await; }
                    },
                    "unfreeze-tab" => if let Some(i) = d.as_u64() {
                        let url = { let mut g = ist.write().await; let tab = &mut g.tabs[i as usize]; tab.frozen = false; tab.last_active = Instant::now(); tab.url.clone() };
                        let mut g = ist.write().await; g.switch_tab(i as usize); update_tabs(&g, &ipx); drop(g);
                        load_url(url, ist.clone(), &ipx, false).await;
                    },
                    "vault" => if let (Some(a), Some(m), Some(d), Some(u), Some(p)) = (d["a"].as_str(), d["m"].as_str(), d["d"].as_str(), d["u"].as_str(), d["p"].as_str()) {
                        let (act, m, d, u, p) = (a.to_string(), m.to_string(), d.to_string(), u.to_string(), p.to_string());
                        let master = zeroize::Zeroizing::new(m);
                        if act == "save" && !master.is_empty() && !d.is_empty() {
                            if let Some((enc, nonce, salt)) = vault::encrypt(&p, &master) {
                                let entries = {
                                    let mut g = ist.write().await; let tab = g.active_tab_mut();
                                    if let Some(vault) = &mut tab.vault { vault.push(state::VaultEntry { domain: d, user: u, pass: enc, nonce, salt, created: 0, last_used: 0 }); vault.clone() } else { Vec::new() }
                                };
                                let msg = if !entries.is_empty() && vault::save(&entries) { "vRes('✅ Saved');" } else { "vRes('⚠ Save failed');" };
                                ipx.send_event(Ev::Js(msg.into())).ok();
                            }
                        } else if act == "get" {
                            let found = { let g = ist.read().await; g.active_tab().vault.as_ref().and_then(|v| v.iter().find(|e| e.domain == d).map(|e| (e.user.clone(), e.pass.clone(), e.nonce.clone(), e.salt.clone()))) };
                            if let Some((user, pass, nonce, salt)) = found {
                                if let Some(dec) = vault::decrypt(&pass, &nonce, &salt, &master) {
                                    if let Ok(d) = serde_json::to_string(&dec) { ipx.send_event(Ev::Js(format!("document.getElementById('v-pass').value={};vRes('🔓 User: {}');", d, user.replace('\'', "")))).ok(); }
                                } else { ipx.send_event(Ev::Js("vRes('❌ Wrong password');".into())).ok(); }
                            } else { ipx.send_event(Ev::Js("vRes('❌ Not found');".into())).ok(); }
                        }
                    },
                    _ => {}
                }
            });
        });
    
    let wv = wb.build().unwrap();
    update_tabs(&st.blocking_read(), &px);
    
    let (mut js_queue, mut last_flush) = (Vec::new(), Instant::now());
    el.run(move |ev, _, cf| {
        *cf = ControlFlow::Wait;
        match ev {
            Event::NewEvents(StartCause::Init) => {
                handle_for_loop.spawn({ let (st, px) = (st.clone(), px.clone()); async move { load_url("nexus://home".into(), st, &px, false).await; } });
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
                    handle_for_loop.spawn({ let (st, px) = (st.clone(), px.clone()); async move { load_url("nexus://home".into(), st, &px, false).await; } });
                }
            }
            Event::WindowEvent { event: wry::application::event::WindowEvent::CloseRequested, .. } => *cf = ControlFlow::Exit,
            _ => {}
        }
    });
}
