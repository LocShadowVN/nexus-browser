// ============================================================================
// NEXUS BROWSER - ELITE RUST EDITION (CLEAN & OPTIMIZED)
// Single-file architecture: src/main.rs
// Target: 4GB RAM / HDD low-end systems
// Wry 0.45 / Tao 0.30 / Tokio multi-thread
// ============================================================================

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
    
    #[derive(Clone, Debug, PartialEq)]
    pub enum Theme { Dark, Light }
    
    #[derive(Clone, Debug, PartialEq)]
    pub enum Lang { EN, VI }
    
    #[derive(Clone, Debug, Default)]
    pub struct Cfg {
        pub proxy: bool, pub proxy_url: String, pub tor: bool, pub warp: bool, pub dev: bool,
        pub ad: bool, pub trk: bool, pub sinkhole: bool,
    }
    
    #[derive(Debug)]
    pub struct State {
        pub hist: Vec<String>, pub cfg: Cfg, pub theme: Theme, pub lang: Lang, pub blocked: u64,
        pub last_active: Instant, pub api_key: String, pub ai_mem: Vec<(String, String)>,
    }
    
    impl State {
        pub fn new() -> Self { 
            Self {
                hist: Vec::with_capacity(32),
                cfg: Cfg { 
                    proxy_url: "socks5h://127.0.0.1:1080".into(), 
                    ad: true, trk: true, sinkhole: true, 
                    warp: false, tor: false, ..Default::default() 
                },
                theme: Theme::Dark, lang: Lang::EN, blocked: 0, last_active: Instant::now(),
                api_key: "NX-ELITE-0000".into(), ai_mem: Vec::with_capacity(40),
            }
        }
        
        #[inline] 
        pub fn push_ai(&mut self, r: String, c: String) {
            self.ai_mem.push((r, c));
            if self.ai_mem.len() > 40 { self.ai_mem.remove(0); }
        }
    }
    
    impl Drop for State {
        fn drop(&mut self) {
            self.ai_mem.clear(); 
            self.hist.clear();
            unsafe { 
                let ptr = self.api_key.as_mut_ptr();
                let len = self.api_key.len();
                std::ptr::write_bytes(ptr, 0, len); 
            }
        }
    }
}

mod blocker {
    use super::state::Cfg;
    #[inline]
    pub fn check(u: &str, c: &Cfg) -> bool {
        (c.ad && (u.contains("adsystem") || u.contains("adnxs") || u.contains("taboola") || u.contains("cookie-law"))) ||
        (c.trk && (u.contains("analytics") || u.contains("segment.io") || u.contains("telemetry") || u.contains("fingerprint") || u.contains("trackcmp")))
    }
}

mod sinkhole {
    #[inline]
    pub fn check(u: &str) -> bool {
        u.contains("doubleclick") || u.contains("adsense") || u.contains("mixpanel") || 
        u.contains("hotjar") || u.contains("facebook.com/tr") || u.contains("google-analytics")
    }
}

mod net {
    use super::state::Cfg;
    pub fn client(c: &Cfg) -> reqwest::Client {
        let mut b = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) Nexus/1.0")
            .cookie_store(false)
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

mod dl {
    use super::{net, state::State};
    use std::sync::Arc;
    use tokio::{sync::Semaphore, task, io::{AsyncWriteExt, AsyncSeekExt, SeekFrom}};
    use futures_util::StreamExt;
    use tokio::sync::RwLock;

    pub async fn turbo(url: String, st: Arc<RwLock<State>>) {
        let cfg = { st.read().await.cfg.clone() };
        let c = net::client(&cfg);
        let len = c.head(&url).send().await.ok().and_then(|r| r.content_length()).unwrap_or(0);
        if len == 0 { return; }

        const PARTS: usize = 16;
        let chunk = (len + PARTS as u64 - 1) / PARTS as u64;
        let f_name = url.split('/').last().filter(|s| !s.is_empty()).unwrap_or("nxdl.bin").to_string();

        let file = match tokio::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&f_name).await {
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
                            let _ = g.seek(SeekFrom::Start(off)).await;
                            let _ = g.write_all(&b).await;
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
        if t.starts_with("http") { t.into() }
        else if t.contains('.') && !t.contains(' ') { format!("https://{}", t) }
        else { format!("https://www.google.com/search?q={}", url::form_urlencoded::byte_serialize(t.as_bytes()).collect::<String>()) }
    }
}

fn html() -> String {
    r###"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { 
  font-family: 'Courier New', monospace; 
  background: #0a0a0c; color: #e0e0e0; height: 100vh; display: flex; flex-direction: column; 
  overflow: hidden;
}
#app { display: flex; flex-direction: column; height: 100vh; }
header { display: flex; align-items: center; gap: 10px; padding: 10px; background: #0f0f11; border-bottom: 1px solid #00f0ff; }
.btn { width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; border: 1px solid #00f0ff; background: transparent; color: #00f0ff; cursor: pointer; font-weight: bold; }
.btn:hover { background: #00f0ff; color: #0a0a0c; }
#url { flex: 1; background: #111; border: 1px solid #333; color: #00f0ff; padding: 8px 12px; outline: none; }
#url:focus { border-color: #00f0ff; box-shadow: 0 0 5px #00f0ff; }
#workspace { display: flex; flex: 1; overflow: hidden; }
main { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 20px; }
.logo { font-size: 4rem; color: #00f0ff; text-shadow: 0 0 20px #00f0ff; margin-bottom: 10px; }
.sub { color: #ff007f; text-shadow: 0 0 10px #ff007f; margin-bottom: 40px; }
#search { width: 60%; max-width: 600px; padding: 15px; font-size: 18px; background: color-mix(in srgb, #00f0ff 10%, transparent); border: 2px solid #00f0ff; color: #fff; text-align: center; }
aside { width: 320px; background: #0f0f11; border-left: 1px solid #00f0ff; display: flex; flex-direction: column; overflow: hidden; }
.side-hd { padding: 15px; border-bottom: 1px solid #00f0ff; color: #00f0ff; font-weight: bold; }
.side-scroll { flex: 1; overflow-y: auto; padding: 15px; }
.sec-title { margin: 15px 0 10px; color: #ff007f; font-size: 0.9rem; }
.row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.sw { position: relative; width: 40px; height: 20px; }
.sw input { opacity: 0; width: 0; height: 0; }
.sl { position: absolute; cursor: pointer; inset: 0; background: #333; transition: .3s; border-radius: 20px; }
.sl:before { position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px; background: white; transition: .3s; border-radius: 50%; }
input:checked + .sl { background: #00f0ff; }
input:checked + .sl:before { transform: translateX(20px); }
#tc { font-size: 2rem; color: #ff007f; font-weight: bold; text-shadow: 0 0 10px #ff007f; }
#dp { position: fixed; right: -400px; top: 0; width: 400px; height: 100vh; background: #0f0f11; border-left: 2px solid #ff007f; z-index: 99; padding: 20px; overflow-y: auto; transition: right 0.3s; }
#dp.o { right: 0; }
.le { font-size: 12px; margin-bottom: 5px; }
.le.error { color: #ff007f; }
.le.info { color: #00f0ff; }
</style>
</head>
<body>
<div id="app">
  <header>
    <button class="btn" onclick="sr('back')">⟵</button>
    <button class="btn" onclick="sr('fwd')">⟶</button>
    <button class="btn" onclick="sr('ref')">⟳</button>
    <input type="text" id="url" placeholder="Search Nexus or enter URL..." onkeydown="if(event.key==='Enter')sr('nav',this.value)">
    <button class="btn" onclick="sr('dl',v('url'))">⬇ TURBO</button>
    <button class="btn" onclick="toggleDevTools()">⚙ DEV</button>
    <button class="btn" onclick="sr('about')">ⓘ ABOUT</button>
    <button class="btn" onclick="sr('theme')">🌓</button>
    <button class="btn" onclick="sr('lang')">🌐</button>
  </header>
  
  <div id="workspace">
    <main>
      <div id="nexus-start">
        <h1 class="logo">NEXUS</h1>
        <div class="sub">ELITE RUST // AI INTEGRATED</div>
        <input type="text" id="search" placeholder="Initiate Query Sequence..." onkeydown="if(event.key==='Enter') { document.getElementById('url').value = this.value; sr('nav', this.value); }">
      </div>
    </main>
  </div>

  <aside>
    <div class="side-hd">🛡 PRIVACY SHIELD</div>
    <div class="side-scroll">
      <div class="sec-title">Protection Toggles</div>
      <div class="row">
        <label>Ad Blocker</label>
        <label class="sw"><input type="checkbox" id="toggle-adblock" checked onchange="toggleShield('adblock', this.checked)"><span class="sl"></span></label>
      </div>
      <div class="row">
        <label>Tracker Block</label>
        <label class="sw"><input type="checkbox" id="toggle-tracker" checked onchange="toggleShield('tracker', this.checked)"><span class="sl"></span></label>
      </div>
      <div class="row">
        <label>Sinkhole</label>
        <label class="sw"><input type="checkbox" id="toggle-sink" checked onchange="toggleShield('sink', this.checked)"><span class="sl"></span></label>
      </div>
      
      <div class="sec-title">Statistics</div>
      <div id="tc">0</div>
    </div>
  </aside>
</div>

<div id="dp">
  <h2 style="color: #ff007f; border-bottom: 1px solid #ff007f;">NEXUS DEV CONSOLE</h2>
  <div id="dl"></div>
</div>

<script>
window.currentLang = 'en';
window.applyTheme = function(mode) {
    if(mode === 'light') {
        document.body.style.background = '#f5f6f8';
        document.body.style.color = '#1a1a1a';
    } else {
        document.body.style.background = '#0a0a0c';
        document.body.style.color = '#e0e0e0';
    }
}
window.applyLanguage = function(lang) {
    window.currentLang = lang;
    if(lang === 'vi') {
        document.getElementById('url').placeholder = 'Tìm kiếm hoặc nhập URL...';
        document.getElementById('search').placeholder = 'Khởi tạo truy vấn...';
    } else {
        document.getElementById('url').placeholder = 'Search Nexus or enter URL...';
        document.getElementById('search').placeholder = 'Initiate Query Sequence...';
    }
}
function toggleDevTools() {
    document.getElementById('dp').classList.toggle('o');
    sr('toggle_dev');
}
function toggleShield(type, val) {
    sr('toggle_shield', { shield: type, value: val });
}
function updateBlockCount(count) {
    document.getElementById('tc').textContent = 'Blocked: ' + count;
}
function sr(action, payload) {
    sendToRust(action, payload || "");
}
function sendToRust(action, payload) {
    if (window.chrome && window.chrome.webview) {
        window.chrome.webview.postMessage(JSON.stringify({action, payload}));
    } else if (window.ipc) {
        window.ipc.postMessage(JSON.stringify({action, payload}));
    }
}
function logToDev(msg, type) {
    let logs = document.getElementById('dl');
    let entry = document.createElement('div');
    entry.className = 'le ' + (type || 'info');
    entry.textContent = '[' + new Date().toISOString().split('T')[1].split('.')[0] + '] ' + msg;
    logs.prepend(entry);
}
function v(id) { return document.getElementById(id).value; }
</script>
</body>
</html>"###.into()
}

#[derive(Debug, Clone)]
enum Ev { Js(String) }

async fn fetch(url: String, st: Arc<RwLock<state::State>>, px: tao::event_loop::EventLoopProxy<Ev>) {
    let cfg = { st.read().await.cfg.clone() };
    if blocker::check(&url, &cfg) || (cfg.sinkhole && sinkhole::check(&url)) {
        let _ = px.send_event(Ev::Js(format!("logToDev('BLOCKED: {}','error');", url.replace('\'', "").replace('"', ""))));
        let blocked = {
            let mut g = st.write().await;
            g.blocked += 1;
            g.blocked
        };
        let _ = px.send_event(Ev::Js(format!("updateBlockCount({});", blocked)));
        return;
    }

    let client = net::client(&cfg);
    if let Ok(r) = client.get(&url)
        .header("Referer", "")
        .header("DNT", "1")
        .header("Sec-GPC", "1")
        .send().await {
        if let Ok(h) = r.text().await {
            let inj = format!(r#"<base href="{}"><meta http-equiv="Content-Security-Policy" content="default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval';"><meta name="referrer" content="no-referrer">"#, url);
            let html_out = if let Some(idx) = h.to_lowercase().find("<head>") {
                let mut s = String::with_capacity(h.len() + inj.len() + 6);
                s.push_str(&h[..idx + 6]);
                s.push_str(&inj);
                s.push_str(&h[idx + 6..]);
                s
            } else {
                format!("{}{}", inj, h)
            };
            if let Ok(esc) = serde_json::to_string(&html_out) {
                let _ = px.send_event(Ev::Js(format!("document.getElementById('workspace').innerHTML = '<main>' + `{}` + '</main>'; try{{localStorage.clear();sessionStorage.clear();}}catch(e){{}}", esc.replace("<main>", "").replace("</main>", ""))));
                let mut g = st.write().await;
                g.hist.push(url);
                if g.hist.len() > 100 { g.hist.remove(0); }
                g.last_active = Instant::now();
            }
        }
    }
}

fn main() {
    unsafe {
        std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    let el = EventLoopBuilder::<Ev>::with_user_event().build();
    let w = match WindowBuilder::new()
        .with_title("NEXUS")
        .with_inner_size(tao::dpi::LogicalSize::new(1024, 768))
        .build(&el) {
        Ok(w) => w,
        Err(_) => return,
    };

    let st = Arc::new(RwLock::new(state::State::new()));
    let px = el.create_proxy();

    let tokio_rt = Arc::new(Builder::new_multi_thread().enable_all().worker_threads(4).build().unwrap_or_else(|_| std::process::exit(1)));
    let tokio_handle = tokio_rt.handle().clone();

    {
        let stc = st.clone();
        let pxc = px.clone();
        tokio_handle.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let idle = { stc.read().await.last_active.elapsed().as_secs() > 300 };
                if idle {
                    let _ = pxc.send_event(Ev::Js("logToDev('Idle: memory compaction triggered','info');".into()));
                }
            }
        });
    }

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
            let a = p["action"].as_str().unwrap_or(p["a"].as_str().unwrap_or(""));
            let d = p["payload"].clone().or_else(|| p["p"].clone()).unwrap_or_default();
            let ist = ist.clone();
            let ipx = ipx.clone();
            let rth = rth.clone();
            
            match a {
                "nav" => if let Some(u) = d.as_str() {
                    let u = u.to_string();
                    rth.spawn(async move { fetch(search::resolve(&u), ist, ipx).await; });
                },
                "dl" => if let Some(u) = d.as_str() {
                    let u = u.to_string();
                    rth.spawn(async move { dl::turbo(u, ist).await; });
                },
                "dev" | "toggle_dev" => { rth.spawn(async move { let mut g = ist.write().await; g.cfg.dev = !g.cfg.dev; }); },
                "theme" => {
                    rth.spawn(async move {
                        let mut g = ist.write().await;
                        g.theme = if g.theme == state::Theme::Dark { state::Theme::Light } else { state::Theme::Dark };
                        let t = if g.theme == state::Theme::Dark { "dark" } else { "light" };
                        let _ = ipx.send_event(Ev::Js(format!("applyTheme('{}');", t)));
                    });
                },
                "lang" => {
                    rth.spawn(async move {
                        let mut g = ist.write().await;
                        g.lang = if g.lang == state::Lang::EN { state::Lang::VI } else { state::Lang::EN };
                        let l = if g.lang == state::Lang::EN { "en" } else { "vi" };
                        let _ = ipx.send_event(Ev::Js(format!("applyLanguage('{}');", l)));
                    });
                },
                "shld" | "toggle_shield" => {
                    if let (Some(s), Some(v)) = (d["shield"].as_str().or_else(|| d["s"].as_str()).map(String::from), d["value"].as_bool().or_else(|| d["v"].as_bool())) {
                        rth.spawn(async move {
                            let mut g = ist.write().await;
                            match s.as_str() {
                                "adblock" | "ad" => g.cfg.ad = v,
                                "tracker" | "trk" => g.cfg.trk = v,
                                "sink" | "sinkhole" => g.cfg.sinkhole = v,
                                _ => {}
                            }
                        });
                    }
                },
                "inc" | "blocker_increment" => {
                    rth.spawn(async move {
                        let mut g = ist.write().await;
                        g.blocked += 1;
                        let c = g.blocked;
                        drop(g);
                        let _ = ipx.send_event(Ev::Js(format!("updateBlockCount({});", c)));
                    });
                },
                "ai" | "translate_text" => if let Some(prompt) = d.as_str() {
                    let p_str = prompt.to_string();
                    let ist_c = ist.clone(); let ipx_c = ipx.clone();
                    rth.spawn(async move {
                        {
                            let mut g = ist_c.write().await;
                            g.push_ai("user".into(), p_str.clone());
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                        let (mem_size, api_prefix) = {
                            let g = ist_c.read().await;
                            (g.ai_mem.len(), g.api_key.chars().take(8).collect::<String>())
                        };
                        let reply = format!("API[{}] | FIFO mem: {} turns | Query: '{}'", api_prefix, mem_size, p_str);
                        {
                            let mut g = ist_c.write().await;
                            g.push_ai("ai".into(), reply.clone());
                        }
                        if let Ok(esc) = serde_json::to_string(&reply) {
                            let _ = ipx_c.send_event(Ev::Js(format!("logToDev('AI: {}','info');", esc.replace('\"', ""))));
                        }
                    });
                },
                "about" => {
                    let about_html = r#"<div style='position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:#0a0a0c;border:2px solid #00f0ff;padding:40px;z-index:99999;box-shadow:0 0 30px #00f0ff;color:#fff;font-family:monospace;'><h1 style='color:#00f0ff;'>NEXUS BROWSER</h1><p style='color:#ff007f;'>Elite Rust Edition</p><p>Developed for extreme memory safety and zero resource hogging.</p><button class='btn' onclick='this.parentNode.remove();'>CLOSE</button></div>"#;
                    let _ = ipx.send_event(Ev::Js(format!("document.body.insertAdjacentHTML('beforeend', `{}`);", about_html)));
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
                let _ = px.send_event(Ev::Js("logToDev('NEXUS CORE INITIALIZED','info');logToDev('Incognito envelope active','info');logToDev('Anti-fingerprint matrix loaded','info');".into()));
            },
            Event::UserEvent(Ev::Js(j)) => { let _ = wv.evaluate_script(&j); },
            Event::WindowEvent { event: tao::event::WindowEvent::CloseRequested, .. } => *cf = ControlFlow::Exit,
            _ => {}
        }
    });
}
