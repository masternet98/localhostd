import os
import re
import sys
import time
import json
import shutil
import queue
import threading
import subprocess
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from typing import Optional, List, Callable

# Tkinter (stdlib)
import tkinter as tk
from tkinter import ttk, messagebox


# --------------------------
# Core state and utilities
# --------------------------


@dataclass
class TunnelState:
    port: int = 8501
    running: bool = False
    proc: Optional[subprocess.Popen] = None
    url: str = ""
    logs: List[str] = field(default_factory=list)
    max_logs: int = 100

    def push_log(self, line: str) -> None:
        line = line.rstrip("\r\n")
        if not line:
            return
        self.logs.append(line)
        if len(self.logs) > self.max_logs:
            # keep only the last max_logs lines
            self.logs = self.logs[-self.max_logs :]


def detect_cloudflared() -> Optional[str]:
    """Detect cloudflared executable path on Windows.

    Search order:
    - PATH via shutil.which
    - Common install locations
    """
    which = shutil.which("cloudflared")
    if which:
        return which

    standard_paths = [
        r"C:\\Program Files\\cloudflared\\cloudflared.exe",
        r"C:\\Program Files (x86)\\cloudflared\\cloudflared.exe",
        r"%LOCALAPPDATA%\\cloudflared\\cloudflared.exe",
        r"%USERPROFILE%\\.cloudflared\\cloudflared.exe",
    ]
    for path in standard_paths:
        expanded = os.path.expandvars(path)
        if os.path.isfile(expanded):
            return expanded
    return None


def get_cloudflared_version(cloudflared_path: str) -> str:
    try:
        result = subprocess.run(
            [cloudflared_path, "--version"], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            m = re.search(r"version (\d+\.\d+\.\d+)", result.stdout)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "unknown"


URL_PATTERNS = [
    re.compile(r"https://[A-Za-z0-9\-]+\.trycloudflare\.com"),
    re.compile(r"https://[A-Za-z0-9\-]+\.cfargotunnel\.com"),
]


def _build_cloudflared_cmd(cloudflared_path: str, port: int) -> List[str]:
    # Minimal flags; avoid auto-update and keep info logs
    return [
        cloudflared_path,
        "tunnel",
        "--no-autoupdate",
        "--loglevel",
        "info",
        "--url",
        f"http://localhost:{port}",
    ]


class TunnelRunner:
    """Manage the cloudflared tunnel process and parse output for URL."""

    def __init__(self, state: TunnelState, cloudflared_path: str):
        self.state = state
        self.cloudflared_path = cloudflared_path
        self._reader_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.on_log: Optional[Callable[[str], None]] = None
        self.on_url: Optional[Callable[[str], None]] = None

    def start(self, port: int) -> Optional[str]:
        if self.state.running:
            return None
        cmd = _build_cloudflared_cmd(self.cloudflared_path, port)
        try:
            # Start process
            self.state.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except FileNotFoundError:
            return "cloudflared executable not found"
        except Exception as e:
            return f"failed to start: {e}"

        self.state.running = True
        self._stop_event.clear()
        self._reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self._reader_thread.start()
        return None

    def stop(self, timeout: float = 5.0) -> None:
        if not self.state.running:
            return
        self._stop_event.set()
        proc = self.state.proc
        self.state.proc = None
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
            except Exception:
                pass
        self.state.running = False
        # Do not clear URL; keep visible after stop

    def _read_output(self) -> None:
        assert self.state.proc is not None
        f = self.state.proc.stdout
        if not f:
            return
        for raw in f:
            if self._stop_event.is_set():
                break
            line = raw.rstrip("\r\n")
            if self.on_log:
                self.on_log(line)
            # Try simple JSON extraction first
            try:
                if line.startswith("{") and '"url"' in line:
                    data = json.loads(line)
                    url = data.get("url")
                    if isinstance(url, str) and url.startswith("http"):
                        if self.on_url:
                            self.on_url(url)
            except Exception:
                pass
            # Fallback to regex patterns
            for pat in URL_PATTERNS:
                m = pat.search(line)
                if m:
                    url = m.group(0)
                    if self.on_url:
                        self.on_url(url)
                    break


# --------------------------
# Install / Download helpers
# --------------------------


def download_with_progress(url: str, local_path: str, progress_cb: Optional[Callable[[int, int], None]] = None, chunk_size: int = 8192) -> None:
    with urllib.request.urlopen(url) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        read = 0
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        with open(local_path, "wb") as f:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                read += len(chunk)
                if progress_cb:
                    try:
                        progress_cb(read, total)
                    except Exception:
                        pass


def auto_install_cloudflared(progress_cb: Optional[Callable[[int, int], None]] = None) -> Optional[str]:
    try:
        url = "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        local_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.getcwd()), "cloudflared")
        os.makedirs(local_dir, exist_ok=True)
        local_path = os.path.join(local_dir, "cloudflared.exe")
        download_with_progress(url, local_path, progress_cb)
        if os.path.isfile(local_path):
            return local_path
    except Exception:
        return None
    return None


# --------------------------
# Tkinter UI
# --------------------------


def build_qr_url(data: str, size: int = 240) -> str:
    """Return a QR image URL from a public API (no deps, opens in browser).

    Uses api.qrserver.com to render a PNG. This avoids bundling QR libs.
    """
    from urllib.parse import quote

    s = max(64, min(size, 1024))
    return f"https://api.qrserver.com/v1/create-qr-code/?size={s}x{s}&data={quote(data)}"


## Short URL feature removed


## Short URL debug feature removed


class DownloadDialog:
    def __init__(self, parent: tk.Tk):
        self.top = tk.Toplevel(parent)
        self.top.title("Cloudflared 다운로드 중...")
        self.top.geometry("420x140")
        self.top.resizable(False, False)
        self._cancelled = False

        self.label = ttk.Label(self.top, text="다운로드 준비 중...")
        self.bar = ttk.Progressbar(self.top, mode="determinate", length=360)
        self.cancel_btn = ttk.Button(self.top, text="취소", command=self.cancel)

        self.label.pack(pady=(16, 8))
        self.bar.pack(pady=8)
        self.cancel_btn.pack(pady=(8, 12))

        # Make dialog modal-ish
        self.top.transient(parent)
        self.top.grab_set()

    def update_progress(self, current: int, total: int) -> None:
        percent = int((current / total) * 100) if total else 0
        self.bar["maximum"] = 100
        self.bar["value"] = percent
        human = f"{current/1024/1024:.1f}MB / {total/1024/1024:.1f}MB" if total else f"{current/1024/1024:.1f}MB"
        self.label.config(text=f"다운로드 중... {percent}%  ({human})")
        self.top.update_idletasks()

    def cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        self._cancelled = True
        # Note: urllib read cannot be interrupted easily; this flag allows caller to stop between chunks.
        self.label.config(text="취소 중...")


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Cloudflared 터널 관리자 (경량)")
        self.geometry("500x460")
        self.resizable(False, False)

        self.state_ = TunnelState()
        self.runner: Optional[TunnelRunner] = None
        self._ui_queue: "queue.Queue[Callable[[], None]]" = queue.Queue()

        # Top: cloudflared status
        frm_top = ttk.Frame(self)
        frm_top.pack(fill="x", padx=12, pady=(12, 6))

        self.lbl_cf = ttk.Label(frm_top, text="Cloudflared: 확인 중...")
        self.btn_install = ttk.Button(frm_top, text="설치", command=self._on_install)

        self.lbl_cf.pack(side="left")
        self.btn_install.pack(side="right")

        # Middle: controls
        frm_mid = ttk.Frame(self)
        frm_mid.pack(fill="x", padx=12, pady=6)

        ttk.Label(frm_mid, text="상태:").grid(row=0, column=0, sticky="w")
        self.var_status = tk.StringVar(value="정지")
        self.lbl_status = ttk.Label(frm_mid, textvariable=self.var_status)
        self.lbl_status.grid(row=0, column=1, sticky="w")

        ttk.Label(frm_mid, text="포트:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.var_port = tk.StringVar(value=str(self.state_.port))
        self.ent_port = ttk.Entry(frm_mid, textvariable=self.var_port, width=8)
        self.ent_port.grid(row=1, column=1, sticky="w", pady=(6, 0))

        # URL row
        ttk.Label(frm_mid, text="URL:").grid(row=2, column=0, sticky="nw", pady=(6, 0))
        self.var_url = tk.StringVar(value="-")
        # Use readonly Entry for better layout and easy copy
        self.ent_url = ttk.Entry(frm_mid, textvariable=self.var_url, width=44, state="readonly")
        self.ent_url.grid(row=2, column=1, sticky="w", pady=(6, 0), columnspan=3)

        self.btn_copy = ttk.Button(frm_mid, text="복사", command=self._on_copy)
        self.btn_open = ttk.Button(frm_mid, text="열기", command=self._on_open)
        self.btn_qr = ttk.Button(frm_mid, text="QR", command=self._on_qr)
        self.btn_copy.grid(row=2, column=4, padx=(6, 0))
        self.btn_open.grid(row=2, column=5, padx=(6, 0))
        self.btn_qr.grid(row=2, column=6, padx=(6, 0))

        # Short URL feature removed

        # Debug toggle
        ttk.Label(frm_mid, text="디버그:").grid(row=3, column=0, sticky="w", pady=(6, 0))
        self.var_debug = tk.BooleanVar(value=False)
        self.chk_debug = ttk.Checkbutton(frm_mid, variable=self.var_debug)
        self.chk_debug.grid(row=3, column=1, sticky="w", pady=(6, 0))

        # Start/Stop
        frm_btns = ttk.Frame(self)
        frm_btns.pack(fill="x", padx=12, pady=(6, 6))
        self.btn_start = ttk.Button(frm_btns, text="시작", command=self._on_start)
        self.btn_stop = ttk.Button(frm_btns, text="중지", command=self._on_stop)
        self.btn_start.pack(side="left")
        self.btn_stop.pack(side="left", padx=(8, 0))

        # Adjust grid weights minimally so entries take space
        try:
            frm_mid.columnconfigure(1, weight=1)
        except Exception:
            pass

        # Logs
        frm_logs = ttk.LabelFrame(self, text="로그 (최근 100줄)")
        frm_logs.pack(fill="both", expand=True, padx=12, pady=(6, 12))
        self.txt_logs = tk.Text(frm_logs, height=12, state="disabled")
        self.txt_logs.pack(fill="both", expand=True)

        # Bind close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Kick off async UI update loop
        self.after(100, self._drain_ui_queue)

        # Detect cloudflared
        self.cloudflared_path: Optional[str] = None
        self._refresh_cloudflared_status()
        self._update_url_buttons_state()

    # -------------- Logging helpers --------------
    def log_info(self, msg: str) -> None:
        self._append_log(f"[INFO] {msg}")

    def log_error(self, msg: str) -> None:
        self._append_log(f"[ERROR] {msg}")

    def log_debug(self, msg: str) -> None:
        if self.var_debug.get():
            self._append_log(f"[DEBUG] {msg}")

    # -------------- UI helpers --------------
    def _drain_ui_queue(self) -> None:
        try:
            while True:
                fn = self._ui_queue.get_nowait()
                fn()
        except queue.Empty:
            pass
        self.after(100, self._drain_ui_queue)

    def _append_log(self, line: str) -> None:
        self.state_.push_log(line)
        self.txt_logs.configure(state="normal")
        self.txt_logs.delete("1.0", tk.END)
        self.txt_logs.insert(tk.END, "\n".join(self.state_.logs))
        self.txt_logs.see(tk.END)
        self.txt_logs.configure(state="disabled")

    def _set_url(self, url: str) -> None:
        self.state_.url = url
        self.ent_url.configure(state="normal")
        self.var_url.set(url)
        self.ent_url.configure(state="readonly")
        self._update_url_buttons_state()

    # Short URL feature removed

    def _update_url_buttons_state(self) -> None:
        has_url = bool(self.state_.url and self.state_.url != "-")
        for btn in (self.btn_copy, self.btn_open, self.btn_qr):
            try:
                btn.config(state=("normal" if has_url else "disabled"))
            except Exception:
                pass

    def _refresh_cloudflared_status(self) -> None:
        path = detect_cloudflared()
        self.cloudflared_path = path
        if path:
            ver = get_cloudflared_version(path)
            self.lbl_cf.config(text=f"Cloudflared: v{ver}")
            self.btn_install.config(text="재설치", state="normal")
            self.btn_start.config(state="normal")
        else:
            self.lbl_cf.config(text="Cloudflared: 미설치")
            self.btn_install.config(text="설치", state="normal")
            self.btn_start.config(state="disabled")

    # -------------- Actions --------------
    def _on_copy(self) -> None:
        if not self.state_.url:
            return
        try:
            self.clipboard_clear()
            self.clipboard_append(self.state_.url)
            self.update()  # keep clipboard
        except Exception:
            pass

    def _on_open(self) -> None:
        if self.state_.url:
            webbrowser.open(self.state_.url)

    def _on_qr(self) -> None:
        if not self.state_.url or self.state_.url == "-":
            return
        qr = build_qr_url(self.state_.url, size=240)
        webbrowser.open(qr)

    def _on_start(self) -> None:
        if not self.cloudflared_path:
            messagebox.showwarning("안내", "Cloudflared가 설치되어 있지 않습니다.")
            return

        # Validate port
        try:
            port = int(self.var_port.get())
            if not (1 <= port <= 65535):
                raise ValueError
        except Exception:
            messagebox.showerror("오류", "포트는 1-65535 범위의 숫자여야 합니다.")
            return

        self.var_status.set("실행 중")
        self.btn_start.config(state="disabled")
        self.ent_port.config(state="disabled")
        self.btn_stop.config(state="normal")
        self._append_log(f"Starting tunnel on port {port}...")

        self.runner = TunnelRunner(self.state_, self.cloudflared_path)
        self.runner.on_log = lambda line: self._ui_queue.put(lambda l=line: self._append_log(l))
        self.runner.on_url = lambda url: self._ui_queue.put(lambda u=url: self._set_url(u))
        err = self.runner.start(port)
        if err:
            messagebox.showerror("시작 실패", err)
            self.var_status.set("정지")
            self.btn_start.config(state="normal")
            self.ent_port.config(state="normal")
            self.btn_stop.config(state="disabled")
            return

    def _on_stop(self) -> None:
        if self.runner:
            self.runner.stop()
        self.var_status.set("정지")
        self.btn_start.config(state="normal")
        self.ent_port.config(state="normal")
        self.btn_stop.config(state="disabled")
        self._append_log("Tunnel stopped.")
        self._update_url_buttons_state()

    # Short URL feature removed

    # Short URL feature removed

    # Short URL feature removed

    def _on_install(self) -> None:
        # Show simple modal progress dialog and do download in a thread
        dlg = DownloadDialog(self)

        def worker():
            def cb(cur: int, tot: int) -> None:
                # Called from download thread; marshal to UI
                self._ui_queue.put(lambda c=cur, t=tot: dlg.update_progress(c, t))
                if dlg.cancelled():
                    raise RuntimeError("cancelled")

            path: Optional[str] = None
            err: Optional[str] = None
            try:
                path = auto_install_cloudflared(cb)
            except Exception as e:  # network/permissions, etc.
                err = str(e)

            def finalize():
                try:
                    dlg.top.grab_release()
                    dlg.top.destroy()
                except Exception:
                    pass
                if path and os.path.isfile(path):
                    messagebox.showinfo("완료", "Cloudflared 설치가 완료되었습니다.")
                    self._refresh_cloudflared_status()
                else:
                    msg = "Cloudflared 설치에 실패했습니다. 네트워크와 권한을 확인해주세요."
                    if err:
                        msg += f"\n\n오류: {err}"
                    messagebox.showerror("설치 실패", msg)

            self._ui_queue.put(finalize)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def _on_close(self) -> None:
        try:
            if self.runner:
                self.runner.stop()
        finally:
            self.destroy()


def main() -> None:
    # High-DPI awareness on Windows for sharper UI (best-effort)
    try:
        if sys.platform.startswith("win"):
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
