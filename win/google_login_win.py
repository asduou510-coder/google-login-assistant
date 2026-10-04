#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google 登录助手 Windows 版 v1.0
单文件、仅标准库。通过 Chrome 远程调试(CDP) 自动登录：
  FL -> Google Flow (https://flow.google.com/)
  RH -> RunningHub (https://www.runninghub.ai/zh-tw)
账号密码/TOTP 存在本地，Windows 下用 DPAPI 加密。
"""
import base64
import binascii
import ctypes
import hashlib
import hmac
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

APP_NAME = "Google 登录助手 Win"
VERSION = "1.1"

# ---------------------------------------------------------------- 登录目标
TARGETS = {
    "flow": {
        "title": "Google Flow",
        "entry": "https://flow.google.com/",
        "hosts": ("flow.google.com", "labs.google"),
    },
    "runninghub": {
        "title": "RunningHub",
        "entry": "https://www.runninghub.ai/zh-tw",
        "hosts": ("runninghub.ai", "www.runninghub.ai"),
    },
}

# ---------------------------------------------------------------- 注入脚本
LOGIN_FIELDS = {
    "email": "#identifierId,input[name='identifier'],input[type='email'],input[autocomplete='username']",
    "password": "input[name='Passwd'],input[type='password']",
    "otp": "#totpPin,input[name='totpPin']",
}

# 当前页面状态探针：host/path/https + 三类输入框可见性 + 错误/拦截标记
JS_STATE = """const visible=s=>Array.from(document.querySelectorAll(s)).some(e=>e.getClientRects().length&&!e.disabled&&!e.readOnly);
return {host:location.hostname,path:location.pathname,https:location.protocol==='https:',
email:visible(arguments[0]),password:visible(arguments[1]),otp:visible(arguments[2]),
error:!!document.querySelector('[aria-invalid=true]'),blocked:/此浏览器或应用可能不安全|This browser or app may not be secure/i.test(document.body?.innerText||'')};"""

# 跳过 Google 通行密钥提示
JS_SKIP_PASSKEY = """if(location.protocol!=='https:' || location.hostname!=='accounts.google.com') return 'none';
const text=document.body?.innerText||'';
const heading=Array.from(document.querySelectorAll('h1,[role="heading"]')).map(e=>e.innerText||e.textContent||'').join(' ');
if(!/(通行密钥|通行密鑰|通行金鑰|passkeys?)/i.test(text)) return 'none';
if(!/(简化.*登录|簡化.*登入|Simplify.*sign.?in|Sign in faster|Create.*passkey|创建通行密钥|建立通行金鑰)/i.test(heading)) return 'none';
const nodes=Array.from(document.querySelectorAll('button,a,[role="button"]'));
const skip=nodes.find(e=>e.getClientRects().length&&!e.disabled&&e.getAttribute('aria-disabled')!=='true'&&/^(以后再说|以後再說|稍后再说|稍後再說|Not now|Maybe later)$/i.test((e.innerText||e.textContent||e.getAttribute('aria-label')||'').trim()));
if(!skip)return 'none';
skip.click();return 'skipped';"""

# Flow：工作台识别 / 入口点击
JS_FLOW_SIGNED_IN = """if(location.protocol!=='https:' || !['flow.google.com','labs.google'].includes(location.hostname))return false;
if(location.hostname==='labs.google' && !/^\\/fx\\/(?:[a-z-]+\\/)?tools\\/flow(?:\\/|$)/i.test(location.pathname))return false;
if(/\\/about(?:\\/|$)/i.test(location.pathname))return false;
const visible=e=>e.getClientRects().length && !e.disabled && e.getAttribute('aria-disabled')!=='true';
const nodes=Array.from(document.querySelectorAll('button,a,[role="button"]')).filter(visible);
const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
if(nodes.some(e=>/^(sign in|log in|sign in with google|登录|登入|使用 Google (账号|帐号)登录)$/i.test(label(e))))return false;
return nodes.some(e=>/^(?:(?:add|plus|新建|新增|\\+)\\s*)?(?:新建项目|创建项目|新建專案|建立專案|new project|create project)$/i.test(label(e)));"""

JS_FLOW_ACTION = """if(location.protocol !== 'https:' || !['flow.google.com','labs.google'].includes(location.hostname)) return 'none';
const visible=e=>!!e.getClientRects().length && !e.disabled;
const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
const safe=e=>{const h=e.getAttribute('href');if(!h)return true;try{const u=new URL(h,location.href);return u.protocol==='https:'&&['flow.google.com','labs.google','accounts.google.com'].includes(u.hostname)}catch{return false}};
const tclick=(e,a)=>{try{e.scrollIntoView({block:'center'})}catch(_){};const r=e.getBoundingClientRect();return {action:a,x:Math.round(r.x+r.width/2),y:Math.round(r.y+r.height/2)}};
const nodes=Array.from(document.querySelectorAll('a,button,[role="button"]')).filter(e=>visible(e)&&safe(e));
const entry=nodes.find(e=>/^(使用\\s*(Google\\s*)?Flow\\s*创建|Create with (Google )?Flow|Try (Google )?Flow|开始使用\\s*Flow)$/i.test(label(e)));
if(entry){return tclick(entry,'entry')}
const signin=nodes.find(e=>/^(Sign in( with Google)?|Log in|登录|登入|使用 Google (账号|帐号)登录)$/i.test(label(e)) || (()=>{try{return new URL(e.getAttribute('href'),location.href).hostname==='accounts.google.com'}catch{return false}})());
if(signin){return tclick(signin,'signin')}
return 'none';"""

# RunningHub：登录态识别 / 入口点击（选择器经 2026-10-04 实测 DOM）
JS_RH_SIGNED_IN = """if(location.protocol!=='https:' || !['runninghub.ai','www.runninghub.ai'].includes(location.hostname)) return false;
const visible=e=>e.getClientRects().length && !e.disabled && e.getAttribute('aria-disabled')!=='true';
const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
const nodes=Array.from(document.querySelectorAll('button,a,[role="button"]')).filter(visible);
if(nodes.some(e=>/(登\\s*入|註\\s*冊|注\\s*册|登\\s*录|^log\\s*in$|^sign\\s*in$)/i.test(label(e)))) return false;
const avatar=document.querySelector('.ant-avatar,[class*="avatar"],[class*="Avatar"]');
return !!(avatar && visible(avatar));"""

JS_RH_ACTION = """if(location.protocol!=='https:' || !['runninghub.ai','www.runninghub.ai'].includes(location.hostname)) return 'none';
const visible=e=>!!e.getClientRects().length && !e.disabled;
const label=e=>(e.innerText||e.textContent||e.getAttribute('aria-label')||'').replace(/\\s+/g,' ').trim();
const safe=e=>{const h=e.getAttribute('href');if(!h)return true;try{const u=new URL(h,location.href);return u.protocol==='https:'&&['runninghub.ai','www.runninghub.ai','accounts.google.com'].includes(u.hostname)}catch{return false}};
const tclick=(e,a)=>{try{e.scrollIntoView({block:'center'})}catch(_){};const r=e.getBoundingClientRect();return {action:a,x:Math.round(r.x+r.width/2),y:Math.round(r.y+r.height/2)}};
const modalRoot=document.querySelector('.ant-modal-root');
const modal=(modalRoot&&visible(modalRoot))?modalRoot:null;
if(modal){
    const gimg=modal.querySelector('img[alt*="Google"]');
    let gbtn=gimg;
    while(gbtn&&gbtn!==modal){const t=gbtn.tagName;if(t==='BUTTON'||t==='A'||gbtn.getAttribute('role')==='button')break;gbtn=gbtn.parentElement;}
    const byText=Array.from(modal.querySelectorAll('button,a,[role="button"]')).find(e=>visible(e)&&safe(e)&&/使用\\s*Google.*(登入|登录)|Sign in with Google/i.test(label(e)));
    const target=(gbtn&&gbtn!==modal&&visible(gbtn)&&safe(gbtn))?gbtn:byText;
    if(target){return tclick(target,'google')}
    return 'modal';
}
const entry=Array.from(document.querySelectorAll('button.login-btn,button,a,[role="button"]')).find(e=>visible(e)&&safe(e)&&/^(登入\\s*\\/\\s*註冊|登\\s*入|登\\s*录|log\\s*in|sign\\s*in)$/i.test(label(e)));
if(entry){return tclick(entry,'entry')}
return 'none';"""

# 可信填表：只允许 accounts.google.com
JS_TRUSTED_FIELD = """if(location.protocol!=='https:' || location.hostname!=='accounts.google.com') throw Error('Origin mismatch');
const e=Array.from(document.querySelectorAll(arguments[0])).find(e=>e.getClientRects().length&&!e.disabled&&!e.readOnly);
if(!e) throw Error('Missing field');
e.scrollIntoView({block:'center'});e.focus();
if(arguments[1] && typeof e.select==='function') e.select();
const r=e.getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2};"""

JS_VERIFY_FILL = """if(location.protocol!=='https:' || location.hostname!=='accounts.google.com') return false;
const e=Array.from(document.querySelectorAll(arguments[0])).find(e=>e.getClientRects().length&&!e.disabled);
return !!e&&document.activeElement===e&&e.value===arguments[1];"""

SITE_SCRIPTS = {
    "flow": {"signed_in": JS_FLOW_SIGNED_IN, "action": JS_FLOW_ACTION},
    "runninghub": {"signed_in": JS_RH_SIGNED_IN, "action": JS_RH_ACTION},
}

# ---------------------------------------------------------------- TOTP
def totp(secret, digits=6, period=30, t=None):
    """RFC 6238 TOTP，secret 为 base32。"""
    key = base64.b32decode(secret.upper().replace(" ", "").replace("=", ""))
    counter = int((t if t is not None else time.time()) // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

# ---------------------------------------------------------------- 凭据库
def _app_dir():
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        d = os.path.join(base, "GoogleLoginWin")
    else:
        d = os.path.join(os.path.expanduser("~"), ".google_login_win")
    os.makedirs(d, exist_ok=True)
    return d

class _Blob(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.c_char_p)]

def _dpapi_protect(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _Blob(len(data), ctypes.c_char_p(data))
    blob_out = _Blob()
    if not crypt32.CryptProtectData(ctypes.byref(blob_in), None, None, None, None, 0x01, ctypes.byref(blob_out)):
        raise OSError("DPAPI 加密失败")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)

def _dpapi_unprotect(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    blob_in = _Blob(len(data), ctypes.c_char_p(data))
    blob_out = _Blob()
    if not crypt32.CryptUnprotectData(ctypes.byref(blob_in), None, None, None, None, 0x01, ctypes.byref(blob_out)):
        raise OSError("DPAPI 解密失败（可能换了 Windows 用户）")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)

def vault_save(accounts):
    raw = json.dumps(accounts, ensure_ascii=False).encode("utf-8")
    if os.name == "nt":
        payload = base64.b64encode(_dpapi_protect(raw)).decode()
        marker = "dpapi"
    else:
        payload = base64.b64encode(raw).decode()  # 仅开发调试用，非 Windows 无 DPAPI
        marker = "plain-dev-only"
    with open(os.path.join(_app_dir(), "vault.json"), "w", encoding="utf-8") as f:
        json.dump({"marker": marker, "data": payload}, f)

def vault_load():
    p = os.path.join(_app_dir(), "vault.json")
    if not os.path.isfile(p):
        return []
    with open(p, encoding="utf-8") as f:
        obj = json.load(f)
    raw = base64.b64decode(obj["data"])
    if obj.get("marker") == "dpapi":
        raw = _dpapi_unprotect(raw)
    return json.loads(raw.decode("utf-8"))

# ---------------------------------------------------------------- CDP
class CDPError(Exception):
    pass

class CDPClient:
    """最小 CDP 客户端：纯标准库 websocket。请求按 id 配对，非 solicited 事件被缓存。"""
    def __init__(self, ws_url, timeout=15):
        assert ws_url.startswith("ws://"), "只允许本机 ws"
        rest = ws_url[5:]
        hostport, self.path = rest.split("/", 1)
        self.path = "/" + self.path
        if ":" in hostport:
            host, port = hostport.split(":", 1)
            port = int(port)
        else:
            host, port = hostport, 80
        assert host in ("127.0.0.1", "localhost"), "拒绝非本机 CDP 地址"
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self._id = 0
        self._lock = threading.Lock()
        self.events = []
        key = base64.b64encode(os.urandom(16)).decode()
        req = (f"GET {self.path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\n"
               f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n")
        self.sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise CDPError("websocket 握手失败")
            resp += chunk
        if b"101" not in resp.split(b"\r\n", 1)[0]:
            raise CDPError("websocket 握手被拒绝")
        # 握手响应和首个数据帧可能同包到达：保留多余字节，后续优先消费
        self._rbuf = bytearray(resp.split(b"\r\n\r\n", 1)[1])

    def close(self):
        try:
            self._send_frame(0x8, b"")
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def _recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            if self._rbuf:
                take = min(len(self._rbuf), n - len(buf))
                buf += self._rbuf[:take]
                del self._rbuf[:take]
            else:
                chunk = self.sock.recv(n - len(buf))
                if not chunk:
                    raise CDPError("连接已断开")
                buf += chunk
        return bytes(buf)

    def _send_frame(self, opcode, data: bytes):
        hdr = bytes([0x80 | opcode])
        n = len(data)
        mask = os.urandom(4)
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self.sock.sendall(hdr + mask + masked)

    def _read_message(self):
        """读一条完整消息，处理分片/ping；返回 (is_text, text)。"""
        opcode = None
        parts = []
        while True:
            hdr = self._recv_exact(2)
            fin = hdr[0] & 0x80
            op = hdr[0] & 0x0F
            masked = hdr[1] & 0x80
            length = hdr[1] & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]
            if masked:
                mask = self._recv_exact(4)
            data = self._recv_exact(length)
            if masked:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if op == 0x8:
                raise CDPError("Chrome 关闭了连接")
            if op == 0x9:  # ping -> pong
                self._send_frame(0xA, data)
                continue
            if op == 0xA:  # pong
                continue
            if op in (0x1, 0x2):
                opcode = op
                parts = [data]
            elif op == 0x0:
                parts.append(data)
            else:
                continue
            if fin:
                raw = b"".join(parts)
                return (opcode == 0x1, raw.decode("utf-8", "replace"))

    def command(self, method, params=None, timeout=15):
        with self._lock:
            self._id += 1
            cid = self._id
            self._send_frame(0x1, json.dumps({"id": cid, "method": method, "params": params or {}}).encode())
            deadline = time.time() + timeout
            while True:
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise CDPError(f"CDP 超时: {method}")
                self.sock.settimeout(remaining)
                try:
                    is_text, text = self._read_message()
                except socket.timeout:
                    raise CDPError(f"CDP 超时: {method}")
                if not is_text:
                    continue
                try:
                    obj = json.loads(text)
                except Exception:
                    continue
                if obj.get("id") == cid:
                    if "error" in obj:
                        err = obj["error"]
                        raise CDPError(f"CDP 错误: {err.get('message', err)}")
                    return obj.get("result", {})
                self.events.append(obj)

# ---------------------------------------------------------------- Chrome
def find_chrome():
    cands = []
    if os.name == "nt":
        for p in (r"%ProgramFiles%\Google\Chrome\Application\chrome.exe",
                  r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
                  r"%LocalAppData%\Google\Chrome\Application\chrome.exe"):
            cands.append(os.path.expandvars(p))
        try:
            import winreg
            for hive, sub in ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"),
                              (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe")):
                try:
                    with winreg.OpenKey(hive, sub) as k:
                        v, _ = winreg.QueryValueEx(k, "")
                        if v:
                            cands.append(v)
                except OSError:
                    pass
        except ImportError:
            pass
    else:
        for p in ("/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"):
            cands.append(p)
    for p in cands:
        if p and os.path.isfile(p):
            return p
    return None

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

def _ws_url_for(port, timeout=25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as r:
                targets = json.load(r)
            for t in targets:
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    return t["webSocketDebuggerUrl"]
        except Exception as e:
            last = e
        time.sleep(0.5)
    raise CDPError(f"拿不到 Chrome 调试目标: {last}")

class Browser:
    """一个托管 Chrome 窗口：独立 profile + CDP 连接。"""
    def __init__(self, chrome_path, profile_dir):
        self.chrome_path = chrome_path
        self.profile_dir = profile_dir
        self.proc = None
        self.cdp = None
        self.port = None

    def start(self, url="about:blank"):
        os.makedirs(self.profile_dir, exist_ok=True)
        self.port = _free_port()
        args = [self.chrome_path,
                f"--user-data-dir={self.profile_dir}",
                f"--remote-debugging-port={self.port}",
                "--remote-debugging-address=127.0.0.1",
                "--new-window", url]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ws_url = _ws_url_for(self.port)
        self.cdp = CDPClient(ws_url)
        self.cdp.command("Page.enable")

    def close(self):
        try:
            if self.cdp:
                self.cdp.command("Browser.close")
        except Exception:
            pass
        try:
            if self.cdp:
                self.cdp.close()
        except Exception:
            pass
        self.cdp = None
        if self.proc and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
        self.proc = None

    @property
    def running(self):
        return self.proc is not None and self.proc.poll() is None

    # -- CDP 便捷封装 --
    def evaluate(self, source, args=None, timeout=12):
        expr = "(function(){" + source + "}).apply(null," + json.dumps(args or []) + ")"
        res = self.cdp.command("Runtime.evaluate",
                               {"expression": expr, "returnByValue": True, "awaitPromise": True},
                               timeout=timeout)
        if res.get("exceptionDetails"):
            raise CDPError("页面脚本执行失败（页面可能正在跳转）")
        return res.get("result", {}).get("value")

    def navigate(self, url):
        res = self.cdp.command("Page.navigate", {"url": url})
        if res.get("errorText"):
            raise CDPError("Chrome 无法打开目标页面，请检查网络")
        deadline = time.time() + 12
        while time.time() < deadline:
            try:
                if self.evaluate("return document.readyState") != "loading":
                    return
            except CDPError:
                pass
            time.sleep(0.15)

    def page_ids(self):
        res = self.cdp.command("Target.getTargets", {})
        return [t["targetId"] for t in res.get("targetInfos", [])
                if t.get("type") == "page" and not t.get("url", "").startswith("devtools://")]

    def attach_first_new(self, known):
        ids = self.page_ids()
        for tid in ids:
            if tid not in known:
                self.cdp.command("Target.attachToTarget", {"targetId": tid, "flatten": True})
                return
        # 原 tab 关了就跟随第一个
        if ids:
            self.cdp.command("Target.attachToTarget", {"targetId": ids[0], "flatten": True})

    def click_point(self, x, y):
        for typ in ("mousePressed", "mouseReleased"):
            self.cdp.command("Input.dispatchMouseEvent",
                             {"type": typ, "x": x, "y": y, "button": "left", "clickCount": 1})

    def fill(self, selector, text, next_selector):
        """只允许在 accounts.google.com 上填表；返回点击下一步后的状态。"""
        self.evaluate(JS_TRUSTED_FIELD, [selector, True])
        self.cdp.command("Input.insertText", {"text": text})
        ok = self.evaluate(JS_VERIFY_FILL, [selector, text])
        if not ok:
            raise CDPError("输入内容未成功写入，请手动填写后继续")
        point = self.evaluate(JS_TRUSTED_FIELD, [next_selector + ",button[type='submit'],input[type='submit']", False])
        if not isinstance(point, dict) or "x" not in point:
            raise CDPError("未找到下一步按钮")
        self.click_point(point["x"], point["y"])

# ---------------------------------------------------------------- 登录状态机
class StopFlag:
    def __init__(self):
        self._e = threading.Event()
    def set(self):
        self._e.set()
    @property
    def stopped(self):
        return self._e.is_set()

def _action_message(target_key, action):
    title = TARGETS[target_key]["title"]
    if target_key == "flow":
        return "已点击“使用 Google Flow 创建”，等待登录页" if action == "entry" else "已点击 Google 登录，等待账号页面"
    return {"entry": "已点击登入，等待登录弹窗",
            "google": "已点击 Google 登录，等待账号页面",
            "modal": "登录弹窗已打开，正在定位 Google 登录按钮"}.get(action, "已操作登录入口，等待页面响应")

def login_account(browser, account, target_key, stop, update):
    """自动登录主循环。account: dict(email/password/secret)。"""
    target = TARGETS[target_key]
    scripts = SITE_SCRIPTS[target_key]
    update(f"正在打开 {target['title']}")
    browser.navigate(target["entry"])
    email_attempts = 0
    password_sent = False
    otp_sent = False
    email_last_sent = 0.0
    entry_attempts = 0
    script_failures = 0
    workspace_matches = 0
    passkey_skips = 0
    last_passkey_skip = 0.0
    last_action = 0.0
    try:
        handles = set(browser.page_ids())
    except CDPError:
        handles = set()
    deadline = time.time() + 120
    while time.time() < deadline:
        if stop.stopped:
            update("已停止 · 浏览器窗口保留")
            return
        try:
            browser.attach_first_new(handles)
        except CDPError:
            pass
        try:
            handles = set(browser.page_ids())
        except CDPError:
            pass
        try:
            state = browser.evaluate(JS_STATE, [LOGIN_FIELDS["email"], LOGIN_FIELDS["password"], LOGIN_FIELDS["otp"]]) or {}
            script_failures = 0
        except CDPError:
            script_failures += 1
            if script_failures < 5:
                time.sleep(1)
                continue
            raise
        host = state.get("host") or ""
        path = state.get("path") or ""
        if host not in target["hosts"]:
            workspace_matches = 0
        if host == "accounts.google.com" and state.get("https"):
            if state.get("blocked"):
                update("Google 拒绝自动化登录 · 请用“普通打开”手动完成登录")
                return
            if not state.get("email") and not state.get("password") and not state.get("otp"):
                if passkey_skips < 3 and time.time() - last_passkey_skip > 5:
                    try:
                        if browser.evaluate(JS_SKIP_PASSKEY) == "skipped":
                            passkey_skips += 1
                            last_passkey_skip = time.time()
                            update("已点击“以后再说”，继续登录")
                            time.sleep(1)
                            continue
                    except CDPError:
                        time.sleep(1)
                        continue
            if state.get("error"):
                update("需要人工操作：请检查登录信息或验证结果")
                return
            if state.get("email") and email_attempts < 2 and time.time() - email_last_sent > 8:
                update("填写 Google 账号")
                browser.fill(LOGIN_FIELDS["email"], account["email"], "#identifierNext")
                email_attempts += 1
                email_last_sent = time.time()
            elif state.get("password") and not password_sent:
                update("填写密码")
                browser.fill(LOGIN_FIELDS["password"], account["password"], "#passwordNext")
                password_sent = True
            elif state.get("otp") and not otp_sent:
                if not account.get("secret"):
                    update("此账号未配置 TOTP，请在 Chrome 中手动完成二步验证")
                    return
                update("TOTP 验证")
                if int(time.time()) % 30 > 25:
                    time.sleep(6)
                browser.fill(LOGIN_FIELDS["otp"], totp(account["secret"]), "#totpNext")
                otp_sent = True
            elif state.get("email") and email_attempts >= 2 and time.time() - email_last_sent > 8:
                update("邮箱提交后仍停在登录页，请查看 Google 页面提示")
                return
            else:
                update("等待 Google 页面 · 如出现额外验证请手动完成")
        elif host in target["hosts"] and state.get("https"):
            try:
                signed_in = browser.evaluate(scripts["signed_in"]) is True
            except CDPError:
                signed_in = False
            if signed_in:
                workspace_matches += 1
                if workspace_matches >= 2:
                    update(f"已登录 · {target['title']}已就绪，继续下一个")
                    return
                update(f"检测到{target['title']}已登录，正在确认状态")
                time.sleep(1.2)
                continue
            workspace_matches = 0
            if target_key == "flow" and ("/project/" in path or path.endswith("/project")):
                update("已进入 Flow 项目页 · 请在窗口确认账号")
                return
            if time.time() - last_action > 8 and entry_attempts < 4:
                try:
                    raw = browser.evaluate(scripts["action"]) or "none"
                except CDPError:
                    time.sleep(1)
                    continue
                # 动作脚本返回点击坐标时，用 CDP 可信鼠标事件点击
                #（JS 合成的 click() 不是真人操作，会被浏览器拦截 OAuth 弹窗）
                action = "none"
                if isinstance(raw, dict):
                    a = raw.get("action")
                    if a in ("entry", "google", "signin") and isinstance(raw.get("x"), (int, float)) and isinstance(raw.get("y"), (int, float)):
                        try:
                            browser.click_point(float(raw["x"]), float(raw["y"]))
                        except CDPError:
                            time.sleep(1)
                            continue
                        action = a
                elif isinstance(raw, str):
                    action = raw
                if action != "none":
                    last_action = time.time()
                    entry_attempts += 1
                    update(_action_message(target_key, action))
                else:
                    update(f"正在识别{target['title']}页面 · 可手动点击登录")
        elif host:
            update("需要人工操作：浏览器进入了其他页面")
            return
        time.sleep(1.2)
    update("自动处理结束 · 请在 Chrome 确认可用状态或完成额外验证")

# ---------------------------------------------------------------- 界面
def _profiles_dir():
    d = os.path.join(_app_dir(), "profiles")
    os.makedirs(d, exist_ok=True)
    return d

def _state_path():
    return os.path.join(_app_dir(), "state.json")

def _load_state():
    try:
        with open(_state_path(), encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_state(s):
    try:
        with open(_state_path(), "w", encoding="utf-8") as f:
            json.dump(s, f)
    except Exception:
        pass

class App:
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk, messagebox, simpledialog
        self.tk, self.ttk, self.messagebox, self.simpledialog = tk, ttk, messagebox, simpledialog
        self.root = root
        root.title(f"{APP_NAME} v{VERSION}")
        root.geometry("760x520")
        self.accounts = vault_load()
        self.checked = set(a["id"] for a in self.accounts)
        self.statuses = {}
        self.state = _load_state()
        self.chrome_path = find_chrome()
        self.browsers = {}
        self.stop = StopFlag()
        self.worker = None
        self.msgq = __import__("queue").Queue()
        self._build()
        self._refresh()
        self._poll()
        if not self.chrome_path:
            self.log("未找到 Chrome，请安装 Google Chrome 后重启。")
        if os.name != "nt":
            self.log("注意：当前不是 Windows，凭据为开发模式明文存储，仅用于调试。")

    # -- 布局 --
    def _build(self):
        tk, ttk = self.tk, self.ttk
        bar = ttk.Frame(self.root, padding=6)
        bar.pack(fill="x")
        ttk.Button(bar, text="＋ 添加", command=self.add_account).pack(side="left", padx=2)
        ttk.Button(bar, text="编辑", command=self.edit_account).pack(side="left", padx=2)
        ttk.Button(bar, text="删除", command=self.del_account).pack(side="left", padx=2)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        self.btn_fl = ttk.Button(bar, text="⚗ FL 登录", command=lambda: self.start_login("flow"))
        self.btn_fl.pack(side="left", padx=2)
        self.btn_rh = ttk.Button(bar, text="⚗ RH 登录", command=lambda: self.start_login("runninghub"))
        self.btn_rh.pack(side="left", padx=2)
        ttk.Button(bar, text="普通打开", command=self.open_plain).pack(side="left", padx=2)
        self.btn_stop = ttk.Button(bar, text="■ 停止", command=self.stop_all, state="disabled")
        self.btn_stop.pack(side="left", padx=2)
        ttk.Separator(bar, orient="vertical").pack(side="left", fill="y", padx=8)
        ttk.Button(bar, text="全选", command=self.check_all).pack(side="left", padx=2)
        ttk.Button(bar, text="清空", command=self.check_none).pack(side="left", padx=2)

        cols = ("check", "email", "status")
        self.tree = ttk.Treeview(self.root, columns=cols, show="headings", height=12)
        self.tree.heading("check", text="")
        self.tree.heading("email", text="账号邮箱")
        self.tree.heading("status", text="状态")
        self.tree.column("check", width=36, anchor="center")
        self.tree.column("email", width=260)
        self.tree.column("status", width=380)
        self.tree.pack(fill="both", expand=True, padx=6, pady=4)
        self.tree.bind("<Double-1>", self._toggle_event)
        self.tree.bind("<space>", self._toggle_event)
        self.tree.bind("<<TreeviewSelect>>", lambda e: None)

        self.logw = tk.Text(self.root, height=8, state="disabled", font=("Consolas", 9))
        self.logw.pack(fill="x", padx=6, pady=(0, 6))
        if not self.chrome_path:
            self.btn_fl["state"] = "disabled"
            self.btn_rh["state"] = "disabled"

    def _poll(self):
        try:
            while True:
                kind, payload = self.msgq.get_nowait()
                if kind == "status":
                    aid, text = payload
                    self.statuses[aid] = text
                    self._refresh_row(aid)
                elif kind == "log":
                    self.log(payload)
                elif kind == "done":
                    self._on_worker_done()
        except Exception:
            pass
        self.root.after(200, self._poll)

    # -- 账号 --
    def _refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for a in self.accounts:
            mark = "☑" if a["id"] in self.checked else "☐"
            self.tree.insert("", "end", iid=a["id"],
                             values=(mark, a["email"], self.statuses.get(a["id"], "")))

    def _refresh_row(self, aid):
        if self.tree.exists(aid):
            a = next((x for x in self.accounts if x["id"] == aid), None)
            if a:
                mark = "☑" if aid in self.checked else "☐"
                self.tree.item(aid, values=(mark, a["email"], self.statuses.get(aid, "")))

    def _toggle_event(self, event):
        iid = self.tree.identify_row(event.y) if hasattr(event, "y") else None
        rows = [iid] if iid else self.tree.selection()
        for r in rows:
            if r in self.checked:
                self.checked.discard(r)
            else:
                self.checked.add(r)
            self._refresh_row(r)
        return "break"

    def _selected_ids(self):
        sel = self.tree.selection()
        return list(sel) if sel else [a["id"] for a in self.accounts if a["id"] in self.checked]

    def _account_dialog(self, account=None):
        tk = self.tk
        dlg = tk.Toplevel(self.root)
        dlg.title("编辑账号" if account else "添加账号")
        dlg.geometry("420x300")
        dlg.transient(self.root)
        dlg.grab_set()
        vars_ = {}
        for i, (label, key, show) in enumerate((("邮箱", "email", None), ("密码", "password", "*"), ("TOTP 密钥(可选)", "secret", None))):
            tk.Label(dlg, text=label).grid(row=i, column=0, sticky="e", padx=8, pady=6)
            v = tk.StringVar(value=(account or {}).get(key, ""))
            vars_[key] = v
            tk.Entry(dlg, textvariable=v, width=36, show=show or "").grid(row=i, column=1, padx=8, pady=6)
        tk.Label(dlg, text="当前验证码").grid(row=3, column=0, sticky="e", padx=8, pady=6)
        code_var = tk.StringVar(value="—")
        tk.Label(dlg, textvariable=code_var, font=("Consolas", 14)).grid(row=3, column=1, sticky="w", padx=8)
        result = {}
        def tick():
            try:
                s = vars_["secret"].get().strip()
                if s:
                    code_var.set(f"{totp(s)}  ({30 - int(time.time()) % 30}s)")
                else:
                    code_var.set("—")
            except Exception:
                code_var.set("密钥无效")
            if dlg.winfo_exists():
                dlg.after(1000, tick)
        tick()
        def ok():
            email = vars_["email"].get().strip()
            if "@" not in email:
                self.messagebox.showerror("错误", "邮箱格式不正确", parent=dlg)
                return
            if not vars_["password"].get():
                self.messagebox.showerror("错误", "密码不能为空", parent=dlg)
                return
            s = vars_["secret"].get().strip()
            if s:
                try:
                    totp(s)
                except Exception:
                    self.messagebox.showerror("错误", "TOTP 密钥无效（应为 base32，如验证器 App 里“设置密钥”）", parent=dlg)
                    return
            result.update(email=email, password=vars_["password"].get(), secret=s)
            dlg.destroy()
        tk.Button(dlg, text="保存", command=ok, width=12).grid(row=4, column=0, columnspan=2, pady=12)
        self.root.wait_window(dlg)
        return result or None

    def add_account(self):
        data = self._account_dialog()
        if data:
            import uuid
            data["id"] = uuid.uuid4().hex
            self.accounts.append(data)
            self.checked.add(data["id"])
            vault_save(self.accounts)
            self._refresh()
            self.log(f"已添加 {data['email']}")

    def edit_account(self):
        ids = self._selected_ids()
        if len(ids) != 1:
            self.messagebox.showinfo("提示", "请只选中一个账号进行编辑")
            return
        a = next(x for x in self.accounts if x["id"] == ids[0])
        data = self._account_dialog(a)
        if data:
            a.update(data)
            vault_save(self.accounts)
            self._refresh()

    def del_account(self):
        ids = self._selected_ids()
        if not ids:
            return
        if not self.messagebox.askyesno("确认", f"删除 {len(ids)} 个账号？（浏览器数据保留）"):
            return
        self.accounts = [a for a in self.accounts if a["id"] not in ids]
        for i in ids:
            self.checked.discard(i)
            self.statuses.pop(i, None)
        vault_save(self.accounts)
        self._refresh()

    def check_all(self):
        self.checked = set(a["id"] for a in self.accounts)
        self._refresh()

    def check_none(self):
        self.checked = set()
        self._refresh()

    # -- 运行 --
    def log(self, text):
        self.logw["state"] = "normal"
        self.logw.insert("end", f"[{time.strftime('%H:%M:%S')}] {text}\n")
        self.logw.see("end")
        self.logw["state"] = "disabled"

    def _set_busy(self, busy):
        st = "disabled" if busy else "normal"
        self.btn_fl["state"] = st
        self.btn_rh["state"] = st
        self.btn_stop["state"] = "normal" if busy else "disabled"

    def start_login(self, target_key):
        if self.worker and self.worker.is_alive():
            return
        ids = self._selected_ids()
        if not ids:
            self.messagebox.showinfo("提示", "请先勾选要登录的账号")
            return
        if not self.chrome_path:
            self.messagebox.showerror("错误", "未找到 Chrome")
            return
        self.stop = StopFlag()
        accts = [a for a in self.accounts if a["id"] in ids]
        self._set_busy(True)
        self.worker = threading.Thread(target=self._run_queue, args=(accts, target_key), daemon=True)
        self.worker.start()
        self.log(f"开始 {TARGETS[target_key]['title']} 自动登录，共 {len(accts)} 个账号")

    def _browser_for(self, aid):
        b = self.browsers.get(aid)
        if b and b.running and b.cdp:
            return b
        if b:
            try:
                b.close()
            except Exception:
                pass
        b = Browser(self.chrome_path, os.path.join(_profiles_dir(), aid))
        b.start()
        self.browsers[aid] = b
        return b

    def _run_queue(self, accts, target_key):
        q = self.msgq
        try:
            for a in accts:
                if self.stop.stopped:
                    q.put(("status", (a["id"], "已取消")))
                    continue
                q.put(("status", (a["id"], "等待处理")))
                def update(t, aid=a["id"]):
                    q.put(("status", (aid, t)))
                try:
                    update("正在启动 Chrome")
                    browser = self._browser_for(a["id"])
                    login_account(browser, a, target_key, self.stop, update)
                    st = self.state
                    st.setdefault("last_target", {})[a["id"]] = target_key
                    _save_state(st)
                except Exception as e:
                    update(f"出错：{e}")
                    q.put(("log", f"{a['email']}: {e}"))
        finally:
            q.put(("done", None))

    def _on_worker_done(self):
        self._set_busy(False)
        self.log("队列处理结束")

    def stop_all(self):
        self.stop.set()
        self.log("已请求停止（当前账号完成后停下，窗口保留）")

    def open_plain(self):
        ids = self._selected_ids()
        if not ids:
            self.messagebox.showinfo("提示", "请先勾选账号")
            return
        if not self.chrome_path:
            self.messagebox.showerror("错误", "未找到 Chrome")
            return
        last = self.state.get("last_target", {})
        for aid in ids:
            a = next((x for x in self.accounts if x["id"] == aid), None)
            if not a:
                continue
            tkey = last.get(aid, "flow")
            try:
                b = self._browser_for(aid)
                b.navigate(TARGETS[tkey]["entry"])
                self.statuses[aid] = "已普通打开 · 登录状态保留"
                self._refresh_row(aid)
            except Exception as e:
                self.statuses[aid] = f"打开失败：{e}"
                self._refresh_row(aid)
        self.log(f"已普通打开 {len(ids)} 个账号窗口")

def main():
    import tkinter as tk
    root = tk.Tk()
    try:
        root.tk.call("tk", "windowingsystem")  # noqa
    except Exception:
        pass
    App(root)
    root.mainloop()

if __name__ == "__main__":
    main()
