#!/usr/bin/env python3
"""Dashboard总览 — 目标数/存活数/Flag数/告警数 卡片+趋势图"""
import os, sys, json, time, threading, random
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import scrolledtext
import ttkbootstrap as tb
from ttkbootstrap.constants import *

DASH_DIR = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(DASH_DIR, 'dashboard_state.json')

C = {
    'bg': '#070b14', 'card_bg': '#0d1526', 'border': '#1b2a4a',
    'text': '#d6e4ff', 'text_dim': '#6b7f9e', 'accent': '#00d4ff',
    'green': '#00ff9d', 'red': '#ff4d6d', 'yellow': '#d29922', 'purple': '#bc8cff',
}

class DashboardTab:
    def __init__(self, parent, tabs_ref=None):
        self.parent = parent
        self.tabs = tabs_ref
        self.state = self.load_state()
        self.build_ui()

    def load_state(self):
        d = {'total_targets':0,'alive_targets':0,'total_flags':0,'total_alerts':0,
             'total_waf':0,'total_shells':0,'history':[]}
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE) as f: d.update(json.load(f))
            except: pass
        return d

    def save_state(self):
        try:
            with open(STATE_FILE, 'w') as f: json.dump(self.state, f, indent=2)
        except: pass

    def update_stats(self, **kw):
        for k, v in kw.items():
            if k in self.state: self.state[k] = v
        self.state['history'].append({'t': datetime.now().isoformat(), **kw})
        if len(self.state['history']) > 200: self.state['history'] = self.state['history'][-200:]
        self.save_state()
        self.refresh_ui()

    def refresh_ui(self):
        for kid, key in [('card_targets','total_targets'),('card_alive','alive_targets'),
                          ('card_flags','total_flags'),('card_alerts','total_alerts'),
                          ('card_waf','total_waf'),('card_shells','total_shells')]:
            if kid in self.cards: self.cards[kid].config(text=str(self.state.get(key, 0)))
        last = self.state.get('history', [])
        if last and 'lbl_last' in dir(self):
            self.lbl_last.config(text=f'最后更新: {last[-1]["t"][:19]}')

    def build_ui(self):
        f = tk.Frame(self.parent, bg=C['bg'])
        f.pack(fill=tk.BOTH, expand=True)

        # ── 顶部霓虹指挥台横幅 ──
        head = tk.Frame(f, bg=C['bg'])
        head.pack(fill=tk.X, padx=12, pady=(10,0))
        self.banner = tk.Frame(head, bg='#082540', height=66)
        self.banner.pack(fill=tk.X)
        self.banner.pack_propagate(False)
        # 顶部青线
        tk.Frame(self.banner, bg='#00d4ff', height=2).pack(side=tk.TOP, fill=tk.X)
        # 主体行
        row = tk.Frame(self.banner, bg='#082540')
        row.pack(fill=tk.BOTH, expand=True)
        # 左侧 LOGO
        logo_frame = tk.Frame(row, bg='#082540')
        logo_frame.pack(side=tk.LEFT, padx=(14, 0))
        logo_box = tk.Canvas(logo_frame, width=34, height=34, bg='#00d4ff',
            highlightthickness=0)
        logo_box.pack(side=tk.LEFT, padx=(0, 8), pady=16)
        logo_box.create_text(17, 17, text='P', font=('微软雅黑', 16, 'bold'), fill='#e8f6ff')
        # 左侧文字
        left = tk.Frame(row, bg='#082540')
        left.pack(side=tk.LEFT, fill=tk.Y, pady=10)
        tk.Label(left, text='YL_PHANTOM', font=('微软雅黑', 18, 'bold'),
            fg='#e8f6ff', bg='#082540').pack(anchor=tk.W)
        tk.Label(left, text='作战指挥台  ·  SECURITY COMMAND CENTER',
            font=('微软雅黑', 9), fg=C['accent'], bg='#082540').pack(anchor=tk.W)
        # 右侧信息
        right = tk.Frame(row, bg='#082540')
        right.pack(side=tk.RIGHT, padx=(0, 14), pady=10)
        tk.Label(right, text='v2.1 · SYSTEM ONLINE', font=('微软雅黑', 8, 'bold'),
            fg='#00ff9d', bg='#082540').pack(anchor=tk.E)
        self.clock_lbl = tk.Label(right, text='', font=('微软雅黑', 12, 'bold'),
            fg=C['accent'], bg='#082540')
        self.clock_lbl.pack(anchor=tk.E)
        self.lbl_last = tk.Label(right, text='', font=('微软雅黑', 8),
            fg=C['text_dim'], bg='#082540')
        self.lbl_last.pack(anchor=tk.E)
        self._update_clock()
        # 底部暗线
        tk.Frame(self.banner, bg='#1b2a4a', height=1).pack(side=tk.BOTTOM, fill=tk.X)
        glow = tk.Frame(f, bg=C['accent'], height=2)
        glow.pack(fill=tk.X, padx=12, pady=(8,0))

        # ── 指标卡片 ──
        c1 = tk.Frame(f, bg=C['bg'])
        c1.pack(fill=tk.X, padx=12, pady=(4,6))
        self.cards = {}
        card_defs = [
            ('card_targets', '🌐 目标数', C['accent'], 'total_targets'),
            ('card_alive', '✅ 存活数', C['green'], 'alive_targets'),
            ('card_flags', '🏆 Flag数', C['yellow'], 'total_flags'),
            ('card_alerts', '🚨 告警数', C['red'], 'total_alerts'),
            ('card_waf', '🛡️ WAF部署', C['purple'], 'total_waf'),
            ('card_shells', '🕷️ 木马植入', '#ff7b72', 'total_shells'),
        ]
        for kid, lbl, col, key in card_defs:
            card = tk.Frame(c1, bg=C['card_bg'], bd=0, highlightthickness=1,
                highlightcolor=C['border'], highlightbackground=C['border'])
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
            # 顶部彩色装饰线
            tk.Frame(card, bg=col, height=3).pack(fill=tk.X)
            n = tk.Label(card, text=str(self.state.get(key, 0)),
                fg=col, bg=C['card_bg'], font=('微软雅黑', 22, 'bold'))
            n.pack(pady=(6,0))
            tk.Label(card, text=lbl, fg=C['text_dim'], bg=C['card_bg'],
                font=('微软雅黑', 9)).pack(pady=(0,6))
            self.cards[kid] = n

        # ── 快捷操作 ──
        c2 = tk.Frame(f, bg=C['bg'])
        c2.pack(fill=tk.X, padx=12, pady=4)
        tk.Label(c2, text='⚡ 快捷操作', font=('微软雅黑', 9, 'bold'),
            fg=C['text'], bg=C['bg']).pack(anchor=tk.W, pady=(0,6))
        btn_f = tk.Frame(c2, bg=C['bg'])
        btn_f.pack(fill=tk.X)
        for txt, cmd, col in [('部署WAF',self.q_waf,'#7c5cff'),('Get Flag',self.q_flag,'#c084fc'),
            ('一键加固',self.q_harden,'#ff4d6d'),('备份网站',self.q_backup,'#00ff9d')]:
            b = tk.Button(btn_f, text=txt, command=cmd, bg=col, fg='white',
                relief=tk.FLAT, bd=0, padx=14, pady=4, cursor='hand2',
                font=('微软雅黑', 9, 'bold'), activebackground=C['text_dim'],
                highlightthickness=1, highlightcolor=col, highlightbackground=col)
            b.pack(side=tk.LEFT, padx=3)
            b.bind('<Enter>', lambda e, c=col, w=b: w.config(bg=C['bg'], fg=c))
            b.bind('<Leave>', lambda e, c=col, w=b: w.config(bg=c, fg='white'))

        # ── 趋势图 ──
        trend_f = tk.Frame(f, bg=C['bg'])
        trend_f.pack(fill=tk.X, padx=12, pady=(4,6))
        tk.Label(trend_f, text='📈 活动趋势', font=('微软雅黑', 9, 'bold'),
            fg=C['text'], bg=C['bg']).pack(anchor=tk.W, pady=(0,4))
        self.trend_canvas = tk.Canvas(trend_f, bg=C['card_bg'], bd=0,
            highlightthickness=0, height=180)
        self.trend_canvas.pack(fill=tk.X)
        self.trend_canvas.bind('<Configure>', self.draw_trend)

        # ── 近期活动 ──
        log_f = tk.Frame(f, bg=C['bg'])
        log_f.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0,8))
        tk.Label(log_f, text='📋 近期活动', font=('微软雅黑', 9, 'bold'),
            fg=C['text'], bg=C['bg']).pack(anchor=tk.W, pady=(0,4))
        log_box = tk.Frame(log_f, bg=C['card_bg'], bd=0, highlightthickness=1,
            highlightcolor=C['border'], highlightbackground=C['border'])
        log_box.pack(fill=tk.BOTH, expand=True)
        self.activity_text = scrolledtext.ScrolledText(log_box, bg=C['card_bg'],
            fg=C['text_dim'], insertbackground=C['text'], font=('Consolas', 9),
            bd=0, highlightthickness=0, state=tk.DISABLED)
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=2, pady=2)
        for t, c in [('flag',C['yellow']),('alert',C['red']),('ok',C['green']),
                      ('info',C['text_dim']),('cmd',C['accent'])]:
            self.activity_text.tag_config(t, foreground=c)

        self.show_welcome()

    def show_welcome(self):
        self.log_activity('✨ 安全监控面板已加载', 'ok')
        self.log_activity('\u2139\ufe0f 左侧Tab栏进入各功能模块', 'info')

    def _update_clock(self):
        from datetime import datetime
        self.clock_lbl.config(text=datetime.now().strftime('%H:%M:%S'))
        self.clock_lbl.after(1000, self._update_clock)

    def log_activity(self, msg, tag='info'):
        self.activity_text.config(state=tk.NORMAL)
        ts = datetime.now().strftime('%H:%M:%S')
        self.activity_text.insert(tk.END, f'[{ts}] ', 'info')
        self.activity_text.insert(tk.END, msg + '\n', tag)
        self.activity_text.see(tk.END)
        self.activity_text.config(state=tk.DISABLED)

    def draw_trend(self, event=None):
        w = self.trend_canvas.winfo_width() or 600
        h = 210
        self.trend_canvas.delete('all')
        hist = self.state.get('history', [])
        if len(hist) < 2:
            self.trend_canvas.create_text(w//2, h//2, text='数据不足，暂不显示趋势',
                fill=C['text_dim'], font=('微软雅黑', 9))
            return
        # Count events per time bucket (last 20 points)
        display = hist[-20:]
        vals = []
        for item in display:
            count = sum(1 for k in item if k not in ('t','history') and isinstance(item[k], (int,float)))
            vals.append(count)
        if not vals: return
        max_v = max(vals) or 1
        bar_w = max(8, (w - 40) // len(vals))
        gap = max(2, (w - 40 - bar_w * len(vals)) // (len(vals) + 1))
        x0 = gap + 10
        colors = [C['green'], C['accent'], C['yellow'], C['purple'], C['red']]
        for i, v in enumerate(vals):
            bh = max(4, (v / max_v) * (h - 30))
            color = colors[i % len(colors)]
            self.trend_canvas.create_rectangle(
                x0 + i*(bar_w+gap), h - 15 - bh,
                x0 + i*(bar_w+gap) + bar_w, h - 15,
                fill=color, outline='', tags='bar')
            if v > 0:
                self.trend_canvas.create_text(
                    x0 + i*(bar_w+gap) + bar_w//2, h - 18 - bh,
                    text=str(v), fill=C['text_dim'], font=('Consolas', 7), tags='bar')

    # ── 快捷操作回调 ──
    def _switch_tab(self, idx):
        try:
            nb = self.parent.master
            if hasattr(nb, 'select'): nb.select(idx)
        except: pass

    def _get_ops_tab(self):
        if self.tabs and hasattr(self.tabs, 'ops'):
            return self.tabs.ops
        return None

    def q_ping(self):
        self.log_activity('快捷: 存活探测 — 请到 综合运维>存活探测 执行', 'cmd')
        self._switch_tab(5)

    def q_port(self):
        self.log_activity('快捷: 端口扫描 — 请到 综合运维>存活探测(端口模式)', 'cmd')
        self._switch_tab(5)

    def q_waf(self):
        self.log_activity('快捷: 部署WAF — 请到 WAF管理 输入目标后部署', 'cmd')
        self._switch_tab(1)

    def q_flag(self):
        self.log_activity('快捷: 获取Flag — 请到 Flag获取 配置目标后开始', 'cmd')
        self._switch_tab(2)

    def q_harden(self):
        self.log_activity('快捷: 一键加固 — 请到 综合运维>加固基线', 'cmd')
        self._switch_tab(5)

    def q_backup(self):
        self.log_activity('快捷: 备份网站 — 请到 综合运维>备份还原', 'cmd')
        self._switch_tab(5)
