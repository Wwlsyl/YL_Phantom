#!/usr/bin/env python3
"""
YL_Phantom 自动漏洞扫描 + 补丁修复模块
扫描靶机源码 → 识别漏洞 → 生成补丁 → 部署修复
"""
import os, re, json, requests, base64, sys, ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LIB_FILE = os.path.join(BASE, '防御模块', 'fix_library.json')

def load_library():
    with open(LIB_FILE, encoding='utf-8') as f:
        return json.load(f)['vulnerabilities']

def guess_lang(ext):
    ext_map = {
        '.php': 'php', '.php3': 'php', '.php4': 'php', '.php5': 'php', '.phtml': 'php',
        '.py': 'python', '.pyc': 'python',
        '.java': 'java', '.jsp': 'java', '.war': 'java',
        '.js': 'nodejs', '.mjs': 'nodejs',
        '.go': 'go',
    }
    return ext_map.get(ext.lower())

class VulnScanner:
    def __init__(self):
        self.lib = load_library()
        self.findings = []
        self.stats = {'scanned': 0, 'found': 0}

    def scan_file(self, filepath, content=None):
        ext = os.path.splitext(filepath)[1]
        lang = guess_lang(ext)
        if not lang:
            return []
        if content is None:
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
            except:
                return []
        results = []
        for vuln in self.lib:
            if vuln['lang'] != lang:
                continue
            pattern = vuln.get('pattern', '')
            if not pattern:
                continue
            try:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for m in matches:
                    line_num = content[:m.start()].count('\n') + 1
                    ctx_start = max(0, m.start() - 40)
                    ctx_end = min(len(content), m.end() + 60)
                    context = content[ctx_start:ctx_end].replace('\n', ' ')
                    results.append({
                        'vuln_id': vuln['id'],
                        'name': vuln['name'],
                        'severity': vuln['severity'],
                        'file': filepath,
                        'line': line_num,
                        'match': m.group()[:80],
                        'context': context.strip(),
                        'fix': vuln['fix'],
                        'dangerous_funcs': vuln['dangerous_funcs'],
                    })
                    self.stats['found'] += 1
            except re.error:
                continue
        self.stats['scanned'] += 1
        return results

    def scan_directory(self, directory):
        self.findings = []
        self.stats = {'scanned': 0, 'found': 0}
        scan_exts = {'.php','.php3','.php4','.php5','.phtml','.py','.java','.jsp','.js','.go'}
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ('vendor','node_modules','__pycache__','venv')]
            for f in files:
                ext = os.path.splitext(f)[1]
                if ext in scan_exts:
                    fp = os.path.join(root, f)
                    findings = self.scan_file(fp)
                    self.findings.extend(findings)
        return self.findings

    def scan_remote(self, ip, port, shell_url, shell_pass, https=False, timeout=10):
        proto = 'https' if https else 'http'
        base = f'{proto}://{ip}:{port}' if port != 80 else f'{proto}://{ip}'
        ws_url = base + shell_url
        session = requests.Session()
        session.headers.update({'User-Agent': 'Mozilla/5.0'})
        findings = []

        cmds = [
            "find /var/www/html -type f \\( -name '*.php' -o -name '*.py' -o -name '*.jsp' -o -name '*.js' \\) 2>/dev/null | head -100",
            "ls -la /var/www/html/ 2>/dev/null",
        ]
        files = []
        for cmd in cmds:
            try:
                r = session.post(ws_url, data={shell_pass: cmd}, timeout=timeout)
                if r.status_code == 200:
                    for line in r.text.split('\n'):
                        line = line.strip()
                        if line and line.endswith(('.php','.py','.jsp','.js')):
                            files.append(line)
            except:
                pass

        for fp in list(set(files))[:50]:
            try:
                cmd = f"cat {fp}"
                r = session.post(ws_url, data={shell_pass: cmd}, timeout=timeout)
                if r.status_code == 200 and r.text.strip():
                    findings.extend(self.scan_file(fp, r.text))
            except:
                pass

        for f in findings:
            f['remote_ip'] = ip
            f['remote_file'] = f.pop('file', '')

        self.findings.extend(findings)
        return findings

    def summary(self):
        if not self.findings:
            return "未发现漏洞"
        by_sev = {}
        for f in self.findings:
            s = f['severity']
            by_sev[s] = by_sev.get(s, 0) + 1
        lines = [f"扫描文件: {self.stats['scanned']} | 发现漏洞: {self.stats['found']}"]
        for sev in ['critical','high','medium','low']:
            if sev in by_sev:
                lines.append(f"  [{sev.upper()}] {by_sev[sev]} 个")
        return '\n'.join(lines)

    def report_text(self):
        out = []
        for i, f in enumerate(self.findings, 1):
            out.append(f"[{i}] [{f['severity'].upper()}] {f['name']}")
            out.append(f"    文件: {f.get('remote_file', f.get('file','?'))}:{f['line']}")
            out.append(f"    匹配: {f['match']}")
            out.append(f"    快速修复: {f['fix']['fast']}")
            out.append(f"    安全修复: {f['fix']['secure']}")
            out.append("")
        return '\n'.join(out)


def scan_local(path):
    s = VulnScanner()
    s.scan_directory(path)
    return s


def scan_remote(ip, port=80, shell_url='/shell.php', shell_pass='cmd', https=False):
    s = VulnScanner()
    s.scan_remote(ip, port, shell_url, shell_pass, https)
    return s


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='YL_Phantom 自动漏洞扫描')
    parser.add_argument('--path', help='本地源码路径')
    parser.add_argument('--ip', help='远程靶机IP')
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--shell-url', default='/shell.php')
    parser.add_argument('--pass', dest='shell_pass', default='cmd')
    parser.add_argument('--https', action='store_true')
    args = parser.parse_args()

    if args.path:
        s = scan_local(args.path)
        print(s.summary())
        print('=' * 50)
        print(s.report_text())
    elif args.ip:
        s = scan_remote(args.ip, args.port, args.shell_url, args.shell_pass, args.https)
        print(s.summary())
        print('=' * 50)
        print(s.report_text())
    else:
        parser.print_help()
