#!/usr/bin/env python3
"""
batch_runner.py — 批量exp执行+自动提交
auto-awd 风格的批量攻击框架
"""
import subprocess, threading, time, re, os, sys, json, requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class BatchRunner:
    def __init__(self, targets=None, exploit_cmd=None, flag_regex=r'flag\{[^}]+\}', submit_url=None, submit_token=None):
        self.targets = targets or []
        self.exploit_cmd = exploit_cmd
        self.flag_regex = flag_regex
        self.submit_url = submit_url
        self.submit_token = submit_token
        self.results = {}
        self.flags = []
        self._lock = threading.Lock()

    def add_target(self, ip, port, extra=None):
        self.targets.append({'ip': ip, 'port': port, 'extra': extra or {}})

    def load_targets(self, filepath, fmt='ip:port'):
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                if fmt == 'ip:port':
                    parts = line.split(':')
                    self.add_target(parts[0], int(parts[1]))
                elif fmt == 'url':
                    self.add_target(line, 80, {'url': line})

    def set_exploit(self, cmd_template):
        """cmd_template 中用 {ip} {port} 作为占位符"""
        self.exploit_cmd = cmd_template

    def run_single(self, target):
        ip = target['ip']; port = target['port']
        cmd = self.exploit_cmd.format(ip=ip, port=port, **target.get('extra', {}))
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = r.stdout + r.stderr
            flags = re.findall(self.flag_regex, output, re.I)
            with self._lock:
                self.results[f'{ip}:{port}'] = {'status': 'ok' if r.returncode == 0 else 'fail', 'output': output[:500], 'flags': flags}
                self.flags.extend(flags)
            return flags
        except subprocess.TimeoutExpired:
            with self._lock:
                self.results[f'{ip}:{port}'] = {'status': 'timeout', 'output': '', 'flags': []}
            return []
        except Exception as e:
            with self._lock:
                self.results[f'{ip}:{port}'] = {'status': 'error', 'output': str(e), 'flags': []}
            return []

    def run_all(self, max_workers=10):
        self.flags = []
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(self.run_single, t): t for t in self.targets}
            for f in as_completed(futures):
                pass
        return self.results

    def submit_flags(self, flag_format=None):
        if not self.submit_url:
            return []
        submitted = []
        flags_to_submit = set(self.flags)
        if flag_format:
            flags_to_submit = {flag_format.format(flag=f) for f in flags_to_submit}
        for flag in flags_to_submit:
            try:
                if self.submit_token:
                    r = requests.post(self.submit_url, json={'flag': flag, 'token': self.submit_token}, timeout=10)
                else:
                    r = requests.post(self.submit_url, data={'flag': flag}, timeout=10)
                submitted.append({'flag': flag, 'status': 'ok', 'code': r.status_code})
            except Exception as e:
                submitted.append({'flag': flag, 'status': 'error', 'error': str(e)})
        return submitted

    def summary(self):
        total = len(self.targets)
        ok = sum(1 for v in self.results.values() if v['status'] == 'ok')
        fail = sum(1 for v in self.results.values() if v['status'] != 'ok')
        unique_flags = len(set(self.flags))
        return f'目标: {total}, 成功: {ok}, 失败: {fail}, 去重Flag: {unique_flags}'

if __name__ == '__main__':
    br = BatchRunner(submit_url='http://127.0.0.1:19999/api/flag', submit_token='test')
    br.add_target('10.0.0.1', 80)
    br.set_exploit('python exploit.py {ip} {port}')
    br.run_all(max_workers=5)
    print(br.summary())
