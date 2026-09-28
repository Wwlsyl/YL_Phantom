#!/usr/bin/env python3
"""用 main_work.py（新版带全局SSH栏）打包 YL_Phantom.exe"""
import os, sys, shutil, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(BASE, 'dist')

cmd = [
    sys.executable, '-m', 'PyInstaller',
    '--onefile',
    '--windowed',
    '--name', 'YL_Phantom',
    '--distpath', DIST,
    '--specpath', BASE,
    '--workpath', os.path.join(BASE, 'build'),
    '--icon', os.path.join(BASE, 'icon.ico'),
    '--add-data', f'{os.path.join(BASE, "rsa_keys.json")}{os.pathsep}.',
    '--add-data', f'{os.path.join(BASE, "攻击模块")}{os.pathsep}攻击模块',
    '--add-data', f'{os.path.join(BASE, "防御模块")}{os.pathsep}防御模块',
    '--add-data', f'{os.path.join(BASE, "上传靶机")}{os.pathsep}上传靶机',
    '--add-data', f'{os.path.join(BASE, "icon.png")}{os.pathsep}.',
    '--add-data', f'{os.path.join(BASE, "dashboard.py")}{os.pathsep}.',
    '--hidden-import', 'dashboard',
    '--hidden-import', 'rsa_crypto',
    '--hidden-import', 'phpggc_wrapper',
    '--hidden-import', 'dfunc_bypass',
    '--hidden-import', 'batch_runner',
    '--hidden-import', 'auto_fix',
    '--hidden-import', 'patch_deploy',
    '--collect-data', 'ttkbootstrap',
    '--hidden-import', 'ttkbootstrap',
    '--hidden-import', 'cryptography',
    '--hidden-import', 'PIL',
    os.path.join(BASE, 'main_work.py'),
]

print('\n[+] Building exe from main_work.py ...')
ret = subprocess.run(cmd)
if ret.returncode != 0:
    print('\n[!] PyInstaller failed, check errors above')
    sys.exit(1)

for d in ['build', '__pycache__']:
    p = os.path.join(BASE, d)
    if os.path.exists(p):
        shutil.rmtree(p)
for f in ['YL_Phantom.spec']:
    p = os.path.join(BASE, f)
    if os.path.exists(p):
        os.remove(p)

exe_path = os.path.join(DIST, 'YL_Phantom.exe')
if os.path.exists(exe_path):
    size_mb = os.path.getsize(exe_path) / 1024 / 1024
    root_exe = os.path.join(BASE, 'YL_Phantom.exe')
    shutil.copy2(exe_path, root_exe)
    print(f'\n[+] DONE! exe at: {exe_path}')
    print(f'[+] Size: {size_mb:.1f} MB')
    print(f'[+] Copied to: {root_exe}')
else:
    print('\n[!] Build failed, check errors above')
