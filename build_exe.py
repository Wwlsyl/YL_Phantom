#!/usr/bin/env python3
import os, sys, shutil, subprocess

BASE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(BASE, 'dist')

gui_src = os.path.join(BASE, '..', '管理工具', 'awd_toolkit_gui.py')
gui_dst = os.path.join(BASE, 'main.py')
if os.path.exists(gui_src):
    shutil.copy2(gui_src, gui_dst)
    print(f'[+] GUI synced: {gui_dst}')

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
    gui_dst,
]

print('\n[+] Building exe...')
ret = subprocess.run(cmd)
if ret.returncode != 0:
    print('\n[!] PyInstaller failed, check errors above')
    sys.exit(1)

for d in ['build', '__pycache__']:
    p = os.path.join(BASE, d)
    if os.path.exists(p): shutil.rmtree(p)
for f in ['YL_Phantom.spec']:
    p = os.path.join(BASE, f)
    if os.path.exists(p): os.remove(p)

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
