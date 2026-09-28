<?php
/* YL WAF IP黑名单 CLI 管理: php waf_ban.php add|del|list [ip]
 * 直接读改写 .waf.dat.php(含HMAC签名), 不经过HTTP, 绕平台层
 * 密钥部署时由平台随机注入, 与 waf_strong.php 保持一致
 */
if (php_sapi_name() !== 'cli') { @header('HTTP/1.1 403 Forbidden'); exit('403'); }
$ks = '__YL_WAF_SIGKEY__';
$w = __DIR__ . '/.waf.dat.php';
if (!file_exists($w)) $w = __DIR__ . '/.waf.dat'; /* 兼容旧名 */
$do = isset($argv[1]) ? $argv[1] : 'list';
$ip = isset($argv[2]) ? trim($argv[2]) : '';
$h = @file_get_contents($w);
if (!$h || !preg_match('~^<\?php \$K="([^"]*)"~', $h, $m)) { echo 'NO_DAT'; exit; }
$J = json_decode(base64_decode($m[1]), true);
if (!is_array($J)) { echo 'BAD_DAT'; exit; }
if (!isset($J['K']) || !is_array($J['K'])) $J['K'] = array();
if ($do === 'add' && $ip !== '' && !in_array($ip, $J['K'], true)) { $J['K'][] = $ip; }
elseif ($do === 'del' && $ip !== '') { $J['K'] = array_values(array_diff($J['K'], array($ip))); }
$b = base64_encode(json_encode($J));
$sig = hash_hmac('sha256', $b, $ks);
@file_put_contents($w, '<?php $K="' . $b . '";#SIG=' . $sig . "\n");
echo 'OK:' . implode(',', $J['K']);
