<?php
/* YL WAF Strong v3.1 — auto_prepend 拦截引擎 + 管理面板
 * v3.1: 密钥部署时随机注入(占位符__YL_WAF_SIGKEY__) / 配置改名 .waf.dat.php 防HTTP下载
 *       规则引擎升级: 空白符归一化+去空格匹配 / $_FILES内容扫描 / base64短串(16位起)
 *       管理面板统一从 .waf.dat.php 的 P 字段鉴权, 不再硬编码默认密码
 * 强度 S: 1=标准 2=严格 3=白名单模式(仅白名单IP可访问)
 * 配置 .waf.dat.php: {"I":[...],"X":[...],"R":[...],"L":[...],"B":[...],"H":[...],"S":1,"W":["1.2.3.4"],"P":"管理密码"}
 * 免检: u=monitor 监控页 / u=waf&p=正确密码 管理页 / 白名单IP
 */
$F=__DIR__;$W="$F/.waf.dat.php";$W2="$F/.waf.dat";$L="$F/.waf.log";
/* 内置签名密钥(部署时由平台随机生成替换, 不要写入配置) */
$KS='__YL_WAF_SIGKEY__';
$D=array();$CONF=0;
$H=@file_get_contents($W);
if(!$H||strlen($H)<=10){$H=@file_get_contents($W2);} /* 兼容旧 .waf.dat */
if($H&&strlen($H)>10){
 if(preg_match('~^<\?php \$K="([^"]*)"\s*;\s*#SIG=([0-9a-f]{64})\s*$~s',$H,$m)){
  $cal=hash_hmac('sha256',$m[1],$KS);
  if($cal===$m[2]){
   $J=json_decode(base64_decode($m[1]),true);if(is_array($J)){$D=$J;$CONF=1;}
  }
 }elseif(preg_match('~^<\?php \$K="([^"]*)"\s*;$~s',$H,$m)){
  $J=json_decode(base64_decode($m[1]),true);if(is_array($J)){$D=$J;$CONF=2;}
 }
}
/* fail-closed: 配置缺失/损坏/签名不符 → 一律403, 等自愈恢复 */
if($CONF===0){@header('HTTP/1.1 403 Forbidden');die('403');}
$S=isset($D['S'])?intval($D['S']):1;
$ALLOW=isset($D['W'])&&is_array($D['W'])?$D['W']:array();
$IP=isset($_SERVER['REMOTE_ADDR'])?$_SERVER['REMOTE_ADDR']:'';
if($IP!==''&&in_array($IP,$ALLOW,true))$S=0;
/* 黑名单 K: 任何请求(含管理/监控)都先查, 命中直接403 */
$BAN=isset($D['K'])&&is_array($D['K'])?$D['K']:array();
if($IP!==''&&in_array($IP,$BAN,true))w3die('ipban');

function w3log($tag){
 global $L,$IP;
 $m=isset($_SERVER['REQUEST_METHOD'])?$_SERVER['REQUEST_METHOD']:'-';
 $q=isset($_SERVER['REQUEST_URI'])?substr($_SERVER['REQUEST_URI'],0,300):'-';
 @file_put_contents($L,"[$IP] [".date('Y-m-d H:i:s')."] BLOCK($tag) $m $q\n",FILE_APPEND|LOCK_EX);
}
function w3die($tag){w3log($tag);@header('HTTP/1.1 403 Forbidden');die('403');}
/* 空白符归一化: 控制字符/URL编码空白/HTML实体空白 → 空格, 堵 %09 %0a %a0 等绕过 */
function w3norm($s){
 $s=(string)$s;
 $s=preg_replace('/[\x00-\x20\x7f\xc2\xa0\xe2\x80\x8b]+/',' ',$s);
 $s=preg_replace('/%(09|0a|0b|0c|0d|1b|00|20|a0|80|8b)/i',' ',$s);
 $s=preg_replace('/&#x(09|0a|0b|0c|0d|1b|00|20|a0|80|8b);/i',' ',$s);
 $s=preg_replace('/&#(9|10|11|12|13|27|32|160|8203);/i',' ',$s);
 return $s;
}
/* 规则扫描: 先归一化, 原样匹配失败再"去所有空白"匹配(堵 tab/换行插缝), 大小写不敏感 */
function w3scan($data,$rules){
 if($data===''||empty($rules))return false;
 $data=w3norm($data);
 $low=strtolower($data);
 $ns=preg_replace('/\s+/','',$low);
 foreach($rules as$kw){
  if($kw==='')continue;
  $kw=strtolower($kw);
  if(strpos($low,$kw)!==false)return true;
  if(strpos($ns,str_replace(' ','',$kw))!==false)return true;
 }
 return false;
}
function w3scan_b64($data,$rules){
 if($data===''||empty($rules))return false;
 if(preg_match_all('/[A-Za-z0-9+\/]{16,}={0,2}/',$data,$mm)){
  foreach($mm[0]as$b){$d=@base64_decode($b);if($d!==false&&$d!==''&&w3scan($d,$rules))return true;}
 }
 return false;
}

$u=isset($_GET['u'])?$_GET['u']:'';
$p=isset($_GET['p'])?$_GET['p']:'';
/* 管理密码从 .waf.dat.php 的 P 字段读取, 无配置则不允许进入管理 */
$PASS=(isset($D['P'])&&$D['P']!=='')?$D['P']:'';
$ISADMIN=($u==='waf'&&$PASS!==''&&$p===$PASS);

/* 管理动作: ?u=waf&p=PASS&act=ban&do=add|del|list&ip=X  (签名写回配置) */
if($ISADMIN&&isset($_GET['act'])&&$_GET['act']==='ban'){
 $nb=isset($D['K'])&&is_array($D['K'])?$D['K']:array();
 $do=isset($_GET['do'])?$_GET['do']:'list';
 $t_ip=trim(isset($_GET['ip'])?$_GET['ip']:'');
 if($do==='add'&&$t_ip!==''&&!in_array($t_ip,$nb,true)){
  $nb[]=$t_ip;$D['K']=$nb;
  $b=base64_encode(json_encode($D));$sig=hash_hmac('sha256',$b,$KS);
  @file_put_contents($W,'<?php $K="'.$b.'";#SIG='.$sig."\n");
 }elseif($do==='del'&&$t_ip!==''){
  $nb=array_values(array_diff($nb,array($t_ip)));$D['K']=$nb;
  $b=base64_encode(json_encode($D));$sig=hash_hmac('sha256',$b,$KS);
  @file_put_contents($W,'<?php $K="'.$b.'";#SIG='.$sig."\n");
 }
 @header('Content-Type: application/json');
 echo json_encode(array('ok'=>true,'do'=>$do,'list'=>$nb));exit;
}

if($u!=='monitor'&&!$ISADMIN){
 if($S>=3){w3die('whitelist');}
 $M=isset($_SERVER['REQUEST_METHOD'])?$_SERVER['REQUEST_METHOD']:'';
 if($S>=2){
  if(!in_array($M,array('GET','POST','HEAD'),true))w3die('method');
  if(isset($_SERVER['CONTENT_LENGTH'])&&intval($_SERVER['CONTENT_LENGTH'])>1048576)w3die('size');
  if($M==='GET'&&(!isset($_SERVER['HTTP_USER_AGENT'])||trim($_SERVER['HTTP_USER_AGENT'])===''))w3die('ua');
 }
 if($S>=1){
  $I=isset($D['I'])?$D['I']:array();
  $X=isset($D['X'])?$D['X']:array();
  $R=isset($D['R'])?$D['R']:array();
  $L2=isset($D['L'])?$D['L']:array();
  $B=isset($D['B'])?$D['B']:array();
  $Q=isset($_SERVER['QUERY_STRING'])?$_SERVER['QUERY_STRING']:'';
  $RAW='';
  if($M==='POST'){$RAW=@file_get_contents('php://input');}
  $in=array();
  if(isset($_GET)&&is_array($_GET))$in=array_merge($in,$_GET);
  if(isset($_POST)&&is_array($_POST))$in=array_merge($in,$_POST);
  if(isset($_COOKIE)&&is_array($_COOKIE))$in=array_merge($in,$_COOKIE);
  $samples=array();
  foreach($in as$k=>$v){if(is_scalar($v)&&$v!==''&&$v!==null)$samples[]=$v;}
  /* $_FILES 内容扫描: 文件名 + 文件内容前64KB (堵上传webshell/图片马) */
  if(isset($_FILES)&&is_array($_FILES)){
   foreach($_FILES as$fk=>$fv){
    if(!is_array($fv))continue;
    if(isset($fv['name'])&&is_scalar($fv['name']))$samples[]='FILE_NAME='.$fv['name'];
    if(isset($fv['tmp_name'])&&$fv['tmp_name']!==''&&is_file($fv['tmp_name'])){
     $fc=@file_get_contents($fv['tmp_name'],false,null,0,65536);
     if($fc!==false&&$fc!=='')$samples[]=$fc;
    }
   }
  }
  $samples[]=$Q;
  if($RAW!=='')$samples[]=$RAW;           /* RAW body 无条件扫描(JSON等不走$_POST的) */
  if($S>=2){$samples[]=urldecode($Q);}
  foreach($samples as$s){
   if(!is_string($s))continue;
   if(w3scan($s,$I))w3die('SQLi');
   if(w3scan($s,$X))w3die('XSS');
   if(w3scan($s,$R))w3die('RCE');
   if(w3scan($s,$L2))w3die('LFI');
   if($S>=2&&w3scan_b64($s,$B))w3die('b64');
  }
 }
}

if($ISADMIN){
$r=@file_get_contents($L);$ls=$r?explode("\n",trim($r)):array();
$ls=array_slice(array_reverse($ls),0,200);$h='';$c=0;$ips=array();
foreach($ls as$n){$c++;if(preg_match("/\[([^\]]+)\]/",$n,$m)){$k=$m[1];$ips[$k]=isset($ips[$k])?$ips[$k]+1:1;}
$cl='';if(strpos($n,'SQLi')!==false)$cl=' class="s"';
if(strpos($n,'XSS')!==false)$cl=' class="x"';
if(strpos($n,'LFI')!==false)$cl=' class="l"';
if(strpos($n,'RCE')!==false)$cl=' class="r"';
if(strpos($n,'b64')!==false)$cl=' class="x"';
if(strpos($n,'whitelist')!==false||strpos($n,'method')!==false||strpos($n,'size')!==false||strpos($n,'ua')!==false)$cl=' class="b"';
$h="<div$cl>$n</div>$h";}
if(isset($_GET['ajax'])){
echo json_encode(array('html'=>$h,'total'=>$c,'ips'=>$ips));exit;}
?><!DOCTYPE html>
<html><head><meta charset="utf-8"><title>WAF Monitor</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,sans-serif;padding:16px}
h1{color:#58a6ff;font-size:20px}
.dash{display:flex;gap:10px;margin:12px 0}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px 20px;text-align:center;flex:1}
.card .n{font-size:24px;color:#58a6ff;font-weight:bold}
.card .l{font-size:11px;color:#8b949e;margin-top:4px}
#log{background:#161b22;border:1px solid #30363d;border-radius:8px;font-family:monospace;font-size:12px;height:500px;overflow:auto;padding:10px}
#log .s{color:#f85149}#log .x{color:#d29922}#log .l{color:#d2a8ff}#log .r{color:#ff7b72}#log .u{color:#7ee787}#log .b{color:#8b949e}
#log::-webkit-scrollbar{width:6px}#log::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}
</style></head><body>
<h1>WAF Strong v3.1 Monitor <span style="color:#8b949e;font-size:13px">引擎已启用</span></h1>
<div class="dash">
<div class="card"><div class="n" id="ct">0</div><div class="l">拦截总数</div></div>
<div class="card"><div class="n" id="ci">0</div><div class="l">攻击IP</div></div>
</div>
<div id="log"></div>
<script>
const L=document.getElementById('log');let P=0;
async function p(){try{
let r=await fetch('?u=waf&p=<?=$p?>&ajax=1&_='+Date.now());let d=await r.json();
if(d.html){L.innerHTML=d.html;document.getElementById('ct').textContent=d.total||0;
document.getElementById('ci').textContent=Object.keys(d.ips||{}).length;}}catch(e){}
setTimeout(p,3000);}p();
</script></body></html>
<?php }
