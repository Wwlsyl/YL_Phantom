<?php
// WAF Strong v2.1 — Admin Dashboard (独立版)
header('Content-Type:text/html;charset=utf-8');
$pwd='y|lladmin121.@ss';$log=__DIR__.'/.waf.log';
$a=$_GET['a']??'';$p=$_POST['p']??'';

function auth(){
    global$pwd;
    if(($_GET['u']??'')!=='waf'||($_GET['p']??'')!==$pwd){
        if(($_POST['u']??'')!=='waf'||$_POST['p']!==$pwd){
            echo'<!DOCTYPE html><html><head><meta charset="utf-8"><title>WAF Login</title>
            <style>*{margin:0;padding:0}body{background:#0f0f1a;display:flex;height:100vh;align-items:center;justify-content:center;font-family:sans-serif}
            .box{background:#1a1a2e;padding:40px;border-radius:12px;width:340px;text-align:center}
            h1{color:#48dbfb;margin-bottom:24px;font-size:20px}
            input{width:100%;padding:12px;margin:8px 0;background:#16213e;border:1px solid #333;border-radius:6px;color:#fff;font-size:14px;outline:none}
            input:focus{border-color:#48dbfb}
            button{width:100%;padding:12px;background:#48dbfb;color:#000;border:none;border-radius:6px;font-size:15px;font-weight:bold;cursor:pointer;margin-top:12px}
            button:hover{background:#0abde3}
            .hint{color:#8395a7;font-size:12px;margin-top:12px}
            </style></head><body>
            <div class="box"><h1>WAF Strong 管理面板</h1>
            <form method="POST"><input type="text" name="u" placeholder="用户名" autocomplete="off">
            <input type="password" name="p" placeholder="密码">
            <button type="submit">登录</button></form>
            <p class="hint">默认账号: waf / y|lladmin121.@ss</p></div></body></html>';exit;
        }
    }
}

if(!isset($_GET['ajax']))auth();

// ── 获取日志数据 ──
$lines=[];$total=0;$ip_stats=[];
if(file_exists($log)){
    $raw=@file_get_contents($log);
    if($raw){$all=explode("\n",trim($raw));$total=count($all);
    $lines=array_slice(array_reverse($all),0,300);
    foreach($all as$ln){
        if(preg_match('/\[([^\]]+)\]/',$ln,$m)){$ip=$m[1];
        $ip_stats[$ip]=($ip_stats[$ip]??0)+1;}}
    }
}
arsort($ip_stats);$top_ips=array_slice($ip_stats,0,10);

// ── 分类统计 ──
$cats=['sqli'=>0,'xss'=>0,'rce'=>0,'lfi'=>0,'other'=>0];
$cat_labels=['sqli'=>'SQL注入','xss'=>'XSS','rce'=>'RCE/命令','lfi'=>'文件包含','other'=>'其他'];
foreach($lines as$ln){
    if(preg_match('/SQLi|SQLcom/',$ln))$cats['sqli']++;
    elseif(preg_match('/XSS/',$ln))$cats['xss']++;
    elseif(preg_match('/RCE|shell|b64/',$ln))$cats['rce']++;
    elseif(preg_match('/LFI/',$ln))$cats['lfi']++;
    else $cats['other']++;
}

if(isset($_GET['ajax'])){header('Content-Type:application/json');
echo json_encode(['total'=>$total,'cats'=>$cats,'top_ips'=>$top_ips,'lines'=>array_slice($lines,0,100)]);exit;}

// ── HTML ──
?><!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>WAF Strong Admin</title>
<style>*{margin:0;padding:0;box-sizing:border-box}
body{background:#0f0f1a;color:#c8d6e5;font-family:"Segoe UI","Microsoft YaHei",sans-serif;padding:20px;min-height:100vh}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;flex-wrap:wrap;gap:12px}
.header h1{color:#48dbfb;font-size:24px}.header h1 span{color:#ff6b6b;font-size:13px;font-weight:normal}
.header .info{color:#8395a7;font-size:13px}
.dash{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.card{background:#1a1a2e;border-radius:12px;padding:18px;text-align:center;transition:transform .2s}
.card:hover{transform:translateY(-2px)}
.card .num{font-size:30px;font-weight:bold}
.card .lbl{font-size:12px;color:#8395a7;margin-top:6px}
.c0 .num{color:#48dbfb}.c1 .num{color:#ff6b6b}.c2 .num{color:#feca57}.c3 .num{color:#ff9ff3}.c4 .num{color:#54a0ff}.c5 .num{color:#5f27cd}
.row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:24px}
@media(max-width:700px){.row{grid-template-columns:1fr}}
.panel{background:#1a1a2e;border-radius:12px;padding:18px}
.panel h2{font-size:15px;color:#ff9f43;margin-bottom:12px}
.panel ul{list-style:none}.panel li{padding:5px 0;font-size:13px;border-bottom:1px solid #1e1e36;display:flex;justify-content:space-between}
.panel li span{color:#8395a7;font-size:12px}
.wrap{background:#1a1a2e;border-radius:12px;overflow:hidden}
.wrap table{width:100%;border-collapse:collapse;font-size:12px}
.wrap th{background:#0abde3;color:#000;padding:8px 14px;text-align:left;font-size:12px}
.wrap td{padding:6px 14px;border-bottom:1px solid #1e1e36;font-family:monospace;word-break:break-all;line-height:1.4}
.wrap tr:hover{background:#16213e}
.sqli td{color:#ff6b6b!important}.xss td{color:#feca57!important}.rce td{color:#ff9ff3!important}.lfi td{color:#54a0ff!important}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:10px;margin-right:6px}
.b-sqli{background:#ff6b6b33;color:#ff6b6b}.b-xss{background:#feca5733;color:#feca57}.b-rce{background:#ff9ff333;color:#ff9ff3}.b-lfi{background:#54a0ff33;color:#54a0ff}.b-other{background:#8395a733;color:#8395a7}
.ft{color:#8395a7;font-size:11px;margin-top:16px;text-align:center}
</style></head><body>
<div class="header"><h1>WAF Strong <span>v2.1 管理面板</span></h1><div class="info">实时监控 · <span id="uptime">-</span></div></div>

<div class="dash" id="dash">
    <div class="card c0"><div class="num" id="t1"><?=$total?></div><div class="lbl">拦截总数</div></div>
    <div class="card c1"><div class="num" id="t2"><?=$cats['sqli']?></div><div class="lbl">SQL注入</div></div>
    <div class="card c2"><div class="num" id="t3"><?=$cats['xss']?></div><div class="lbl">XSS</div></div>
    <div class="card c3"><div class="num" id="t4"><?=$cats['rce']?></div><div class="lbl">RCE/命令</div></div>
    <div class="card c4"><div class="num" id="t5"><?=$cats['lfi']?></div><div class="lbl">文件包含</div></div>
    <div class="card c5"><div class="num" id="t6"><?=$cats['other']?></div><div class="lbl">其他</div></div>
</div>

<div class="row">
    <div class="panel"><h2>Top 10 攻击IP</h2><ul id="iplist">
    <?php foreach($top_ips as $ip=>$c):?>
    <li><?=htmlspecialchars($ip)?> <span><?=$c?>次</span></li>
    <?php endforeach;?>
    </ul></div>
    <div class="panel"><h2>防护概况</h2>
    <ul><li>限速 <span>300次/分钟/IP</span></li>
    <li>Null字节 <span>已开启</span></li>
    <li>JSON检测 <span>已开启</span></li>
    <li>多层解码 <span>URL→HTML→Unicode</span></li>
    <li>Base64检测 <span>24+字符自动解码</span></li>
    <li>Flag替换 <span>响应中自动混淆</span></li></ul></div>
</div>

<div class="wrap"><table><thead><tr><th style="width:70px">类型</th><th>拦截日志 (最新300条)</th></tr></thead>
<tbody id="logbody">
<?php foreach($lines as $ln):
$cls='other';if(preg_match('/SQLi|SQLcom/',$ln))$cls='sqli';
elseif(preg_match('/XSS/',$ln))$cls='xss';
elseif(preg_match('/RCE|shell|b64/',$ln))$cls='rce';
elseif(preg_match('/LFI/',$ln))$cls='lfi';
$tag=$cat_labels[$cls]??'其他';
$short=mb_substr($ln,0,120);
?><tr class="<?=$cls?>"><td><span class="badge b-<?=$cls?>"><?=$tag?></span></td><td><?=htmlspecialchars($short)?></td></tr>
<?php endforeach;?>
</tbody></table></div>
<div class="ft">数据自动刷新 <span id="timer">5s</span></div>
<script>
function refresh(){
fetch('?ajax=1&u=waf&p=y|lladmin121.@ss').then(r=>r.json()).then(d=>{
document.getElementById('t1').textContent=d.total;
document.getElementById('t2').textContent=d.cats.sqli;
document.getElementById('t3').textContent=d.cats.xss;
document.getElementById('t4').textContent=d.cats.rce;
document.getElementById('t5').textContent=d.cats.lfi;
document.getElementById('t6').textContent=d.cats.other;
var iph='';for(var k in d.top_ips){iph+='<li>'+k+' <span>'+d.top_ips[k]+'次</span></li>'}
document.getElementById('iplist').innerHTML=iph;
var lb='';d.lines.forEach(function(l){
var cls='other',tag='其他';
if(/SQLi|SQLcom/.test(l)){cls='sqli';tag='SQL注入'}
else if(/XSS/.test(l)){cls='xss';tag='XSS'}
else if(/RCE|shell|b64/.test(l)){cls='rce';tag='RCE'}
else if(/LFI/.test(l)){cls='lfi';tag='LFI'}
lb+='<tr class="'+cls+'"><td><span class="badge b-'+cls+'">'+tag+'</span></td><td>'+l.slice(0,120)+'</td></tr>'});
document.getElementById('logbody').innerHTML=lb;
document.getElementById('uptime').textContent=new Date().toLocaleTimeString();
});
}
setInterval(refresh,5000);
refresh();
</script></body></html>
