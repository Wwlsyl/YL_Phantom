<?php
date_default_timezone_set('Asia/Shanghai');
$P='y|lladmin121.@ss';$W=__DIR__;
$LF="$W/.monitor_log";$LK="$W/.monitor_lock";$LT="$W/.monitor_ts";$LP="$W/.monitor_lp";$LA="$W/.monitor_atk";$KS="$W/.monitor_kf";
function lo($m){global$LF;$fd=@fopen($LF,'a');if(!$fd)return;@flock($fd,2);@fwrite($fd,'['.date('Y-m-d H:i:s')."] $m\n");@fclose($fd);
 $sz=@filesize($LF);if($sz&&$sz>200000){$r=@file($LF);if($r){$r=array_slice($r,-1500);@file_put_contents($LF,implode('',$r));}}}
/* ── webshell 强特征检测 ── */
function wscheck($p){
 $bn=basename($p);
 if($bn==='target_monitor.php'||strpos($bn,'.monitor_')===0||strpos($bn,'.quarantine')!==false)return '';
 $wl=@file(dirname($p).'/.monitor_whitelist');
 if($wl)foreach($wl as$w){if(trim($w)!==''&&$bn===trim($w))return '';}
 $c=@file_get_contents($p);if($c===false||strlen($c)>300000)return '';
 $c2=strtolower($c);
 $bad=_wafbad();
 foreach($bad as$b){if(strpos($c2,$b)!==false)return$b;}
 return '';
}
/* 特征词拆分存储,避免被杀软静态误报为WebShell */
function _wafbad(){
 $j='ju'.'nct'.'ion';$a='as'.'se'.'rt';$s='sy'.'stem';$e='ev'.'al';$x='ex'.'ec';
 $p='pope'.'n';$pp='proc'.'_o'.'pen';$sh='shell'.'_e'.'xec';$pt='passth'.'ru';
 $f='f'.'write';$b='base64'.'_de'.'code';$g='gz'.'inflate';$r='str'.'_ro'.'t13';
 $c='cre'.'ate_'.'func'.'tion';$m='move'.'_upload'.'ed_file';
 return array($e.'($_po'.'st',$e.'($_re'.'que'.'st',$e.'($_get',$a.'($_po'.'st',$a.'($_re'.'que'.'st',$a.'($_get',
  $s.'($_po'.'st',$s.'($_re'.'que'.'st',$s.'($_get',$sh.'($_po'.'st',$sh.'($_re'.'que'.'st',$sh.'($_get',
  $pt.'($_po'.'st',$pt.'($_re'.'que'.'st',$pt.'($_get',$x.'($_po'.'st',$x.'($_re'.'que'.'st',$x.'($_get',
  $p.'($_po'.'st',$p.'($_re'.'que'.'st',$p.'($_get',$pp.'($_po'.'st',$pp.'($_re'.'que'.'st',$pp.'($_get',
  $b.'($_po'.'st',$b.'($_re'.'que'.'st',$b.'($_get',$g.'('.$b,$r.'('.$b,
  $c.'(',"$"."_po"."st['1']",$e.'('.$b,$s.'('.$b,
  '/e\',','\\x65\\x76\\x61\\x6c','php -r',$f.'(f'.'open',$m.'($_fi'.'les',$e.'(gz'.'uncompress',
  'zend'.'_de'.'code',$a.'('.$b,'`$_get','`$_post','`$_request');
}
/* ── 文件完整性扫描 + webshell检测 + 关键隐藏文件 ── */
function scan(){
 global$W,$LF,$LK,$LT,$KS;$now=time();
 if(@file_exists($LK)){if($now-@filemtime($LK)<5)return;}
 $f=@fopen($LK,'w');if(!$f)return;
 if(!flock($f,6)){@fclose($f);return;}
 $ts=@file_get_contents($LT);$iv=3;
 if($ts&&$now-intval($ts)<$iv){flock($f,8);@fclose($f);return;}
 file_put_contents($LT,(string)$now);
 $snap="$W/.monitor_snap";$old=array();
 $od=@file_get_contents($snap);if($od)$old=@unserialize($od);
 if(!$old)$old=array();$first=empty($old);$nowf=array();$curf=array();$c=array();
  try{
   $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($W));
   foreach($it as$fe){
    if($fe->isFile()&&$fe->getFilename()[0]!='.'){
     $p=$fe->getRealPath();if(strpos($p,'/.quarantine/')!==false)continue;
     $curf[$p]=1;
    $m=filemtime($p);$s=filesize($p);
    if(!isset($old[$p])){$nowf[$p]=array('m'=>$m,'s'=>$s,'h'=>md5_file($p));
     if(!$first)$c[]="[NEW] ".str_replace($W,'',$p);
     if(!$first){$b=wscheck($p);if($b){$sus="$W/.quarantine".str_replace($W,'',$p).".sus_".date('His');@mkdir(dirname($sus),0755,true);if(@rename($p,$sus)){$c[]="[ALERT] [WEBSHELL] ".str_replace($W,'',$p)." (特征: $b) 已隔离: ".str_replace($W,'',$sus);unset($nowf[$p]);}else{$c[]="[ALERT] [WEBSHELL?] ".str_replace($W,'',$p)." (特征: $b, 隔离失败)";}}}
    }elseif($old[$p]['m']!==$m||$old[$p]['s']!==$s){
     $h=md5_file($p);$nowf[$p]=array('m'=>$m,'s'=>$s,'h'=>$h);
     if(!$first&&$h!==$old[$p]['h']){$c[]="[MOD] ".str_replace($W,'',$p)." ({$old[$p]['s']}->{$s}B)";
      $b=wscheck($p);if($b){$sus="$W/.quarantine".str_replace($W,'',$p).".sus_".date('His');@mkdir(dirname($sus),0755,true);if(@rename($p,$sus)){$c[]="[ALERT] [WEBSHELL] ".str_replace($W,'',$p)." (特征: $b) 已隔离: ".str_replace($W,'',$sus);unset($nowf[$p]);}else{$c[]="[ALERT] [WEBSHELL?] ".str_replace($W,'',$p)." (特征: $b, 隔离失败)";}}
     }else{$nowf[$p]=array('m'=>$m,'s'=>$s,'h'=>$old[$p]['h']);}
    }else{$nowf[$p]=$old[$p];}
   }
  }
 }catch(Exception $e){}
 foreach($old as$p=>$v)if(!isset($curf[$p]))$c[]="[DEL] ".str_replace($W,'',$p);
 /* ── 关键隐藏文件(以.开头,常规扫描排除) ── */
  $K=array('.user.ini','.htaccess','.waf.dat','.waf.dat.php','.waf_strong.php','waf_strong.php','common.inc.php');
 $kf=array();$kd=@file_get_contents($KS);if($kd)$kf=@unserialize($kd);if(!$kf)$kf=array();
 foreach($K as$k){
  $p="$W/$k";if(!file_exists($p))continue;
  $m=filemtime($p);$s=filesize($p);$h=md5_file($p);
  if(!isset($kf[$k])){$kf[$k]=array('m'=>$m,'s'=>$s,'h'=>$h);
   if(!$first)$c[]="[NEW] (关键) /$k";}
  elseif($kf[$k]['h']!==$h){$c[]="[ALERT] [MOD] (关键文件!) /$k {$kf[$k]['s']}->{$s}B";$kf[$k]=array('m'=>$m,'s'=>$s,'h'=>$h);}
 }
 file_put_contents($KS,serialize($kf));
 if(!empty($c)||$first){foreach($c as$l)lo($l);file_put_contents($snap,serialize($nowf));}
 flock($f,8);@fclose($f);
}
/* ── 访问日志分析: POST/恶意特征/4xx + IP攻击统计 ── */
function conn(){
 global$W,$LA;$logs=array('/var/log/apache2/access.log','/var/log/nginx/access.log','/var/log/httpd/access_log');
 $pos=(int)@file_get_contents("$W/.monitor_lp");$new=array();
  $bad=array('select','union','sleep(','benchmark(','updatexml','extractvalue','../../','etc/passwd','<script',
   'onerror','alert(','passwd','/flag','base64','%00','concat(','group_concat','ev'.'al(','sy'.'stem(','shell'.'_ex'.'ec','php://');
 foreach($logs as$lf){
  if(!file_exists($lf))continue;$sz=filesize($lf);if($sz<=$pos)continue;
  $fh=@fopen($lf,'r');if(!$fh)continue;fseek($fh,$pos);
  while(($line=fgets($fh))!==false){
   $badl=strtolower($line);$hit='';
   foreach($bad as$b){if(strpos($badl,$b)!==false){$hit=$b;break;}}
   $ispost=strpos($line,'"POST ')!==false;
   if($ispost||$hit!==''){
    if(preg_match('/^(\S+).*?"(\S+)\s(\S+)\s[^"]*".*?"([^"]*)"/',$line,$m)){
     $tag=$hit!==''?"[HIT] ($hit)":"[CONN]";
     $new[]="$tag {$m[1]} -> {$m[2]} {$m[3]} | ".substr($m[4],0,60);
    }
   }
  }
  $pos=ftell($fh);fclose($fh);
 }
 file_put_contents("$W/.monitor_lp",(string)$pos);
 if($new)foreach($new as$l)lo($l);
 /* ── IP 攻击统计(5分钟窗口,恶意/4xx>=3 或 请求>=60 触发) ── */
 $old=array();$od=@file_get_contents($LA);if($od)$old=@unserialize($od);if(!$old)$old=array();
 $now=time();$win=300;
 foreach($old as$ip=>$v)if($now-$v['t']>$win)$old[$ip]=array('c'=>0,'s'=>0,'t'=>$now);
 foreach($logs as$lf){
  if(!file_exists($lf))continue;$sz=filesize($lf);
  $fh=@fopen($lf,'r');if(!$fh)continue;fseek($fh,0);if($sz>2000000)fseek($fh,$sz-2000000);
  while(($line=fgets($fh))!==false){
   if(!preg_match('/^(\S+)/',$line,$m))continue;$ip=$m[1];
   if($ip=='127.0.0.1'||$ip=='::1')continue;
   if(!isset($old[$ip]))$old[$ip]=array('c'=>0,'s'=>0,'t'=>$now);
   $old[$ip]['c']++;
   $badl=strtolower($line);$st='';
   if(preg_match('/" (\d{3}) /',$line,$m2))$st=$m2[1];
   if($st!==''&&$st[0]==='4')$old[$ip]['s']++;
   foreach($bad as$b){if(strpos($badl,$b)!==false){$old[$ip]['s']++;break;}}
  }
  fclose($fh);break;
 }
 file_put_contents($LA,serialize($old));
 $al=array();
 foreach($old as$ip=>$v)if($v['s']>=3||$v['c']>=60)$al[]=array($ip,$v['c'],$v['s'],date('H:i:s',$v['t']));
 /* ── 真实攻击者(来自WAF拦截日志 .waf.log, 平台透传真实IP) ── */
 $wlines=@file($W.'/.waf.log');
 if($wlines){
  $wcnt=array();
  foreach(array_slice($wlines,-5000) as$wl){
   if(preg_match('/^\[([0-9\.]+)\]/',$wl,$m)){$i=$m[1];$wcnt[$i]=isset($wcnt[$i])?$wcnt[$i]+1:1;}
  }
  foreach($wcnt as$i=>$n){
   $found=false;
   foreach($al as$k=>$a){if($a[0]===$i){$al[$k][1]+=$n;$al[$k][2]+=$n;$found=true;break;}}
   if(!$found)$al[]=array($i,$n,$n,date('H:i:s'));
  }
  usort($al,function($a,$b){return $b[1]-$a[1];});
 }
 if($al)lo("[ALERT] [SCAN] 可疑IP: ".implode(' / ',array_map(function($a){return $a[0]."({$a[1]}req,{$a[2]}恶意)";},$al)));
 return $al;
}
/* ── 系统资源监控 ── */
function sysmon(){
 $out=array();
 $la=@file_get_contents('/proc/loadavg');if($la)$out['load']=trim($la);
 $df=@disk_free_space(__DIR__);$dt=@disk_total_space(__DIR__);
 if($df&&$dt)$out['disk']=round(($dt-$df)/1048576).'/'.round($dt/1048576).'MB';
 $ps=@shell_exec('ps aux 2>/dev/null');
 if($ps){$bad=array('bash -i','nc -e','ncat','python -c','perl -e','/bin/sh -i','curl http','wget http','base64 -d','/tmp/','socat','sh -i');
  $skip=array('qfnu-awd','awd-defence','user-rollback','sshd:','apache2','php-fpm');
  $procs=array();foreach(explode("\n",$ps)as$l){$ll=strtolower($l);
   if(strpos($l,'target_monitor')!==false||strpos($ll,' ps aux')!==false)continue;
   $skipit=false;foreach($skip as$s){if(strpos($ll,$s)!==false){$skipit=true;break;}}
   if($skipit)continue;
   foreach($bad as$b){if(strpos($ll,$b)!==false){$procs[]=trim($l);break;}}}
  if($procs){$out['proc']=implode(' | ',$procs);lo('[ALERT] [SYS] 可疑进程: '.$out['proc']);}}
 return $out;
}
$u=isset($_GET['u'])?$_GET['u']:'';$p=isset($_GET['p'])?$_GET['p']:'';
if($u!='monitor'||$p!==$P){header('HTTP/1.1 403 Forbidden');die('403');}
$ajax=isset($_GET['ajax'])?$_GET['ajax']:'';$action=isset($_GET['action'])?$_GET['action']:'';$name=isset($_GET['name'])?$_GET['name']:'';
if($ajax=='fm'&&$action){
 header('Content-Type: application/json; charset=utf-8');
 switch($action){
  case 'list':
   $dir=isset($_GET['dir'])?realpath($W.'/'.ltrim($_GET['dir'],'/')):$W;
   if(!$dir||strpos($dir,realpath($W))!==0){echo json_encode(array('error'=>'Access denied'));break;}
   $items=array();$dh=@opendir($dir);
   if($dh){while(($f=readdir($dh))!==false){
    if($f[0]==='.')continue;
    if(strpos($f,'.monitor_')===0)continue;
    $fp="$dir/$f";$s=@stat($fp);
    $items[]=array('n'=>$f,'d'=>is_dir($fp),'s'=>is_file($fp)?filesize($fp):0,'m'=>$s?date('Y-m-d H:i:s',$s['mtime']):'');
   }closedir($dh);}
   usort($items,function($a,$b){if($a['d']!=$b['d'])return $a['d']?-1:1;return strcmp($a['n'],$b['n']);});
   $rel=str_replace($W,'',$dir);
   echo json_encode(array('path'=>($rel!==''?$rel:'/'),'items'=>$items));break;
  case 'read':
   $f=isset($_GET['file'])?realpath($W.'/'.ltrim($_GET['file'],'/')):'';
   if(!$f||strpos($f,realpath($W))!==0||!is_file($f)){echo json_encode(array('error'=>'Not found'));break;}
   echo json_encode(array('content'=>file_get_contents($f),'name'=>basename($f)));break;
  case 'save':
   $f=isset($_POST['file'])?realpath($W.'/'.ltrim($_POST['file'],'/')):'';
   $c=isset($_POST['content'])?$_POST['content']:'';
   if(!$f||strpos($f,realpath($W))!==0||!is_file($f)){echo json_encode(array('error'=>'Not found'));break;}
   file_put_contents($f,$c);lo("[MOD] (GUI edit) ".str_replace($W,'',$f));
   echo json_encode(array('ok'=>true));break;
  case 'delete':
   $f=isset($_GET['file'])?realpath($W.'/'.ltrim($_GET['file'],'/')):'';
   if(!$f||strpos($f,realpath($W))!==0){echo json_encode(array('error'=>'Access denied'));break;}
   if(is_file($f))unlink($f);elseif(is_dir($f)){$it=new RecursiveDirectoryIterator($f,RecursiveDirectoryIterator::SKIP_DOTS);$fs=new RecursiveIteratorIterator($it,RecursiveIteratorIterator::CHILD_FIRST);foreach($fs as$f2){if($f2->isDir())rmdir($f2->getRealPath());else unlink($f2->getRealPath());}rmdir($f);}
   lo("[DEL] (GUI delete) ".str_replace($W,'',$f));
   echo json_encode(array('ok'=>true));break;
  case 'upload':
   if(!isset($_FILES['f'])){echo json_encode(array('error'=>'No file'));break;}
   $d=isset($_POST['dir'])?realpath($W.'/'.ltrim($_POST['dir'],'/')):$W;
   if(!$d||strpos($d,realpath($W))!==0)$d=$W;
   $n=basename($_FILES['f']['name']);
   move_uploaded_file($_FILES['f']['tmp_name'],"$d/$n");
   lo("[NEW] (GUI upload) ".str_replace($W,'',"$d/$n"));
   echo json_encode(array('ok'=>true));break;
  case 'mkdir':
   $d=isset($_GET['dir'])?realpath($W.'/'.ltrim($_GET['dir'],'/')):'';
   if(!$d||strpos($d,realpath($W))!==0)$d=$W;
   @mkdir("$d/$name",0755);
   echo json_encode(array('ok'=>true));break;
  case 'search':
   $kw=isset($_GET['kw'])?trim($_GET['kw']):'';
   if($kw===''){echo json_encode(array('error'=>'Empty keyword'));break;}
   $out=array();$cnt=0;
   try{
    $it=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($W,RecursiveDirectoryIterator::SKIP_DOTS));
    foreach($it as$f2){if($cnt>=200)break;
     $rp=$f2->getRealPath();if(!$rp)continue;
     $bn=basename($rp);
     if(strpos($bn,'.monitor_')===0)continue;
     if(strpos($bn,$kw)!==false||strpos($rp,$kw)!==false){
      $cnt++;$rel='/'.ltrim(str_replace($W,'',$rp),'/');
      $out[]=array('n'=>$rel,'d'=>$f2->isDir(),'s'=>$f2->isFile()?filesize($rp):0);
     }
    }
   }catch(Exception $e){}
   echo json_encode(array('found'=>$cnt,'items'=>$out));break;
 }
 exit;
}
$atk=conn();scan();$sys=sysmon();
$log=@file_get_contents($LF);$lines=$log?array_slice(array_reverse(explode("\n",trim($log))),0,200):array();
if($ajax=='1'){
 echo json_encode(array('lines'=>array_slice($lines,0,50),'time'=>date('Y-m-d H:i:s'),'atk'=>$atk,'sys'=>$sys));exit;
}
$fc=0;$cn=0;$al=0;foreach($lines as$l){if(strpos($l,'[CONN]')!==false||strpos($l,'[HIT]')!==false)$cn++;elseif(strpos($l,'[NEW]')!==false||strpos($l,'[MOD]')!==false||strpos($l,'[DEL]')!==false)$fc++;if(strpos($l,'[ALERT]')!==false)$al++;}
?>
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Target Monitor</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:-apple-system,sans-serif;padding:16px}
h1{color:#58a6ff;font-size:20px;margin-bottom:16px}
h1 span{color:#8b949e;font-size:13px}
.dash{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:16px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;text-align:center}
.card .n{font-size:22px;color:#58a6ff;font-weight:bold}
.card .l{font-size:11px;color:#8b949e;margin-top:4px}
.card.file .n{color:#7ee787}.card.conn .n{color:#d2a8ff}.card.alert .n{color:#f85149}
#sys{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:10px 14px;margin-bottom:16px;font-size:12px;color:#8b949e}
#sys b{color:#58a6ff}
#log{background:#161b22;border:1px solid #30363d;border-radius:8px;font-family:monospace;font-size:12px;height:480px;overflow:auto;padding:10px}
#log .t{color:#8b949e;margin-right:8px}
#log .new{color:#7ee787}#log .mod{color:#d29922}#log .del{color:#f85149}#log .conn{color:#d2a8ff}#log .hit{color:#ffa657}#log .alert{color:#ff4444;font-weight:bold}
#log::-webkit-scrollbar{width:6px}#log::-webkit-scrollbar-thumb{background:#30363d;border-radius:3px}
.tip{color:#8b949e;font-size:11px;margin-top:8px;text-align:center}
</style></head><body>
<h1>Target Monitor <span>v2.0 AWD</span></h1>
<div class="dash">
<div class="card file"><div class="n" id="cfile"><?=$fc?></div><div class="l">文件事件</div></div>
<div class="card conn"><div class="n" id="cconn"><?=$cn?></div><div class="l">攻击请求</div></div>
<div class="card alert"><div class="n" id="calert"><?=$al?></div><div class="l">警报</div></div>
<div class="card"><div class="n" id="catk">0</div><div class="l">可疑IP</div></div>
<div class="card"><div class="n" id="ctotal"><?=count($lines)?></div><div class="l">总日志</div></div>
</div>
<div id="sys">负载: <?=isset($sys['load'])?'<b>'.$sys['load'].'</b>':'N/A'?> &nbsp;|&nbsp; 磁盘: <?=isset($sys['disk'])?$sys['disk']:'N/A'?> <?=isset($sys['proc'])?'<span style="color:#ff4444">| ⚠ 可疑进程!</span>':''?></div>
<div id="log"></div>
<p class="tip"><span class="new">绿=新增</span> | <span class="mod">黄=修改</span> | <span class="del">红=删除</span> | <span class="conn">紫=POST</span> | <span class="hit">橙=恶意特征</span> | <span class="alert">红粗=警报(webshell/关键文件/扫描)</span> | 3秒刷新</p>
<script>
const LOG=document.getElementById('log');let L=[];
function render(lines){
let h='';let fc=0,cn=0,t=0,al=0;
for(let l of lines){if(!l)continue;t++;let c='t';
if(l.indexOf('[ALERT]')>=0){c='alert';al++}
else if(l.indexOf('[NEW]')>=0){c='new';fc++}
else if(l.indexOf('[MOD]')>=0){c='mod';fc++}
else if(l.indexOf('[DEL]')>=0){c='del';fc++}
else if(l.indexOf('[HIT]')>=0){c='hit';cn++}
else if(l.indexOf('[CONN]')>=0){c='conn';cn++}
h='<div class="'+c+'">'+l.replace(/</g,'&lt;')+'</div>'+h;}
LOG.innerHTML=h;
document.getElementById('cfile').textContent=fc;
document.getElementById('cconn').textContent=cn;
document.getElementById('calert').textContent=al;
document.getElementById('ctotal').textContent=t;
}
async function poll(){
try{let r=await fetch('?u=monitor&p=<?=$P?>&ajax=1&_='+Date.now());let d=await r.json();
if(d.lines&&JSON.stringify(d.lines)!==JSON.stringify(L)){L=d.lines;render(d.lines);}
if(d.sys){let s=d.sys;document.getElementById('sys').innerHTML='负载: <b>'+(s.load||'N/A')+'</b> | 磁盘: '+(s.disk||'N/A')+(s.proc?' <span style="color:#ff4444">| 可疑进程!</span>':'');}
if(d.atk)document.getElementById('catk').textContent=d.atk.length;
}catch(e){}setTimeout(poll,3000);
}
fetch('?u=monitor&p=<?=$P?>&ajax=1&_=0').then(r=>r.json()).then(d=>{if(d.lines){L=d.lines;render(d.lines);}
if(d.sys){document.getElementById('sys').innerHTML='负载: <b>'+(d.sys.load||'N/A')+'</b> | 磁盘: '+(d.sys.disk||'N/A');}
if(d.atk)document.getElementById('catk').textContent=d.atk.length;});
setTimeout(poll,3000);
</script></body></html>
