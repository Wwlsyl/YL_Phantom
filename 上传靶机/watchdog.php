<?php
// AWD靶机监控面板 - 放Web目录下直接访问
// 用法：上传到靶机 http://your-target-ip/watchdog.php
// 安全: 删除/清日志操作需口令 ?p=XXXX; 上线前请修改 $PANEL_PASS 为强口令!

header('Content-Type: text/html; charset=utf-8');

$web_root = realpath(__DIR__); // 当前目录，本地测试用
$log_file = '/tmp/awd_watchdog.log';
$PANEL_PASS = 'ylphantom_wd@2026'; // ⚠ 上线前改成你自己的强口令

// 受保护文件(禁止通过面板删除)
$PROTECTED = ['.waf.dat.php', '.waf.dat', '.user.ini', '.htaccess',
    'watchdog.php', 'watchdog.sh', 'target_monitor.php', 'waf_strong.php',
    'waf_ban.php', 'index.php', '.creep.php'];

function auth_ok($pass) {
    global $PANEL_PASS;
    return hash_equals((string)$PANEL_PASS, (string)$pass);
}

// 校验待删文件: 必须在web根目录内 且 非受保护文件
function can_delete($f, $web_root) {
    if ($f === '' || strpos($f, "\0") !== false) return false;
    $real = realpath($f);
    if (!$real) return false;
    $root = realpath($web_root);
    if ($root === false || strpos($real, $root) !== 0) return false;
    global $PROTECTED;
    if (in_array(basename($real), $PROTECTED, true)) return false;
    return true;
}

// 处理删除请求
if (isset($_GET['del'])) {
    if (!auth_ok(isset($_GET['p']) ? $_GET['p'] : '')) exit('forbidden');
    $f = $_GET['del'];
    if (can_delete($f, $web_root)) {
        unlink($f);
        file_put_contents($log_file, date('H:i:s') . " [DELETE] $f\n", FILE_APPEND);
        echo "<script>alert('已删除: $f');location.href='?'</script>";
    } else {
        echo "<script>alert('拒绝删除(路径越权或受保护): $f');location.href='?'</script>";
    }
    exit;
}

// 处理批量删除
if (isset($_GET['delall'])) {
    if (!auth_ok(isset($_GET['p']) ? $_GET['p'] : '')) exit('forbidden');
    $files = explode("\n", file_get_contents($log_file));
    $del_cnt = 0;
    foreach ($files as $line) {
        if (preg_match('/\[NEW\] (.+)$/', $line, $m)) {
            $f = trim($m[1]);
            if (can_delete($f, $web_root) && file_exists($f)) { unlink($f); $del_cnt++; }
        }
    }
    file_put_contents($log_file, date('H:i:s') . " [BATCH_DEL] 删除 $del_cnt 个文件\n", FILE_APPEND);
    echo "<script>alert('批量删除 $del_cnt 个文件');location.href='?'</script>";
    exit;
}

// 清除日志
if (isset($_GET['clear'])) {
    if (!auth_ok(isset($_GET['p']) ? $_GET['p'] : '')) exit('forbidden');
    file_put_contents($log_file, '');
    echo "<script>alert('日志已清空');location.href='?'</script>";
    exit;
}

// ========== 扫描最近修改的文件 ==========
function scan_files($dir) {
    $result = [];
    $now = time();
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    foreach ($items as $item) {
        $ext = strtolower(pathinfo($item, PATHINFO_EXTENSION));
        $suspicious_exts = ['php', 'php5', 'phtml', 'php7', 'pht', 'asp', 'aspx', 'jsp', 'py', 'sh', 'pl'];
        if (!in_array($ext, $suspicious_exts)) continue;

        $mtime = $item->getMTime();
        $diff = $now - $mtime;
        if ($diff > 600) continue; // 10分钟内修改的才显示

        $size = $item->getSize();
        $lines = count(file($item->getRealPath()));
        $content_preview = '';
        if ($size < 5000) {
            $c = file_get_contents($item->getRealPath());
            if (preg_match('/\b(eval|system|exec|passthru|shell_exec|popen|assert|base64_decode|file_put_contents|pfsockopen)\b/i', $c)) {
                $content_preview = ' [高危函数]';
            }
        }

        $result[] = [
            'path' => $item->getRealPath(),
            'rel' => str_replace($dir, '', $item->getRealPath()),
            'mtime' => $mtime,
            'diff' => $diff,
            'size' => $size,
            'lines' => $lines,
            'suspicious' => $content_preview,
        ];
    }
    usort($result, function($a, $b) { return $a['diff'] <=> $b['diff']; });
    return $result;
}

// ========== 获取网络连接 ==========
function get_connections() {
    $result = [];
    $raw = shell_exec('netstat -antp 2>/dev/null || ss -antp 2>/dev/null');
    if (!$raw) return [];
    foreach (explode("\n", $raw) as $line) {
        if (preg_match('/(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(ESTABLISHED|TIME_WAIT|SYN_SENT)/', $line, $m)) {
            // 排除自身SSH和常见连接
            if ($m[2] != 22 && $m[1] != '127.0.0.1') {
                $result[] = ['local' => "$m[1]:$m[2]", 'remote' => "$m[3]:$m[4]", 'status' => $m[5]];
            }
        }
    }
    return $result;
}

// ========== 记录新文件 ==========
function log_new_files($dir, $log_file) {
    $known = '/tmp/awd_known_files.txt';
    if (!file_exists($known)) {
        // 首次运行，记录当前所有文件
        $all = [];
        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
        );
        foreach ($items as $item) {
            if ($item->isFile()) $all[] = $item->getRealPath();
        }
        file_put_contents($known, implode("\n", $all));
        return;
    }
    $known_files = explode("\n", file_get_contents($known));
    $known_map = array_flip($known_files);

    $current = [];
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS)
    );
    foreach ($items as $item) {
        if (!$item->isFile()) continue;
        $path = $item->getRealPath();
        $current[] = $path;
        if (!isset($known_map[$path])) {
            $ext = pathinfo($path, PATHINFO_EXTENSION);
            if (in_array($ext, ['php','php5','phtml','php7','pht','asp','aspx','jsp','sh','py','pl'])) {
                file_put_contents($log_file, date('H:i:s') . " [NEW] $path\n", FILE_APPEND);
            }
        }
    }
    file_put_contents($known, implode("\n", $current));
}

log_new_files($web_root, $log_file);

$files = scan_files($web_root);
$conns = get_connections();
$logs = file_exists($log_file) ? array_reverse(array_slice(file($log_file), -50)) : [];
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AWD Watchdog</title>
<meta http-equiv="refresh" content="5">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0d1117; color:#c9d1d9; font-family:'Consolas','Courier New',monospace; padding:20px; }
h1 { color:#58a6ff; font-size:22px; margin-bottom:15px; }
h2 { color:#f0883e; font-size:16px; margin:15px 0 8px 0; border-bottom:1px solid #21262d; padding-bottom:5px; }
.status-bar { display:flex; gap:15px; margin-bottom:15px; flex-wrap:wrap; }
.status-item { background:#161b22; padding:8px 14px; border-radius:6px; border:1px solid #30363d; font-size:13px; }
.status-item .num { color:#58a6ff; font-weight:bold; font-size:18px; }
.alert { background:#da3633; color:white; padding:8px 14px; border-radius:6px; font-weight:bold; font-size:13px; }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { background:#161b22; color:#8b949e; text-align:left; padding:8px 10px; border:1px solid #30363d; font-weight:normal; }
td { padding:6px 10px; border:1px solid #30363d; }
tr:hover { background:#1c2128; }
tr.new-row { background:#2d1500; }
tr.suspicious { color:#ff7b72; }
.del-btn { color:#f85149; text-decoration:none; font-weight:bold; padding:2px 8px; border:1px solid #f85149; border-radius:4px; font-size:12px; }
.del-btn:hover { background:#f85149; color:#fff; }
.batch-bar { margin:10px 0; display:flex; gap:10px; }
.batch-bar a { padding:6px 14px; border-radius:4px; text-decoration:none; font-size:13px; }
.batch-del { background:#da3633; color:#fff; }
.batch-clear { background:#21262d; color:#c9d1d9; border:1px solid #30363d; }
.time { color:#8b949e; font-size:12px; }
.log-box { background:#0d1117; border:1px solid #30363d; padding:10px; font-size:12px; max-height:200px; overflow-y:auto; margin-top:5px; }
.log-box div { padding:2px 0; border-bottom:1px solid #21262d; }
.log-new { color:#3fb950; }
.log-del { color:#f85149; }
.tag-high { background:#da3633; color:#fff; padding:1px 6px; border-radius:3px; font-size:11px; }
.tag-warn { background:#d29922; color:#fff; padding:1px 6px; border-radius:3px; font-size:11px; }
.tag-ok { background:#238636; color:#fff; padding:1px 6px; border-radius:3px; font-size:11px; }
.conn-ip { color:#58a6ff; }
.refresh-note { color:#8b949e; font-size:12px; text-align:right; margin-top:5px; }
</style>
</head>
<body>

<h1>🛡 AWD Watchdog</h1>

<div class="status-bar">
    <div class="status-item">📁 最近修改 <span class="num"><?=count($files)?></span></div>
    <div class="status-item">🔗 连接 <span class="num"><?=count($conns)?></span></div>
    <div class="status-item">📋 事件 <span class="num"><?=count($logs)?></span></div>
    <?php if (count($files) > 0 || count($conns) > 0): ?>
    <div class="alert">⚠ 有异常！请检查</div>
    <?php endif; ?>
</div>

<!-- 文件监控 -->
<h2>📁 最近修改的文件 (10分钟内)</h2>
<div class="batch-bar">
    <a class="batch-del" href="?delall=1&amp;p=<?=htmlspecialchars($PANEL_PASS)?>" onclick="return confirm('确认批量删除所有新增文件？')">🗑 批量删除新增</a>
    <a class="batch-clear" href="?clear=1&amp;p=<?=htmlspecialchars($PANEL_PASS)?>">🧹 清空日志</a>
</div>
<table>
<tr><th>文件</th><th>修改时间</th><th>大小</th><th>行数</th><th>操作</th></tr>
<?php if (empty($files)): ?>
<tr><td colspan="5" style="text-align:center;color:#8b949e;">暂无新文件变化</td></tr>
<?php else: ?>
<?php foreach ($files as $f): ?>
<tr class="<?=strpos($f['suspicious'], '高危')!==false?'suspicious':($f['diff']<120?'new-row':'')?>">
    <td><?=htmlspecialchars($f['rel'])?><?=$f['suspicious']?></td>
    <td class="time"><?=date('H:i:s', $f['mtime'])?> (<?=$f['diff']?>秒前)</td>
    <td><?=$f['size']?>B</td>
    <td><?=$f['lines']?></td>
    <td><a class="del-btn" href="?del=<?=urlencode($f['path'])?>&amp;p=<?=htmlspecialchars($PANEL_PASS)?>" onclick="return confirm('删除 <?=basename($f['path'])?>？')">删除</a></td>
</tr>
<?php endforeach; ?>
<?php endif; ?>
</table>

<!-- 连接监控 -->
<h2>🔗 网络连接</h2>
<table>
<tr><th>本地</th><th>远程</th><th>状态</th><th>可疑</th></tr>
<?php if (empty($conns)): ?>
<tr><td colspan="4" style="text-align:center;color:#8b949e;">无异常连接</td></tr>
<?php else: ?>
<?php foreach ($conns as $c): ?>
<?php
$suspicious = '';
if (preg_match('/:80$|:8080$|:4433$|:8888$|:9999$/', $c['remote'])) $suspicious = '<span class="tag-warn">Web端口</span>';
if (preg_match('/:4444$|:5555$|:6666$|:7777$|:2333$|:1337$/', $c['remote'])) $suspicious = '<span class="tag-high">可疑端口</span>';
if (strpos($c['status'], 'SYN_SENT') !== false) $suspicious = '<span class="tag-warn">外连</span>';
?>
<tr>
    <td class="conn-ip"><?=htmlspecialchars($c['local'])?></td>
    <td><?=htmlspecialchars($c['remote'])?></td>
    <td><?=$c['status']?></td>
    <td><?=$suspicious?></td>
</tr>
<?php endforeach; ?>
<?php endif; ?>
</table>

<!-- 事件日志 -->
<h2>📋 实时事件</h2>
<div class="log-box">
<?php if (empty($logs)): ?>
<div style="color:#8b949e;">暂无事件</div>
<?php else: ?>
<?php foreach ($logs as $log): ?>
<?php
$cls = '';
if (strpos($log, '[NEW]') !== false) $cls = 'log-new';
if (strpos($log, '[DELETE]') !== false || strpos($log, '[BATCH_DEL]') !== false) $cls = 'log-del';
?>
<div class="<?=$cls?>"><?=htmlspecialchars(trim($log))?></div>
<?php endforeach; ?>
<?php endif; ?>
</div>

<div class="refresh-note">⏱ 每5秒自动刷新 · 上次刷新: <?=date('H:i:s')?></div>

</body>
</html>
