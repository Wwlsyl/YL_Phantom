#!/bin/bash
# AWD 后台监控脚本 - 放靶机上运行
# 用法: nohup bash watchdog.sh &
# 功能: 实时监控文件变化 + 连接变化 → 写入日志

WEB_DIR="/var/www/html"
LOG_FILE="/tmp/awd_watchdog.log"
CONN_FILE="/tmp/awd_conns.txt"

echo "========== AWD Watchdog Started at $(date) ==========" >> "$LOG_FILE"

# 检查是否有 inotifywait
HAVE_INOTIFY=false
if command -v inotifywait &>/dev/null; then
    HAVE_INOTIFY=true
fi

# 记录初始文件列表
if [ ! -f /tmp/awd_snapshot.txt ]; then
    find "$WEB_DIR" -type f -name "*.php" -o -name "*.php5" -o -name "*.phtml" -o -name "*.sh" -o -name "*.py" 2>/dev/null | sort > /tmp/awd_snapshot.txt
    echo "$(date '+%H:%M:%S') [INFO] 初始快照已记录: $(wc -l < /tmp/awd_snapshot.txt) 个文件" >> "$LOG_FILE"
fi

# ======== 文件监控 ========
if [ "$HAVE_INOTIFY" = true ]; then
    # 实时监控模式（有 inotifywait）
    echo "$(date '+%H:%M:%S') [INFO] 实时监控模式 (inotify)" >> "$LOG_FILE"
    inotifywait -m -r -e create,modify,move "$WEB_DIR" --format '%e %w%f' 2>/dev/null | while read event path; do
        ext="${path##*.}"
        case "$ext" in
            php|php5|phtml|php7|pht|sh|py|pl|asp|aspx|jsp)
                echo "$(date '+%H:%M:%S') [$event] $path" >> "$LOG_FILE"
                # 检查是否包含高危函数
                if grep -q -E '(eval|system|exec|passthru|shell_exec|popen|assert|base64_decode|pfsockopen|file_put_contents|curl_exec|ob_start|create_function)' "$path" 2>/dev/null; then
                    echo "$(date '+%H:%M:%S') [WARN] 高危函数: $path" >> "$LOG_FILE"
                fi
                ;;
        esac
    done
else
    # 轮询模式（没有 inotifywait）
    echo "$(date '+%H:%M:%S') [INFO] 轮询监控模式 (每5秒)" >> "$LOG_FILE"
    while true; do
        # 对比当前文件列表和快照
        find "$WEB_DIR" -type f \( -name "*.php" -o -name "*.php5" -o -name "*.phtml" -o -name "*.sh" -o -name "*.py" \) 2>/dev/null | sort > /tmp/awd_current.txt
        
        # 检查新增文件
        while IFS= read -r line; do
            if ! grep -Fxq "$line" /tmp/awd_snapshot.txt 2>/dev/null; then
                echo "$(date '+%H:%M:%S') [NEW] $line" >> "$LOG_FILE"
                # 检查高危函数
                if grep -q -E '(eval|system|exec|passthru|shell_exec|popen|assert|base64_decode|pfsockopen|file_put_contents)' "$line" 2>/dev/null; then
                    echo "$(date '+%H:%M:%S') [WARN] 高危函数: $line" >> "$LOG_FILE"
                fi
            fi
        done < /tmp/awd_current.txt
        
        # 更新快照（附加新文件）
        cat /tmp/awd_current.txt >> /tmp/awd_snapshot.txt 2>/dev/null
        sort -u /tmp/awd_snapshot.txt -o /tmp/awd_snapshot.txt
        
        sleep 5
    done
fi
