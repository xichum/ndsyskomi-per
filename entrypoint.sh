#!/bin/sh

# Author      : Prince (Shell Port)
# Version     : 1.0.3
# License     : MIT

set +e

# ================= 环境变量设置 =================
DATA_PATH="${DATA_PATH:-$(pwd)/.backend_service}"
WORK_DIR="$DATA_PATH"
mkdir -p "$WORK_DIR"

# 端口设置
T_PORT="${T_PORT:-}"       # T 端口
H_PORT="${H_PORT:-}"       # H 端口
R_PORT="${R_PORT:-}"       # R 端口
PORT_WEB="${PORT:-3000}"   # Web 页端口

# 核心参数
UUID="${UUID:-}"
SNI="${R_SNI:-bunny.net}"
DEST="${R_DEST:-bunny.net:443}"
PREFIX="${NODE_PREFIX:-}"
HY2_OBFS="${HY2_OBFS:-true}"
CRON="${CRON:-}"

# 监控参数
PROBE_URL="${KOMARI_HOST:-}"
PROBE_TOK="${KOMARI_TOKEN:-}"

# 证书参数
CERT_URL="${RES_CERT_URL:-}"
KEY_URL="${RES_KEY_URL:-}"
CERT_DOMAIN="${CERT_DOMAIN:-}"

# 文件路径 (混淆处理)
FILES_META="$WORK_DIR/registry.dat"
FILES_TOKEN="$WORK_DIR/identity.key"
FILES_PAIR="$WORK_DIR/transport_pair.bin"
FILES_CERT="$WORK_DIR/tls_cert.pem"
FILES_KEY="$WORK_DIR/tls_key.pem"
FILES_CONF="$WORK_DIR/service_conf.json"
FILES_SUB="$WORK_DIR/blob_storage.dat"
FILES_SID="$WORK_DIR/session_ticket.hex"
FILES_SEC="$WORK_DIR/access_token.key"
WEB_ROOT="$WORK_DIR/www"

# ================= 工具函数 =================

sys_log() {
    echo "[$(date -u +"%T")] [$1] $2"
}

check_deps() {
    for cmd in curl jq openssl tar; do
        if ! command -v $cmd >/dev/null 2>&1; then
            echo "错误: 缺少依赖 $cmd"
            exit 1
        fi
    done
}

rand_hex() {
    openssl rand -hex "$1"
}

download_file() {
    local url="$1"
    local dest="$2"
    local label="$3"
    local tmp="${dest}.tmp"
    
    if [ -z "$url" ]; then return 1; fi
    
    sys_log "Net" "正在下载 $label: $url"
    
    # -k 允许不安全的SSL (防止证书源本身证书过期导致下载失败)
    if curl -k -L -s --connect-timeout 20 --retry 3 -o "$tmp" "$url"; then
        local size=$(wc -c < "$tmp")
        if [ "$size" -lt 100 ]; then
            sys_log "ERR" "下载 $label 失败: 文件过小 ($size bytes)，可能是无效链接"
            rm -f "$tmp"
            return 1
        fi
        mv "$tmp" "$dest"
        sys_log "Net" "下载 $label 成功 (大小: $size bytes)"
        return 0
    else
        sys_log "ERR" "下载 $label 失败: 网络连接错误"
        rm -f "$tmp"
        return 1
    fi
}

fetch_bin() {
    local type="$1"
    local meta_key="$type"
    local current_bin=""
    
    if [ -f "$FILES_META" ]; then
        current_bin=$(jq -r --arg k "$meta_key" '.[$k] // empty' "$FILES_META")
    fi
    
    if [ -n "$current_bin" ] && [ -f "$WORK_DIR/$current_bin" ]; then
        echo "$WORK_DIR/$current_bin"
        return 0
    fi
    
    local arch=$(uname -m)
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        s390x) arch="s390x" ;;
        *) return 1 ;;
    esac
    
    local dl_url=""
    local bin_name=""
    local rand=$(rand_hex 4)
    
    if [ "$type" = "srv" ]; then
        local tag=$(curl -s -H "User-Agent: Node" "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r .tag_name)
        if [ "$tag" = "null" ] || [ -z "$tag" ]; then tag="v1.12.13"; fi
        local ver=${tag#v}
        dl_url="https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${ver}-linux-${arch}.tar.gz"
        bin_name="S${ver//./}_${rand}"
    else
        local tag=$(curl -s -H "User-Agent: Node" "https://api.github.com/repos/komari-monitor/komari-agent/releases/latest" | jq -r .tag_name)
        if [ "$tag" = "null" ] || [ -z "$tag" ]; then tag="latest"; fi
        local ver="000"
        if [ "$tag" != "latest" ]; then ver=${tag#v}; ver=${ver//./}; fi
        if [ "$tag" = "latest" ]; then
             dl_url="https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${arch}"
        else
             dl_url="https://github.com/komari-monitor/komari-agent/releases/download/${tag}/komari-agent-linux-${arch}"
        fi
        bin_name="K${ver}_${rand}"
    fi
    
    local tmp_dl="$WORK_DIR/dl_${rand}"
    if download_file "$dl_url" "$tmp_dl" "核心组件($type)"; then
        local final_path="$WORK_DIR/$bin_name"
        if [ "$type" = "srv" ]; then
            local tmp_ext="$WORK_DIR/ext_${rand}"
            mkdir -p "$tmp_ext"
            tar -xzf "$tmp_dl" -C "$tmp_ext"
            local found_bin=$(find "$tmp_ext" -type f -name "sing-box" | head -n 1)
            if [ -n "$found_bin" ]; then mv "$found_bin" "$final_path"; fi
            rm -rf "$tmp_ext"
        else
            mv "$tmp_dl" "$final_path"
        fi
        rm -f "$tmp_dl"
        
        if [ -f "$final_path" ]; then
            chmod 755 "$final_path"
            if [ -f "$FILES_META" ]; then
                local tmp_meta=$(mktemp)
                jq --arg k "$meta_key" --arg v "$bin_name" '.[$k] = $v' "$FILES_META" > "$tmp_meta" && mv "$tmp_meta" "$FILES_META"
            else
                echo "{\"$meta_key\": \"$bin_name\"}" > "$FILES_META"
            fi
            echo "$final_path"
            return 0
        fi
    fi
    return 1
}

# ================= 主逻辑 =================

main() {
    check_deps
    
    # 清理旧的临时文件
    find "$WORK_DIR" -type f -name "dl_*" -delete 2>/dev/null
    find "$WORK_DIR" -type d -name "ext_*" -exec rm -rf {} + 2>/dev/null
    
    sys_log "Init" "正在检查核心组件..."
    local bin_srv=$(fetch_bin "srv")
    local bin_mon=$(fetch_bin "mon")
    
    if [ -z "$bin_srv" ]; then
        sys_log "ERR" "核心组件下载失败，无法启动"
        exit 1
    fi
    
    # UUID 初始化
    if [ -z "$UUID" ]; then
        if [ -f "$FILES_TOKEN" ]; then
            UUID=$(cat "$FILES_TOKEN")
        else
            if uuidgen >/dev/null 2>&1; then UUID=$(uuidgen); else UUID=$(cat /proc/sys/kernel/random/uuid); fi
            echo "$UUID" > "$FILES_TOKEN"
        fi
    fi
    
    # 辅助密钥生成
    if [ ! -f "$FILES_PAIR" ]; then "$bin_srv" generate reality-keypair > "$FILES_PAIR" 2>/dev/null; fi
    local pk=$(grep "PrivateKey" "$FILES_PAIR" | awk '{print $2}')
    local pub=$(grep "PublicKey" "$FILES_PAIR" | awk '{print $2}')
    
    if [ -f "$FILES_SEC" ]; then local sec_key=$(cat "$FILES_SEC"); else local sec_key=$(rand_hex 16); echo "$sec_key" > "$FILES_SEC"; fi
    if [ -f "$FILES_SID" ]; then local sid=$(cat "$FILES_SID"); else local sid=$(rand_hex 4); echo "$sid" > "$FILES_SID"; fi
    
    # 证书逻辑
    local tls_ready=0
    local use_cert_download=0
    
    # 1. 优先尝试下载证书
    if [ -n "$CERT_URL" ] && [ -n "$KEY_URL" ]; then
        download_file "$CERT_URL" "$FILES_CERT" "TLS公钥"
        download_file "$KEY_URL" "$FILES_KEY" "TLS私钥"
        use_cert_download=1
    fi
    
    # 2. 验证证书有效性
    if [ -f "$FILES_CERT" ] && [ -f "$FILES_KEY" ]; then
        if grep -q "BEGIN CERTIFICATE" "$FILES_CERT"; then
            tls_ready=1
            sys_log "Init" "TLS 证书加载成功"
        else
            sys_log "ERR" "TLS 证书文件存在但格式无效"
            if [ "$use_cert_download" -eq 1 ]; then
                 sys_log "ERR" "请检查 RES_CERT_URL 链接是否直链且有效"
            fi
        fi
    fi
    
    # 3. 只有在未提供下载链接 且 提供了域名时，才生成自签
    if [ "$tls_ready" -eq 0 ] && [ -z "$CERT_URL" ] && [ -n "$CERT_DOMAIN" ]; then
        sys_log "Init" "未提供证书链接，生成自签名证书 ($CERT_DOMAIN)..."
        "$bin_srv" generate tls-keypair "$CERT_DOMAIN" > "$WORK_DIR/temp_cert" 2>/dev/null
        awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/' "$WORK_DIR/temp_cert" > "$FILES_KEY"
        awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$WORK_DIR/temp_cert" > "$FILES_CERT"
        rm -f "$WORK_DIR/temp_cert"
        tls_ready=1
    fi
    
    # 配置生成逻辑
    local inbound_json=""
    local listen_ip="0.0.0.0"
    local config_count=0
    
    # TUIC
    if [ -n "$T_PORT" ]; then
        if [ "$tls_ready" -eq 1 ]; then
            inbound_json="${inbound_json} {\"type\": \"tuic\", \"listen\": \"$listen_ip\", \"listen_port\": $T_PORT, \"users\": [{\"uuid\": \"$UUID\", \"password\": \"$sec_key\"}], \"congestion_control\": \"bbr\", \"tls\": {\"enabled\": true, \"certificate_path\": \"$FILES_CERT\", \"key_path\": \"$FILES_KEY\", \"alpn\": [\"h3\"]}},"
            config_count=$((config_count+1))
        else
            sys_log "Warn" "跳过 TUIC 配置: 缺少有效证书 (需要设置 RES_CERT_URL 或 CERT_DOMAIN)"
        fi
    fi
    
    # Hysteria2
    if [ -n "$H_PORT" ]; then
        if [ "$tls_ready" -eq 1 ]; then
            local obfs_json=""
            if [ "$HY2_OBFS" = "true" ]; then obfs_json="\"obfs\": {\"type\": \"salamander\", \"password\": \"$sec_key\"},"; fi
            inbound_json="${inbound_json} {\"type\": \"hysteria2\", \"listen\": \"$listen_ip\", \"listen_port\": $H_PORT, \"users\": [{\"password\": \"$UUID\"}], \"masquerade\": \"https://bing.com\", \"tls\": {\"enabled\": true, \"certificate_path\": \"$FILES_CERT\", \"key_path\": \"$FILES_KEY\"}, \"ignore_client_bandwidth\": false, $obfs_json \"xx\": 0},"
            config_count=$((config_count+1))
        else
            sys_log "Warn" "跳过 Hysteria2 配置: 缺少有效证书"
        fi
    fi
    
    # Reality
    if [ -n "$R_PORT" ]; then
        local s_host=$(echo "$DEST" | cut -d: -f1)
        local s_port=$(echo "$DEST" | cut -d: -f2)
        if [ -z "$s_port" ] || [ "$s_port" = "$s_host" ]; then s_port=443; fi
        inbound_json="${inbound_json} {\"type\": \"vless\", \"listen\": \"$listen_ip\", \"listen_port\": $R_PORT, \"users\": [{\"uuid\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}], \"tls\": {\"enabled\": true, \"server_name\": \"$SNI\", \"reality\": {\"enabled\": true, \"handshake\": {\"server\": \"$s_host\", \"server_port\": $s_port}, \"private_key\": \"$pk\", \"short_id\": [\"$sid\"]}}},"
        config_count=$((config_count+1))
    fi
    
    # 检查是否有有效配置
    if [ "$config_count" -eq 0 ]; then
        sys_log "ERR" "未配置任何有效端口！"
        sys_log "ERR" "请设置 T_PORT/H_PORT (需证书) 或 R_PORT"
        sys_log "Sys" "服务挂起中，等待配置更新..."
        tail -f /dev/null
        return
    fi
    
    # 写入配置文件
    inbound_json=$(echo "$inbound_json" | sed 's/,}/}/g' | sed 's/,\s*$//')
    echo "{\"log\": {\"disabled\": true, \"level\": \"warn\", \"timestamp\": true}, \"inbounds\": [$inbound_json], \"outbounds\": [{\"type\": \"direct\", \"tag\": \"direct\"}], \"route\": {\"final\": \"direct\"}}" > "$FILES_CONF"
    
    # 获取公网IP
    local pub_ip="127.0.0.1"
    pub_ip=$(curl -s --connect-timeout 3 https://api.ipify.org || echo "127.0.0.1")
    sys_log "Net" "服务器IP: $pub_ip"
    
    # 生成分享链接
    local links=""
    if [ -n "$T_PORT" ] && [ "$tls_ready" -eq 1 ]; then links="${links}tuic://${UUID}:${sec_key}@${pub_ip}:${T_PORT}?sni=${CERT_DOMAIN}&alpn=h3&congestion_control=bbr#${PREFIX}-T\n"; fi
    if [ -n "$H_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        local h_params="sni=${CERT_DOMAIN}&insecure=1"
        if [ "$HY2_OBFS" = "true" ]; then h_params="${h_params}&obfs=salamander&obfs-password=${sec_key}"; fi
        links="${links}hysteria2://${UUID}@${pub_ip}:${H_PORT}/?${h_params}#${PREFIX}-H\n"
    fi
    if [ -n "$R_PORT" ]; then links="${links}vless://${UUID}@${pub_ip}:${R_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=edge&pbk=${pub}&sid=${sid}&type=tcp#${PREFIX}-R\n"; fi
    
    local b64=$(echo -e "$links" | base64 | tr -d '\n')
    echo "$b64" > "$FILES_SUB"
    
    sys_log "Sys" "配置初始化完成"
    echo -e "\n========== BASE64 订阅链接 ==========\n$b64\n======================================\n"

    # 准备 Web 目录
    rm -rf "$WEB_ROOT"
    mkdir -p "$WEB_ROOT/api"
    echo "<!DOCTYPE html><html><head><title>Status</title></head><body><h3>Service Operational</h3><p>Running on $pub_ip</p></body></html>" > "$WEB_ROOT/index.html"
    cp "$FILES_SUB" "$WEB_ROOT/api/data"
    echo '{"status":"OK"}' > "$WEB_ROOT/api/heartbeat"

    # 启动核心服务
    sys_log "Sys" "启动核心服务..."
    export GOGC=80
    "$bin_srv" run -c "$FILES_CONF" >/dev/null 2>&1 &
    PID_SRV=$!
    
    # 启动监控服务
    PID_MON=""
    if [ -n "$bin_mon" ] && [ -n "$PROBE_URL" ]; then
        local mon_url="$PROBE_URL"
        if echo "$mon_url" | grep -v -q "^http"; then mon_url="https://$mon_url"; fi
        sys_log "Sys" "启动监控服务..."
        "$bin_mon" -e "$mon_url" -t "$PROBE_TOK" >/dev/null 2>&1 &
        PID_MON=$!
    fi
    
    sys_log "Web" "Web 服务监听端口: $PORT_WEB"
    
    # === Web 服务 (Httpd + Netcat 兜底) ===
    if busybox httpd -p "$PORT_WEB" -h "$WEB_ROOT" >/dev/null 2>&1; then
        sys_log "Web" "Httpd 服务已启动"
    else
        sys_log "Warn" "Httpd 未找到，使用 Netcat 模式 (不推荐，建议更新镜像)"
        # 改进的 Netcat 循环，支持简单的 HTTP 响应
        (
            while true; do
                echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: $(wc -c < $WEB_ROOT/index.html)\r\n\r\n$(cat $WEB_ROOT/index.html)" | nc -l -p "$PORT_WEB" -w 3 >/dev/null 2>&1
                sleep 0.1
            done
        ) &
    fi
    
    # 进程守护
    while true; do
        if ! kill -0 $PID_SRV 2>/dev/null; then
             sys_log "ERR" "核心服务异常退出，正在重启..."
             "$bin_srv" run -c "$FILES_CONF" >/dev/null 2>&1 &
             PID_SRV=$!
        fi
        
        if [ -n "$PID_MON" ] && ! kill -0 $PID_MON 2>/dev/null; then
             sys_log "ERR" "监控服务异常退出，正在重启..."
             "$bin_mon" -e "$PROBE_URL" -t "$PROBE_TOK" >/dev/null 2>&1 &
             PID_MON=$!
        fi
        
        # 更新心跳
        local tick=$(($(date +%s) - $(date -r "$FILES_CONF" +%s)))
        echo "{\"status\":\"OK\",\"tick\":$tick}" > "$WEB_ROOT/api/heartbeat"
        
        # 定时重启逻辑
        if [ -n "$CRON" ]; then
            local current_hour=$(date -u -d "+8 hours" +%H)
            local current_min=$(date -u -d "+8 hours" +%M)
            if [ "$current_hour" = "06" ] && [ "$current_min" = "30" ]; then
                 sys_log "Sys" "计划任务重启..."
                 kill $PID_SRV 2>/dev/null
                 if [ -n "$PID_MON" ]; then kill $PID_MON 2>/dev/null; fi
                 sleep 65
            fi
        fi
        sleep 10
    done
}

main
