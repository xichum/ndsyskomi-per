#!/bin/sh

# Author      : Prince (Shell Port)
# Version     : 1.0.0
# License     : MIT

set -e

# ================= Configuration =================
# 优先读取环境变量，否则使用默认值
DATA_PATH="${DATA_PATH:-$(pwd)/.backend_service}"
WORK_DIR="$DATA_PATH"
mkdir -p "$WORK_DIR"

T_PORT="${T_PORT:-}"
H_PORT="${H_PORT:-}"
R_PORT="${R_PORT:-}"
WEB_PORT="${PORT:-3000}"
UUID="${UUID:-}"
SNI="${R_SNI:-bunny.net}"
DEST="${R_DEST:-bunny.net:443}"
PREFIX="${NODE_PREFIX:-}"
PROBE_URL="${KOMARI_HOST:-}"
PROBE_TOK="${KOMARI_TOKEN:-}"
CERT_URL="${RES_CERT_URL:-}"
KEY_URL="${RES_KEY_URL:-}"
CERT_DOMAIN="${CERT_DOMAIN:-}"
CRON="${CRON:-}"
HY2_OBFS="${HY2_OBFS:-true}"

# 文件路径定义 (混淆名称)
FILE_META="$WORK_DIR/registry.dat"
FILE_TOKEN="$WORK_DIR/identity.key"
FILE_PAIR="$WORK_DIR/transport_pair.bin"
FILE_CERT="$WORK_DIR/tls_cert.pem"
FILE_KEY="$WORK_DIR/tls_key.pem"
FILE_CONF="$WORK_DIR/service_conf.json"
FILE_SUB="$WORK_DIR/blob_storage.dat"
FILE_SID="$WORK_DIR/session_ticket.hex"
FILE_SEC="$WORK_DIR/access_token.key"
WEB_ROOT="$WORK_DIR/www"

# 日志函数
sys_log() {
    echo "[$(date -u +"%T")] [$1] $2"
}

# 依赖检查
check_deps() {
    for cmd in curl jq openssl tar; do
        if ! command -v $cmd >/dev/null 2>&1; then
            echo "Error: Missing dependency $cmd"
            exit 1
        fi
    done
}

# 随机字符串生成
rand_hex() {
    openssl rand -hex "$1"
}

# 下载函数
download_file() {
    local url="$1"
    local dest="$2"
    local min_size="$3"
    local tmp="${dest}.tmp"
    
    if [ -z "$url" ]; then return 1; fi
    
    if curl -L -s --connect-timeout 20 --retry 3 -o "$tmp" "$url"; then
        if [ "$min_size" -gt 0 ]; then
            local size=$(wc -c < "$tmp")
            if [ "$size" -lt "$min_size" ]; then
                rm -f "$tmp"
                return 1
            fi
        fi
        mv "$tmp" "$dest"
        return 0
    else
        rm -f "$tmp"
        return 1
    fi
}

# 获取二进制文件
fetch_bin() {
    local type="$1"
    local meta_key="$type"
    local current_bin=""
    
    # 读取meta缓存
    if [ -f "$FILE_META" ]; then
        current_bin=$(jq -r --arg k "$meta_key" '.[$k] // empty' "$FILE_META")
    fi
    
    if [ -n "$current_bin" ] && [ -f "$WORK_DIR/$current_bin" ]; then
        echo "$WORK_DIR/$current_bin"
        return 0
    fi
    
    # 架构检测
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
        # Core Service (Sing-box)
        local tag=$(curl -s -H "User-Agent: Node" "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | jq -r .tag_name)
        if [ "$tag" = "null" ] || [ -z "$tag" ]; then tag="v1.12.13"; fi
        local ver=${tag#v}
        dl_url="https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${ver}-linux-${arch}.tar.gz"
        bin_name="S${ver//./}_${rand}"
    else
        # Monitor Agent (Komari)
        local tag=$(curl -s -H "User-Agent: Node" "https://api.github.com/repos/komari-monitor/komari-agent/releases/latest" | jq -r .tag_name)
        if [ "$tag" = "null" ] || [ -z "$tag" ]; then tag="latest"; fi
        local ver="000"
        if [ "$tag" != "latest" ]; then ver=${tag#v}; ver=${ver//./}; fi
        dl_url="https://github.com/komari-monitor/komari-agent/releases/download/${tag}/komari-agent-linux-${arch}"
        if [ "$tag" = "latest" ]; then dl_url="https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${arch}"; fi
        bin_name="K${ver}_${rand}"
    fi
    
    local tmp_dl="$WORK_DIR/dl_${rand}"
    
    if download_file "$dl_url" "$tmp_dl" 1000000; then
        local final_path="$WORK_DIR/$bin_name"
        
        if [ "$type" = "srv" ]; then
            local tmp_ext="$WORK_DIR/ext_${rand}"
            mkdir -p "$tmp_ext"
            tar -xzf "$tmp_dl" -C "$tmp_ext"
            local found_bin=$(find "$tmp_ext" -type f -name "sing-box" | head -n 1)
            if [ -n "$found_bin" ]; then
                mv "$found_bin" "$final_path"
            fi
            rm -rf "$tmp_ext"
        else
            mv "$tmp_dl" "$final_path"
        fi
        rm -f "$tmp_dl"
        
        if [ -f "$final_path" ]; then
            chmod 755 "$final_path"
            # 更新Meta
            if [ -f "$FILE_META" ]; then
                local tmp_meta=$(mktemp)
                jq --arg k "$meta_key" --arg v "$bin_name" '.[$k] = $v' "$FILE_META" > "$tmp_meta" && mv "$tmp_meta" "$FILE_META"
            else
                echo "{\"$meta_key\": \"$bin_name\"}" > "$FILE_META"
            fi
            echo "$final_path"
            return 0
        fi
    fi
    return 1
}

# 核心逻辑
main() {
    check_deps
    
    # 清理旧文件
    find "$WORK_DIR" -type f -name "dl_*" -delete
    find "$WORK_DIR" -type d -name "ext_*" -exec rm -rf {} +
    
    sys_log "Init" "Checking binary resources..."
    local bin_srv=$(fetch_bin "srv")
    local bin_mon=$(fetch_bin "mon")
    
    if [ -z "$bin_srv" ]; then
        sys_log "ERR" "Core binary download failed."
        exit 1
    fi
    
    # 环境准备
    if [ -z "$UUID" ]; then
        if [ -f "$FILE_TOKEN" ]; then
            UUID=$(cat "$FILE_TOKEN")
        else
            if uuidgen >/dev/null 2>&1; then UUID=$(uuidgen); else UUID=$(cat /proc/sys/kernel/random/uuid); fi
            echo "$UUID" > "$FILE_TOKEN"
        fi
    fi
    
    # Reality Keypair
    if [ ! -f "$FILE_PAIR" ]; then
        "$bin_srv" generate reality-keypair > "$FILE_PAIR" 2>/dev/null
    fi
    local pk=$(grep "PrivateKey" "$FILE_PAIR" | awk '{print $2}')
    local pub=$(grep "PublicKey" "$FILE_PAIR" | awk '{print $2}')
    
    # Secrets
    if [ -f "$FILE_SEC" ]; then
        local sec_key=$(cat "$FILE_SEC")
    else
        local sec_key=$(rand_hex 16)
        echo "$sec_key" > "$FILE_SEC"
    fi
    
    if [ -f "$FILE_SID" ]; then
        local sid=$(cat "$FILE_SID")
    else
        local sid=$(rand_hex 4)
        echo "$sid" > "$FILE_SID"
    fi
    
    # TLS Assets
    local tls_ready=0
    if [ -n "$CERT_URL" ] && [ -n "$KEY_URL" ]; then
        sys_log "Init" "Syncing assets..."
        download_file "$CERT_URL" "$FILE_CERT" 0
        download_file "$KEY_URL" "$FILE_KEY" 0
    fi
    
    if [ -f "$FILE_CERT" ] && [ -f "$FILE_KEY" ]; then
        if grep -q "BEGIN CERTIFICATE" "$FILE_CERT"; then tls_ready=1; fi
    fi
    
    if [ "$tls_ready" -eq 0 ] && [ -n "$CERT_DOMAIN" ]; then
        sys_log "Init" "Generating self-signed cert..."
        "$bin_srv" generate tls-keypair "$CERT_DOMAIN" > "$WORK_DIR/temp_cert" 2>/dev/null
        awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/' "$WORK_DIR/temp_cert" > "$FILE_KEY"
        awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$WORK_DIR/temp_cert" > "$FILE_CERT"
        rm -f "$WORK_DIR/temp_cert"
        tls_ready=1
    fi
    
    # 构建配置 JSON
    local inbound_json=""
    local listen_ip="0.0.0.0"
    
    # Tuic
    if [ -n "$T_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        inbound_json="${inbound_json} {
            \"type\": \"tuic\", \"listen\": \"$listen_ip\", \"listen_port\": $T_PORT,
            \"users\": [{\"uuid\": \"$UUID\", \"password\": \"$sec_key\"}],
            \"congestion_control\": \"bbr\",
            \"tls\": {\"enabled\": true, \"certificate_path\": \"$FILE_CERT\", \"key_path\": \"$FILE_KEY\", \"alpn\": [\"h3\"]}
        },"
    fi
    
    # Hysteria2
    if [ -n "$H_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        local obfs_json=""
        if [ "$HY2_OBFS" = "true" ]; then
            obfs_json="\"obfs\": {\"type\": \"salamander\", \"password\": \"$sec_key\"},"
        fi
        inbound_json="${inbound_json} {
            \"type\": \"hysteria2\", \"listen\": \"$listen_ip\", \"listen_port\": $H_PORT,
            \"users\": [{\"password\": \"$UUID\"}],
            \"masquerade\": \"https://bing.com\",
            \"tls\": {\"enabled\": true, \"certificate_path\": \"$FILE_CERT\", \"key_path\": \"$FILE_KEY\"},
            \"ignore_client_bandwidth\": false,
            $obfs_json
            \"xx\": 0
        },"
    fi
    
    # Vless/Reality
    if [ -n "$R_PORT" ]; then
        local s_host=$(echo "$DEST" | cut -d: -f1)
        local s_port=$(echo "$DEST" | cut -d: -f2)
        if [ -z "$s_port" ] || [ "$s_port" = "$s_host" ]; then s_port=443; fi
        
        inbound_json="${inbound_json} {
            \"type\": \"vless\", \"listen\": \"$listen_ip\", \"listen_port\": $R_PORT,
            \"users\": [{\"uuid\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}],
            \"tls\": {
                \"enabled\": true, \"server_name\": \"$SNI\",
                \"reality\": {
                    \"enabled\": true, \"handshake\": {\"server\": \"$s_host\", \"server_port\": $s_port},
                    \"private_key\": \"$pk\", \"short_id\": [\"$sid\"]
                }
            }
        },"
    fi
    
    # 清理末尾逗号 hack
    inbound_json=$(echo "$inbound_json" | sed 's/,}/}/g' | sed 's/,\s*$//')
    
    cat > "$FILE_CONF" <<EOF
{
  "log": {"disabled": true, "level": "warn", "timestamp": true},
  "inbounds": [$inbound_json],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
EOF

    # 获取 IP
    local pub_ip="127.0.0.1"
    pub_ip=$(curl -s --connect-timeout 3 https://api.ipify.org || echo "127.0.0.1")
    sys_log "Net" "Server IP: $pub_ip"
    
    # 生成链接
    local links=""
    if [ -n "$T_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        links="${links}tuic://${UUID}:${sec_key}@${pub_ip}:${T_PORT}?sni=${CERT_DOMAIN}&alpn=h3&congestion_control=bbr#${PREFIX}-T\n"
    fi
    if [ -n "$H_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        local h_params="sni=${CERT_DOMAIN}&insecure=1"
        if [ "$HY2_OBFS" = "true" ]; then h_params="${h_params}&obfs=salamander&obfs-password=${sec_key}"; fi
        links="${links}hysteria2://${UUID}@${pub_ip}:${H_PORT}/?${h_params}#${PREFIX}-H\n"
    fi
    if [ -n "$R_PORT" ]; then
        links="${links}vless://${UUID}@${pub_ip}:${R_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=edge&pbk=${pub}&sid=${sid}&type=tcp#${PREFIX}-R\n"
    fi
    
    local b64=$(echo -e "$links" | base64 | tr -d '\n')
    echo "$b64" > "$FILE_SUB"
    
    sys_log "Sys" "Service initialized"
    echo ""
    echo "========== ACCESS TOKEN =========="
    echo "$b64"
    echo "=================================="
    echo ""

    # 准备 Web 服务目录
    rm -rf "$WEB_ROOT"
    mkdir -p "$WEB_ROOT/api"
    
    # 生成 HTML
    cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html><html><head><title>Service Status</title></head><body><h3>Service Operational</h3><p>The backend interface is running normally.</p></body></html>
EOF
    
    # 放置订阅文件
    cp "$FILE_SUB" "$WEB_ROOT/api/data"
    
    # 放置心跳文件
    echo '{"status":"OK"}' > "$WEB_ROOT/api/heartbeat"

    # 启动进程
    sys_log "Sys" "Starting Core..."
    export GOGC=80
    "$bin_srv" run -c "$FILE_CONF" >/dev/null 2>&1 &
    PID_SRV=$!
    
    PID_MON=""
    if [ -n "$bin_mon" ] && [ -n "$PROBE_URL" ]; then
        local mon_url="$PROBE_URL"
        if echo "$mon_url" | grep -v -q "^http"; then mon_url="https://$mon_url"; fi
        sys_log "Sys" "Starting Monitor..."
        "$bin_mon" -e "$mon_url" -t "$PROBE_TOK" >/dev/null 2>&1 &
        PID_MON=$!
    fi
    
    sys_log "Web" "Service running on $WEB_PORT"
    # 使用 busybox httpd 提供轻量级 Web 服务
    busybox httpd -p "$WEB_PORT" -h "$WEB_ROOT"
    
    # 守护进程与CRON逻辑
    while true; do
        if ! kill -0 $PID_SRV 2>/dev/null; then
             sys_log "ERR" "Core crashed, restarting..."
             "$bin_srv" run -c "$FILE_CONF" >/dev/null 2>&1 &
             PID_SRV=$!
        fi
        
        if [ -n "$PID_MON" ] && ! kill -0 $PID_MON 2>/dev/null; then
             sys_log "ERR" "Monitor crashed, restarting..."
             "$bin_mon" -e "$PROBE_URL" -t "$PROBE_TOK" >/dev/null 2>&1 &
             PID_MON=$!
        fi
        
        # 刷新心跳
        local tick=$(($(date +%s) - $(date -r "$FILE_CONF" +%s)))
        echo "{\"status\":\"OK\",\"tick\":$tick}" > "$WEB_ROOT/api/heartbeat"
        
        # 简单的 Cron 重启逻辑 (UTC+8 06:30)
        if [ -n "$CRON" ]; then
            current_hour=$(date -u -d "+8 hours" +%H)
            current_min=$(date -u -d "+8 hours" +%M)
            if [ "$current_hour" = "06" ] && [ "$current_min" = "30" ]; then
                 sys_log "Sys" "Scheduled restart..."
                 kill $PID_SRV 2>/dev/null
                 if [ -n "$PID_MON" ]; then kill $PID_MON 2>/dev/null; fi
                 sleep 65 # 避免一分钟内重复重启
            fi
        fi
        
        sleep 10
    done
}

main
