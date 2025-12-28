#!/bin/bash

IS_SILENT=false

DEFAULT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.backend_service"
TARGET_DIR="${DATA_PATH:-$DEFAULT_PATH}"

# 检测权限与创建目录
if ! mkdir -p "$TARGET_DIR" 2>/dev/null || [ ! -w "$TARGET_DIR" ]; then
    # 权限不足，降级处理
    WORK_DIR="/tmp/backend_service_fallback"
    mkdir -p "$WORK_DIR"
    FALLBACK_TRIGGERED=true
else
    WORK_DIR="$TARGET_DIR"
    FALLBACK_TRIGGERED=false
fi

# 文件路径定义
FILE_META="$WORK_DIR/registry.dat"
FILE_TOKEN="$WORK_DIR/identity.key"
FILE_KEYPAIR="$WORK_DIR/transport_pair.bin"
FILE_CERT="$WORK_DIR/tls_cert.pem"
FILE_KEY="$WORK_DIR/tls_key.pem"
FILE_CONF="$WORK_DIR/service_conf.json"
FILE_SUB="$WORK_DIR/blob_storage.dat"
FILE_SID="$WORK_DIR/session_ticket.hex"
FILE_SEC_KEY="$WORK_DIR/access_token.key"

# -----------------------------------------------------------------------------
# 2. 基础工具 (Utils)
# -----------------------------------------------------------------------------
sys_log() {
    local type="$1"
    local msg="$2"
    if [ "$IS_SILENT" = true ] && [ "$type" != "ERR" ]; then return; fi
    echo "[$(date -u +"%Y-%m-%dT%H:%M:%S")] [$type] $msg"
}

check_deps() {
    local deps=("curl" "tar" "grep" "sed" "openssl" "base64" "nc" "timeout")
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Error: Required command '$cmd' not found."
            exit 1
        fi
    done
}
check_deps

save_file() {
    local f="$1" d="$2" m="${3:-644}" tmp="$f.$(date +%s).tmp"
    echo -n "$d" > "$tmp"
    chmod "$m" "$tmp"
    mv -f "$tmp" "$f" 2>/dev/null || rm -f "$tmp"
}

disk_clean() {
    local keep_paths=("$@")
    local keep_set=()
    for p in "${keep_paths[@]}"; do [ -n "$p" ] && keep_set+=("$(readlink -f "$p")"); done
    local known_files=("$FILE_META" "$FILE_TOKEN" "$FILE_KEYPAIR" "$FILE_CERT" "$FILE_KEY" "$FILE_CONF" "$FILE_SUB" "$FILE_SID" "$FILE_SEC_KEY")
    for f in "$WORK_DIR"/*; do
        [ -e "$f" ] || continue
        local abs_f=$(readlink -f "$f")
        local fname=$(basename "$f")
        local is_known=false
        for k in "${known_files[@]}"; do if [ "$abs_f" == "$k" ]; then is_known=true; break; fi; done
        if [ "$is_known" = true ]; then continue; fi
        local is_keep=false
        for k in "${keep_set[@]}"; do if [ "$abs_f" == "$k" ]; then is_keep=true; break; fi; done
        if [[ "$fname" == S* || "$fname" == K* ]]; then
            if [ "$is_keep" = false ]; then rm -f "$abs_f"; fi
        elif [[ "$fname" == dl_* || "$fname" == ext_* || "$fname" == *.tmp ]]; then
             rm -rf "$abs_f"
        fi
    done
}

download() {
    local url="$1" dest="$2" min_size="${3:-0}"
    if [ -z "$url" ]; then return 1; fi
    local tmp="$dest.$(date +%s).dl"
    if curl -L -s -f --connect-timeout 20 --max-time 300 -o "$tmp" "$url"; then
        local size=$(stat -c%s "$tmp" 2>/dev/null || echo 0)
        if [ "$size" -ge "$min_size" ]; then mv -f "$tmp" "$dest"; return 0; fi
    fi
    rm -f "$tmp"; return 1
}

# -----------------------------------------------------------------------------
# 3. 环境变量与状态 (Env & State)
# -----------------------------------------------------------------------------
PORT_T="${T_PORT:-}"
PORT_H="${H_PORT:-}"
PORT_R="${R_PORT:-20343}"
PORT_WEB="${PORT:-3000}"
UUID_ENV="${UUID:-}"
SNI="${R_SNI:-web.c-servers.co.uk}"
DEST="${R_DEST:-web.c-servers.co.uk:443}"
PREFIX="${NODE_PREFIX:-}"
PROBE_URL="${KOMARI_HOST:-komari.myn.dpdns.org}"
PROBE_TOK="${KOMARI_TOKEN:-OGBATJH6FRF2my9f7eVd7y}"
CERT_URL="${RES_CERT_URL:-}"
KEY_URL="${RES_KEY_URL:-}"
CERT_DOMAIN="${CERT_DOMAIN:-}"
CRON="${CRON:-}"
HY2_OBFS="${HY2_OBFS:-false}"

UUID_ENV=$(echo "$UUID_ENV" | xargs)
SNI=$(echo "$SNI" | xargs)
DEST=$(echo "$DEST" | xargs)
CERT_DOMAIN=$(echo "$CERT_DOMAIN" | xargs)
HY2_OBFS=$(echo "$HY2_OBFS" | xargs)

declare -A STATE_PID STATE_CRASH_COUNT STATE_LAST_START
STATE_PID["srv"]=0; STATE_CRASH_COUNT["srv"]=0; STATE_LAST_START["srv"]=0
STATE_PID["mon"]=0; STATE_CRASH_COUNT["mon"]=0; STATE_LAST_START["mon"]=0

# -----------------------------------------------------------------------------
# 4. 核心逻辑 (Core Logic)
# -----------------------------------------------------------------------------

fetch_bin() {
    local type="$1" meta_val=""
    [ -f "$FILE_META" ] && meta_val=$(grep -o "\"$type\": *\"[^\"]*\"" "$FILE_META" | cut -d'"' -f4)
    local arch=""; case "$(uname -m)" in x86_64) arch="amd64" ;; aarch64|arm64) arch="arm64" ;; s390x) arch="s390x" ;; esac
    [ -z "$arch" ] && return 1
    if [ -n "$meta_val" ] && [ -f "$WORK_DIR/$meta_val" ]; then echo "$WORK_DIR/$meta_val"; return 0; fi
    
    local targets=() rand=$(openssl rand -hex 4)
    if [ "$type" == "srv" ]; then
        local tag_data=$(curl -s -H "User-Agent: Node" "https://api.github.com/repos/SagerNet/sing-box/releases/latest" || echo "")
        local tag=$(echo "$tag_data" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
        [ -n "$tag" ] && { local v="${tag#v}"; targets+=("https://github.com/SagerNet/sing-box/releases/download/${tag}/sing-box-${v}-linux-${arch}.tar.gz|S${v//./}_${rand}"); }
        targets+=("https://github.com/SagerNet/sing-box/releases/download/v1.12.13/sing-box-1.12.13-linux-${arch}.tar.gz|S11213_${rand}")
    else
        local tag_data=$(curl -s -H "User-Agent: Node" "https://api.github.com/repos/komari-monitor/komari-agent/releases/latest" || echo "")
        local tag=$(echo "$tag_data" | grep -o '"tag_name": *"[^"]*"' | head -1 | cut -d'"' -f4)
        [ -n "$tag" ] && { local v="${tag#v}"; targets+=("https://github.com/komari-monitor/komari-agent/releases/download/${tag}/komari-agent-linux-${arch}|K${v//./}_${rand}"); }
        targets+=("https://github.com/komari-monitor/komari-agent/releases/latest/download/komari-agent-linux-${arch}|K000_${rand}")
    fi

    for item in "${targets[@]}"; do
        local url="${item%|*}" name="${item#*|}" tmp_dl="$WORK_DIR/dl_$(openssl rand -hex 4)"
        local min_s=1000000; [ "$type" == "srv" ] && min_s=2000000
        if download "$url" "$tmp_dl" "$min_s"; then
            local final_path=""
            if [ "$type" == "srv" ]; then
                local tmp_ext="$WORK_DIR/ext_$(openssl rand -hex 4)"
                mkdir -p "$tmp_ext"
                if tar -xzf "$tmp_dl" -C "$tmp_ext" 2>/dev/null; then
                    local bin=$(find "$tmp_ext" -type f -name "sing-box" | head -1)
                    [ -n "$bin" ] && final_path="$WORK_DIR/$name" && mv "$bin" "$final_path"
                fi
                rm -rf "$tmp_ext"
            else
                final_path="$WORK_DIR/$name" && mv "$tmp_dl" "$final_path"
            fi
            rm -f "$tmp_dl"
            if [ -n "$final_path" ]; then
                chmod 755 "$final_path"
                # 兼容性自检
                if ! "$final_path" version >/dev/null 2>&1; then
                    sys_log "ERR" "Binary compatible check failed (gcompat missing?)."
                    rm -f "$final_path"
                    continue
                fi
                local fname=$(basename "$final_path")
                if grep -q "\"$type\"" "$FILE_META" 2>/dev/null; then
                     sed -i "s/\"$type\": *\"[^\"]*\"/\"$type\": \"$fname\"/" "$FILE_META"
                else
                     echo "{\"$type\": \"$fname\"}" > "$FILE_META"
                fi
                echo "$final_path"; return 0
            fi
        fi
    done
    return 1
}

prepare_env() {
    local bin_srv="$1"
    
    if [ "$FALLBACK_TRIGGERED" = true ]; then
        sys_log "Dsk" "Storage fallback active: $WORK_DIR"
    else
        sys_log "Dsk" "Data Path: $WORK_DIR"
    fi
    
    # UUID
    local uuid="$UUID_ENV"
    if [ -z "$uuid" ]; then
        if [ -f "$FILE_TOKEN" ]; then uuid=$(cat "$FILE_TOKEN" | xargs); else
            if ! uuid=$("$bin_srv" generate uuid 2>/dev/null); then uuid=$(cat /proc/sys/kernel/random/uuid); fi
            save_file "$FILE_TOKEN" "$uuid"
        fi
    fi
    
    # Reality Keys
    local priv pub
    gen_keys() { "$bin_srv" generate reality-keypair > "$FILE_KEYPAIR"; }
    [ ! -f "$FILE_KEYPAIR" ] && gen_keys
    priv=$(grep "PrivateKey" "$FILE_KEYPAIR" | awk '{print $2}')
    pub=$(grep "PublicKey" "$FILE_KEYPAIR" | awk '{print $2}')
    
    if [ -z "$priv" ]; then 
        gen_keys
        priv=$(grep "PrivateKey" "$FILE_KEYPAIR" | awk '{print $2}')
        pub=$(grep "PublicKey" "$FILE_KEYPAIR" | awk '{print $2}')
        if [ -z "$priv" ]; then sys_log "FATAL" "Keygen failed"; exit 1; fi
    fi

    local sec_key short_id
    [ -f "$FILE_SEC_KEY" ] && sec_key=$(cat "$FILE_SEC_KEY" | xargs) || { sec_key=$(openssl rand -hex 16); save_file "$FILE_SEC_KEY" "$sec_key"; }
    [ -f "$FILE_SID" ] && short_id=$(cat "$FILE_SID" | xargs) || { short_id=$(openssl rand -hex 4); save_file "$FILE_SID" "$short_id"; }

    check_tls() { [ -f "$FILE_CERT" ] && [ -f "$FILE_KEY" ] && grep -q "BEGIN CERTIFICATE" "$FILE_CERT"; }
    if { [ -n "$PORT_T" ] || [ -n "$PORT_H" ]; }; then
        if [ -n "$CERT_URL" ] && [ -n "$KEY_URL" ]; then 
            sys_log "Sec" "Syncing remote security assets..."
            download "$CERT_URL" "$FILE_CERT" && download "$KEY_URL" "$FILE_KEY"
        fi
        if ! check_tls; then
             local out=$("$bin_srv" generate tls-keypair "$CERT_DOMAIN" 2>/dev/null)
             local k=$(echo "$out" | sed -n '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/p')
             local c=$(echo "$out" | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p')
             [ -n "$k" ] && [ -n "$c" ] && { save_file "$FILE_KEY" "$k" 600; save_file "$FILE_CERT" "$c"; }
        fi
    fi

    local tls_ready=false; check_tls && tls_ready=true
    local listen_ip="0.0.0.0"
    local inbounds=()
    
    if [ -n "$PORT_T" ] && [ "$tls_ready" = true ]; then
        inbounds+=("{\"type\": \"tuic\", \"listen\": \"$listen_ip\", \"listen_port\": $PORT_T, \"users\": [{\"uuid\": \"$uuid\", \"password\": \"$sec_key\"}], \"congestion_control\": \"bbr\", \"tls\": { \"enabled\": true, \"certificate_path\": \"$FILE_CERT\", \"key_path\": \"$FILE_KEY\", \"alpn\": [\"h3\"] }}")
    fi
    if [ -n "$PORT_H" ] && [ "$tls_ready" = true ]; then
        local obfs_part=""
        if [ "$HY2_OBFS" == "true" ]; then obfs_part=", \"obfs\": { \"type\": \"salamander\", \"password\": \"$sec_key\" }"; fi
        inbounds+=("{\"type\": \"hysteria2\", \"listen\": \"$listen_ip\", \"listen_port\": $PORT_H, \"users\": [{\"password\": \"$uuid\"}], \"masquerade\": \"https://bing.com\", \"tls\": { \"enabled\": true, \"certificate_path\": \"$FILE_CERT\", \"key_path\": \"$FILE_KEY\" }, \"ignore_client_bandwidth\": false${obfs_part}}")
    fi
    if [ -n "$PORT_R" ]; then
        local sd="${DEST%:*}"
        local sp="${DEST##*:}"
        [ "$sd" == "$DEST" ] && sp=443
        inbounds+=("{\"type\": \"vless\", \"listen\": \"$listen_ip\", \"listen_port\": $PORT_R, \"users\": [{\"uuid\": \"$uuid\", \"flow\": \"xtls-rprx-vision\"}], \"tls\": { \"enabled\": true, \"server_name\": \"$SNI\", \"reality\": { \"enabled\": true, \"handshake\": { \"server\": \"$sd\", \"server_port\": $sp }, \"private_key\": \"$priv\", \"short_id\": [\"$short_id\"] }}}")
    fi
    
    local inbounds_json=$(IFS=,; echo "${inbounds[*]}")
    cat > "$FILE_CONF" <<EOF
{
  "log": { "disabled": true, "level": "warn", "timestamp": true },
  "inbounds": [ $inbounds_json ],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "final": "direct" }
}
EOF

    local ip="127.0.0.1"
    local ext_ip=$(curl -s --connect-timeout 3 https://api.ipify.org)
    [ -n "$ext_ip" ] && ip=$(echo "$ext_ip" | xargs)
    sys_log "Net" "Public endpoint detected: $ip"
    
    local s=""
    if [ -n "$PORT_T" ] && [ "$tls_ready" = true ]; then
        s+="tuic://${uuid}:${sec_key}@${ip}:${PORT_T}?sni=${CERT_DOMAIN}&alpn=h3&congestion_control=bbr#${PREFIX}-T"$'\n'
    fi
    if [ -n "$PORT_H" ] && [ "$tls_ready" = true ]; then
        s+="hysteria2://${uuid}@${ip}:${PORT_H}/?sni=${CERT_DOMAIN}&insecure=1"
        [ "$HY2_OBFS" == "true" ] && s+="&obfs=salamander&obfs-password=${sec_key}"
        s+="#${PREFIX}-H"$'\n'
    fi
    if [ -n "$PORT_R" ]; then
        s+="vless://${uuid}@${ip}:${PORT_R}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=edge&pbk=${pub}&sid=${short_id}&type=tcp#${PREFIX}-R"$'\n'
    fi
    
    local b64=$(echo -n "$s" | base64 | tr -d '\n')
    save_file "$FILE_SUB" "$b64"
    
    sys_log "Sys" "Service initialized"
    echo ""
    echo "========== SESSION TICKET =========="
    echo "$b64"
    echo "===================================="
    echo ""
}

filter_log() {
    local key="$1" prefix="LinkAgent"
    [ "$key" == "srv" ] && prefix="CoreService"
    while IFS= read -r line; do
        [ ${#line} -lt 5 ] && continue
        echo "$line" | grep -qE "Komari|sing-box|SagerNet|version|Github|DNS|Mountpoints|Interfaces|Using|Checking|Current|Get|Attempting|IPV4" && continue
        local msg="$line"
        msg=${msg/WebSocket/Uplink}; msg=${msg/uploaded/Sync}; msg=${msg/connected/est}
        if echo "$msg" | grep -qE "error|fatal|panic"; then 
            sys_log "ERR" "[$prefix] Runtime exception"
        elif ! $IS_SILENT; then
             sys_log "$prefix" "${msg:0:50}"
        fi
    done
}

spawn_service() {
    local key="$1" bin="$2"; shift 2; local args=("$@")
    local old_pid="${STATE_PID[$key]}"
    if [ "$old_pid" -gt 0 ] && kill -0 "$old_pid" 2>/dev/null; then return; fi
    STATE_LAST_START["$key"]=$(date +%s%3N)
    ("$bin" "${args[@]}" 2>&1 | filter_log "$key") &
    STATE_PID["$key"]=$!
}

NEXT_CRON_TS=0
check_cron() {
    [ -z "$CRON" ] && return
    local now_sec=$(date +%s)
    if [ "$NEXT_CRON_TS" -eq 0 ]; then NEXT_CRON_TS=$((now_sec + 60)); return; fi
    if [ "$now_sec" -ge "$NEXT_CRON_TS" ]; then
        local cron_str="$CRON"
        [[ "$cron_str" == "true" || "$cron_str" == "1" ]] && cron_str="UTC+8 06:30"
        if [[ "$cron_str" =~ UTC([+-]?[0-9]+)[[:space:]]+([0-9]+):([0-9]+) ]]; then
            local off="${BASH_REMATCH[1]}" h="${BASH_REMATCH[2]}" min="${BASH_REMATCH[3]}"
            local utc_now=$(date -u +%s)
            local offset_sec=$((off * 3600))
            local target_zone_now=$((utc_now + offset_sec))
            local target_day=$(date -u -d "@$target_zone_now" +%Y-%m-%d)
            local target_ts=$(date -u -d "$target_day $h:$min:00" +%s)
            [ "$target_ts" -le "$target_zone_now" ] && target_ts=$((target_ts + 86400))
            local wait_until=$((target_ts - offset_sec))
            if [ "$NEXT_CRON_TS" -ne 0 ] && [ "$now_sec" -ge "$NEXT_CRON_TS" ]; then
                [ "${STATE_PID["srv"]}" -gt 0 ] && kill -SIGTERM "${STATE_PID["srv"]}"
                [ "${STATE_PID["mon"]}" -gt 0 ] && kill -SIGTERM "${STATE_PID["mon"]}"
                NEXT_CRON_TS=$wait_until
            elif [ "$NEXT_CRON_TS" -eq 0 ]; then NEXT_CRON_TS=$wait_until; fi
        fi
    fi
}

monitor_loop() {
    local bin_srv="$1" bin_mon="$2"
    export GOGC=80
    local mem_total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    [ "$mem_total" -lt 262144 ] && export GOMEMLIMIT="100MiB"
    spawn_service "srv" "$bin_srv" "run" "-c" "$FILE_CONF"
    if [ -n "$bin_mon" ] && [ -n "$PROBE_URL" ]; then
        sys_log "Mon" "Telemetry agent active"
        local u="$PROBE_URL"; [[ "$u" != http* ]] && u="https://$u"
        spawn_service "mon" "$bin_mon" "-e" "$u" "-t" "$PROBE_TOK"
    fi
    (sleep 60; IS_SILENT=true; sys_log "Sys" "Entering silent mode") &
    while true; do
        local now=$(date +%s%3N)
        for key in "srv" "mon"; do
            [ "$key" == "mon" ] && { [ -z "$bin_mon" ] || [ -z "$PROBE_URL" ]; } && continue
            local pid="${STATE_PID[$key]}" last_start="${STATE_LAST_START[$key]}"
            if ! kill -0 "$pid" 2>/dev/null; then
                 local live_time=$((now - last_start))
                 if [ "$live_time" -gt 30000 ]; then STATE_CRASH_COUNT["$key"]=0; else STATE_CRASH_COUNT["$key"]=$((STATE_CRASH_COUNT["$key"] + 1)); fi
                 local count="${STATE_CRASH_COUNT[$key]}"
                 local delay=$(( 2000 * (2 ** count) )); [ "$delay" -gt 60000 ] && delay=60000
                 local label="Core"; [ "$key" == "mon" ] && label="Agent"
                 sys_log "Sys" "$label reload in $((delay/1000))s"
                 sleep $((delay/1000))
                 if [ "$key" == "srv" ]; then spawn_service "srv" "$bin_srv" "run" "-c" "$FILE_CONF"
                 else spawn_service "mon" "$bin_mon" "-e" "$u" "-t" "$PROBE_TOK"; fi
            fi
        done
        check_cron
        sleep 2
    done
}

start_http_server() {
    local cmd="nc"; command -v netcat &>/dev/null && cmd="netcat"
    sys_log "Web" "Service running on $PORT_WEB"
    while true; do
        { echo -ne "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: auto\r\n\r\n";
          read -t 1 -r line || true
          line=${line%%$'\r'}; local path=$(echo "$line" | awk '{print $2}')
          if [[ "$path" == "/api/data"* ]] && [ -f "$FILE_SUB" ]; then
               cat "$FILE_SUB"
          elif [[ "$path" == "/api/heartbeat" ]]; then
               local pid="${STATE_PID["srv"]}" ok=false
               if [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null; then ok=true; fi
               local status="ERR"; local tick=0
               if [ "$ok" = true ]; then status="OK"; tick=$(( ( $(date +%s%3N) - STATE_LAST_START["srv"] ) / 1000 )); fi
               echo -n "{\"status\": \"$status\", \"tick\": $tick}"
          else
               echo "<!DOCTYPE html><html><head><title>Service Status</title></head><body style=\"font-family:sans-serif;text-align:center;padding:50px;\"><h1>Service Operational</h1><p>The backend interface is running normally.</p></body></html>"
          fi
        } | timeout 3 $cmd -l -p $PORT_WEB >/dev/null 2>&1
        sleep 0.1
    done
}

BIN_SRV=$(fetch_bin "srv")
BIN_MON=$(fetch_bin "mon")
if [ -z "$BIN_SRV" ]; then echo "Fatal: Core binary fetch failed."; exit 1; fi
disk_clean "$BIN_SRV" "$BIN_MON"
prepare_env "$BIN_SRV"
start_http_server &
monitor_loop "$BIN_SRV" "$BIN_MON"
