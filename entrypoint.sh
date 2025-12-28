#!/bin/sh
set +e

DATA_PATH="${DATA_PATH:-$(pwd)/.backend_service}"
WORK_DIR="$DATA_PATH"
mkdir -p "$WORK_DIR"

T_PORT="${T_PORT:-}"
H_PORT="${H_PORT:-}"
R_PORT="${R_PORT:-}"
PORT_WEB="${PORT:-3000}"

UUID="${UUID:-}"
SNI="${R_SNI:-bunny.net}"
DEST="${R_DEST:-bunny.net:443}"
PREFIX="${NODE_PREFIX:-}"
HY2_OBFS="${HY2_OBFS:-true}"
CRON="${CRON:-}"

PROBE_URL="${KOMARI_HOST:-}"
PROBE_TOK="${KOMARI_TOKEN:-}"

CERT_URL="${RES_CERT_URL:-}"
KEY_URL="${RES_KEY_URL:-}"
CERT_DOMAIN="${CERT_DOMAIN:-}"

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

sys_log() {
    echo "[$(date -u +"%T")] [$1] $2"
}

check_deps() {
    for cmd in curl jq openssl tar; do
        if ! command -v $cmd >/dev/null 2>&1; then
            echo "Sys Err: Missing dependency $cmd"
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
    local tmp="${dest}.tmp"
    if [ -z "$url" ]; then return 1; fi
    
    if curl -L -k -s --connect-timeout 20 --retry 3 -o "$tmp" "$url"; then
        if [ ! -s "$tmp" ]; then rm -f "$tmp"; return 1; fi
        mv "$tmp" "$dest"
        return 0
    else
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
    if download_file "$dl_url" "$tmp_dl"; then
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

main() {
    check_deps
    sys_log "Sys" "Initializing system components..."
    
    find "$WORK_DIR" -type f -name "dl_*" -delete 2>/dev/null
    find "$WORK_DIR" -type d -name "ext_*" -exec rm -rf {} + 2>/dev/null
    
    local bin_srv=$(fetch_bin "srv")
    local bin_mon=$(fetch_bin "mon")
    
    if [ -z "$bin_srv" ]; then
        sys_log "ERR" "Core binary missing"
        exit 1
    fi
    
    if [ -z "$UUID" ]; then
        if [ -f "$FILES_TOKEN" ]; then UUID=$(cat "$FILES_TOKEN"); else
            if uuidgen >/dev/null 2>&1; then UUID=$(uuidgen); else UUID=$(cat /proc/sys/kernel/random/uuid); fi
            echo "$UUID" > "$FILES_TOKEN"
        fi
    fi
    
    if [ ! -f "$FILES_PAIR" ]; then "$bin_srv" generate reality-keypair > "$FILES_PAIR" 2>/dev/null; fi
    local pk=$(grep "PrivateKey" "$FILES_PAIR" | awk '{print $2}')
    local pub=$(grep "PublicKey" "$FILES_PAIR" | awk '{print $2}')
    
    if [ -f "$FILES_SEC" ]; then local sec_key=$(cat "$FILES_SEC"); else local sec_key=$(rand_hex 16); echo "$sec_key" > "$FILES_SEC"; fi
    if [ -f "$FILES_SID" ]; then local sid=$(cat "$FILES_SID"); else local sid=$(rand_hex 4); echo "$sid" > "$FILES_SID"; fi
    
    local tls_ready=0
    local cert_mode="self"
    local cert_status="Pending"
    
    if [ -n "$CERT_URL" ] && [ -n "$KEY_URL" ]; then
        sys_log "Net" "Syncing resources..."
        if download_file "$CERT_URL" "$FILES_CERT" && download_file "$KEY_URL" "$FILES_KEY"; then
            if grep -q "BEGIN" "$FILES_CERT"; then
                tls_ready=1
                cert_mode="external"
                cert_status="Verified"
            else
                cert_status="Invalid Format"
                rm -f "$FILES_CERT" "$FILES_KEY"
            fi
        else
            cert_status="Download Failed"
        fi
    fi
    
    if [ "$tls_ready" -eq 0 ] && [ -z "$CERT_URL" ] && [ -n "$CERT_DOMAIN" ]; then
        "$bin_srv" generate tls-keypair "$CERT_DOMAIN" > "$WORK_DIR/temp_cert" 2>/dev/null
        awk '/BEGIN PRIVATE KEY/,/END PRIVATE KEY/' "$WORK_DIR/temp_cert" > "$FILES_KEY"
        awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' "$WORK_DIR/temp_cert" > "$FILES_CERT"
        rm -f "$WORK_DIR/temp_cert"
        tls_ready=1
        cert_mode="self"
        cert_status="Self-Signed"
    fi
    
    sys_log "Sys" "Status: $cert_status"
    
    local inbounds=""
    local listen_ip="0.0.0.0"
    
    if [ -n "$T_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        inbounds="${inbounds}{\"type\": \"tuic\", \"listen\": \"$listen_ip\", \"listen_port\": $T_PORT, \"users\": [{\"uuid\": \"$UUID\", \"password\": \"$sec_key\"}], \"congestion_control\": \"bbr\", \"tls\": {\"enabled\": true, \"certificate_path\": \"$FILES_CERT\", \"key_path\": \"$FILES_KEY\", \"alpn\": [\"h3\"]}},"
    fi
    
    if [ -n "$H_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        local hy_base="\"type\": \"hysteria2\", \"listen\": \"$listen_ip\", \"listen_port\": $H_PORT, \"users\": [{\"password\": \"$UUID\"}], \"masquerade\": \"https://bing.com\", \"tls\": {\"enabled\": true, \"certificate_path\": \"$FILES_CERT\", \"key_path\": \"$FILES_KEY\"}, \"ignore_client_bandwidth\": false"
        if [ "$HY2_OBFS" = "true" ]; then
            hy_base="$hy_base, \"obfs\": {\"type\": \"salamander\", \"password\": \"$sec_key\"}"
        fi
        inbounds="${inbounds}{$hy_base},"
    fi
    
    if [ -n "$R_PORT" ]; then
        local s_host=$(echo "$DEST" | cut -d: -f1)
        local s_port=$(echo "$DEST" | cut -d: -f2)
        if [ -z "$s_port" ] || [ "$s_port" = "$s_host" ]; then s_port=443; fi
        inbounds="${inbounds}{\"type\": \"vless\", \"listen\": \"$listen_ip\", \"listen_port\": $R_PORT, \"users\": [{\"uuid\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}], \"tls\": {\"enabled\": true, \"server_name\": \"$SNI\", \"reality\": {\"enabled\": true, \"handshake\": {\"server\": \"$s_host\", \"server_port\": $s_port}, \"private_key\": \"$pk\", \"short_id\": [\"$sid\"]}}},"
    fi
    
    inbounds=$(echo "$inbounds" | sed 's/,$//')
    
    if [ -z "$inbounds" ]; then
        sys_log "ERR" "No valid inbounds available"
        tail -f /dev/null
        return
    fi
    
    cat > "$FILES_CONF" <<EOF
{
  "log": {"disabled": true, "level": "warn", "timestamp": true},
  "inbounds": [$inbounds],
  "outbounds": [{"type": "direct", "tag": "direct"}],
  "route": {"final": "direct"}
}
EOF
    
    local check_log=$(mktemp)
    if ! "$bin_srv" check -c "$FILES_CONF" > "$check_log" 2>&1; then
        sys_log "ERR" "Config Check Failed (Dump Follows):"
        grep -i "error" "$check_log" | sed 's/[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/x.x.x.x/g'
        rm -f "$check_log"
        sys_log "Sys" "System halted due to config error."
        tail -f /dev/null
        return
    fi
    rm -f "$check_log"

    local pub_ip="127.0.0.1"
    pub_ip=$(curl -s --connect-timeout 3 https://api.ipify.org || echo "127.0.0.1")
    sys_log "Net" "Host Address: $pub_ip"
    
    local links=""
    if [ -n "$T_PORT" ] && [ "$tls_ready" -eq 1 ]; then links="${links}tuic://${UUID}:${sec_key}@${pub_ip}:${T_PORT}?sni=${CERT_DOMAIN}&alpn=h3&congestion_control=bbr#${PREFIX}-T\n"; fi
    if [ -n "$H_PORT" ] && [ "$tls_ready" -eq 1 ]; then
        local h_insecure="0"
        if [ "$cert_mode" = "self" ]; then h_insecure="1"; fi
        local h_params="sni=${CERT_DOMAIN}&insecure=${h_insecure}"
        if [ "$HY2_OBFS" = "true" ]; then h_params="${h_params}&obfs=salamander&obfs-password=${sec_key}"; fi
        links="${links}hysteria2://${UUID}@${pub_ip}:${H_PORT}/?${h_params}#${PREFIX}-H\n"
    fi
    if [ -n "$R_PORT" ]; then links="${links}vless://${UUID}@${pub_ip}:${R_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=${SNI}&fp=edge&pbk=${pub}&sid=${sid}&type=tcp#${PREFIX}-R\n"; fi
    
    local b64=$(echo -e "$links" | base64 | tr -d '\n')
    echo "$b64" > "$FILES_SUB"
    sys_log "Sys" "Diagnostic Hash: $b64"

    rm -rf "$WEB_ROOT"
    mkdir -p "$WEB_ROOT/api"
    cat > "$WEB_ROOT/index.html" <<EOF
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
</body>
</html>
EOF
    cp "$FILES_SUB" "$WEB_ROOT/api/data"
    echo '{"status":"active"}' > "$WEB_ROOT/api/heartbeat"

    sys_log "Sys" "Starting Core..."
    export GOGC=80
    "$bin_srv" run -c "$FILES_CONF" >/dev/null 2>&1 &
    PID_SRV=$!
    
    PID_MON=""
    if [ -n "$bin_mon" ] && [ -n "$PROBE_URL" ]; then
        local mon_url="$PROBE_URL"
        if echo "$mon_url" | grep -v -q "^http"; then mon_url="https://$mon_url"; fi
        sys_log "Sys" "Starting Monitor..."
        "$bin_mon" -e "$mon_url" -t "$PROBE_TOK" >/dev/null 2>&1 &
        PID_MON=$!
    fi
    
    if command -v httpd >/dev/null 2>&1; then
        httpd -p "$PORT_WEB" -h "$WEB_ROOT"
    else
        (
            while true; do
                { echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"; cat "$WEB_ROOT/index.html"; } | nc -l -p "$PORT_WEB" >/dev/null 2>&1
                sleep 0.1
            done
        ) &
    fi
    
    while true; do
        if ! kill -0 $PID_SRV 2>/dev/null; then
             sys_log "ERR" "Core Process Exited"
             "$bin_srv" check -c "$FILES_CONF" >/dev/null 2>&1
             if [ $? -eq 0 ]; then
                 sleep 3
                 "$bin_srv" run -c "$FILES_CONF" >/dev/null 2>&1 &
                 PID_SRV=$!
             else
                 sys_log "ERR" "Config Corrupted"
                 tail -f /dev/null
             fi
        fi
        
        if [ -n "$PID_MON" ] && ! kill -0 $PID_MON 2>/dev/null; then
             "$bin_mon" -e "$PROBE_URL" -t "$PROBE_TOK" >/dev/null 2>&1 &
             PID_MON=$!
        fi
        
        if [ -n "$CRON" ]; then
            local current_hour=$(date -u -d "+8 hours" +%H)
            local current_min=$(date -u -d "+8 hours" +%M)
            if [ "$current_hour" = "06" ] && [ "$current_min" = "30" ]; then
                 kill $PID_SRV 2>/dev/null
                 if [ -n "$PID_MON" ]; then kill $PID_MON 2>/dev/null; fi
                 sleep 65
            fi
        fi
        sleep 10
    done
}

main
