FROM alpine:latest

# 安装基础依赖
RUN apk add --no-cache curl jq openssl ca-certificates tar libstdc++ gcompat busybox-extras

WORKDIR /app
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

ENV DATA_PATH="/app/data" \
    PORT=3000

VOLUME ["/app/data"]
ENTRYPOINT ["/app/entrypoint.sh"]
