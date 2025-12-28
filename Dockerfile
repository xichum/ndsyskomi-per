FROM alpine:latest

# 安装依赖
RUN apk add --no-cache curl jq openssl ca-certificates tar libstdc++ gcompat busybox-extras

# 设置工作目录
WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh

# 权限设置
RUN chmod +x /app/entrypoint.sh

# 环境变量默认值 (设置默认 R_PORT 防止链接为空)
ENV DATA_PATH="/app/data" \
    PORT=3000 \
    R_PORT=8080

# 创建数据目录挂载点
VOLUME ["/app/data"]

# 入口点
ENTRYPOINT ["/app/entrypoint.sh"]
