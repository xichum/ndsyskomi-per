FROM alpine:latest

# 安装必要依赖
# curl: 下载文件
# jq: 解析GitHub API JSON
# openssl: 生成随机数和UUID
# ca-certificates: HTTPS支持
# tar: 解压资源
RUN apk add --no-cache curl jq openssl ca-certificates tar libstdc++ gcompat

# 设置工作目录
WORKDIR /app

# 复制脚本
COPY entrypoint.sh /app/entrypoint.sh

# 权限设置
RUN chmod +x /app/entrypoint.sh

# 环境变量默认值
ENV DATA_PATH="/app/data" \
    PORT=3000

# 创建数据目录挂载点
VOLUME ["/app/data"]

# 入口点
ENTRYPOINT ["/app/entrypoint.sh"]
