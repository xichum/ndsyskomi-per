FROM alpine:latest

# 设置环境与语言
ENV LANG=C.UTF-8 \
    TZ=Asia/Shanghai

# 安装依赖
RUN apk add --no-cache \
    bash \
    curl \
    openssl \
    tar \
    ca-certificates \
    netcat-openbsd \
    coreutils \
    grep \
    sed

WORKDIR /app

COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
