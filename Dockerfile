FROM alpine:latest

ENV LANG=C.UTF-8 \
    TZ=Asia/Shanghai

RUN apk add --no-cache \
    bash \
    curl \
    openssl \
    tar \
    ca-certificates \
    netcat-openbsd \
    coreutils \
    grep \
    sed \
    awk

WORKDIR /app

COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
