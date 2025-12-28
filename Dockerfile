FROM debian:stable-slim

ENV LANG=C.UTF-8 \
    TZ=Asia/Shanghai \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl tar openssl netcat-openbsd ca-certificates procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

ENTRYPOINT ["./entrypoint.sh"]
