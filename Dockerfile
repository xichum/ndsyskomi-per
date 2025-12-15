# 使用官方轻量级 Node.js 镜像
FROM node:20-alpine

# [新增] 安装基础系统依赖
# 1. libc6-compat: 必须！因为下载的 sing-box 二进制文件通常是为常规 Linux 编译的，在 Alpine (musl) 上需要兼容库才能运行，否则会报 "not found" 错误。
# 2. ca-certificates: 更新系统证书，提高网络请求稳定性。
# 3. tzdata: 确保容器时间正确，保证定时重启功能准确。
RUN apk add --no-cache libc6-compat ca-certificates tzdata

# 设置工作目录
WORKDIR /app

# 复制依赖文件
COPY package.json ./

# 安装依赖 (生产环境模式，更小更快)
RUN npm install --production

# 复制所有源代码（index.js 和 index.html 都会被复制到 /app）
COPY . .

# [修改] 暴露端口改为 2999，与您代码中的默认配置和反代一致
EXPOSE 2999

# 设置环境变量
ENV NODE_ENV=production
# [新增] 显式注入端口变量，双重保险
ENV PORT=2999

# 启动命令
CMD ["npm", "start"]
