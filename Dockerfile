# 使用官方轻量级 Node.js 镜像
FROM node:20-alpine

# 设置工作目录
WORKDIR /app

# 首先只复制依赖文件，利用 Docker 缓存层加速构建
COPY package.json ./

# 安装依赖
RUN npm install

# 复制所有源代码（包括 index.js 和你即将上传的 index.html）
COPY . .

# 暴露端口 (对应代码中的 PORT 环境变量，默认 3000)
EXPOSE 3000

# 设置环境变量，确保性能
ENV NODE_ENV=production

# 启动命令
CMD ["npm", "start"]
