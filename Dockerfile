# 浮标离线受限委托链验签岸站
# 纯 Node.js（内置 WebCrypto / node:test），无第三方依赖
FROM node:20-alpine

WORKDIR /app

# 先拷清单（本项目无 npm 依赖，保留 package.json 供脚本使用）
COPY package.json ./
COPY src ./src
COPY public ./public
COPY bin ./bin
COPY scripts ./scripts
COPY test ./test

# verify 可执行文件
RUN chmod +x bin/verify.js && ln -s /app/bin/verify.js /usr/local/bin/verify

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.js"]
