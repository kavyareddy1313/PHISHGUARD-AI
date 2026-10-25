# Multi-stage lightweight Node.js Dockerfile
FROM node:20-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5001

COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./
COPY src/ ./src/

USER node
EXPOSE 5001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:5001/health || exit 1

CMD ["node", "src/server.js"]
