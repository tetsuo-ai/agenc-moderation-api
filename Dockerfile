# Self-host the AgenC moderation attestation service.
#
#   docker build -t agenc-moderation-api .
#   docker run -p 8787:8787 \
#     -e MODERATION_SIGNER_SECRET='[...64-byte keypair JSON...]' \
#     -e RPC_URL=https://your-rpc \
#     agenc-moderation-api
#
# Key custody: prefer your orchestrator's secret store (docker secrets, k8s
# Secret, systemd LoadCredential) over a literal -e value in shell history.
FROM node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json tsup.config.ts ./
COPY src ./src
RUN npm run build

FROM node:22-slim
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY --from=build /app/dist ./dist
EXPOSE 8787
USER node
CMD ["node", "dist/bin.js"]
