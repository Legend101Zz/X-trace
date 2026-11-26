# The paired campaign uses this exact one image for both legs and isolated readback.
ARG NODE_VERSION
FROM node:${NODE_VERSION}-bookworm-slim
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 DO_NOT_TRACK=1 PLAYWRIGHT_BROWSERS_PATH=/opt/xtrace-browsers
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ git ca-certificates curl perl-base \
    && rm -rf /var/lib/apt/lists/* && corepack enable pnpm
WORKDIR /opt/xtrace-vendure-viewer
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund \
    && ./node_modules/.bin/playwright install --with-deps chromium \
    && chmod -R a+rX /opt/xtrace-browsers
WORKDIR /work
