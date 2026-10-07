# Ephemeral build/run image for upstream Node campaign projects (linux/arm64).
# Holds only the OS toolchain; node_modules live on the bind-mounted workspace.
ARG NODE_VERSION
FROM node:${NODE_VERSION}-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ git ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && corepack enable
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 \
    DO_NOT_TRACK=1
WORKDIR /work
