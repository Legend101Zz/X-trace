# Same Ubuntu ABI floor as the development archive; same pinned Node for build and both legs.
FROM node@sha256:dc73bdac873c82e6cbfa496e35dd6e27a20302ebba043d0d9646708df19a9996 AS pinned_node
FROM ubuntu@sha256:9a04f13b3f80ef056361e30868593b1cfd2279fe19e4081cb93a90bf56819d6a
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ git ca-certificates curl tar gzip libstdc++6 libatomic1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=pinned_node /usr/local/ /usr/local/
# The build uses pnpm. The upstream Yarn shim points outside the copied prefix.
RUN corepack enable pnpm
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0 DO_NOT_TRACK=1
WORKDIR /work
