# The image behind https://hubertjablon.ski. Built, scanned, SBOM'd and signed by
# .github/workflows/build-web.yml; Kyverno refuses to admit it unsigned (ADR 0011).
#
# Two stages (ADR 0019). The first compiles TypeScript and CSS into content-hashed static files and
# runs the unit tests, so an image cannot be built from code whose tests fail. Nothing from it
# reaches the final image except dist/: no node, no node_modules, no npm, no sources. The second
# stage is the same nginx-unprivileged base as before. Both bases are pinned by tag *and* digest
# (ADR 0008).

FROM node:22.22.0-alpine3.23@sha256:e4bf2a82ad0a4037d28035ae71529873c069b13eb0455466ae0bc13363826e34 AS build

WORKDIR /src
# Lockfile first so the dependency layer is cached until the lockfile changes. `npm ci` installs
# exactly what package-lock.json records (integrity hashes included) and fails if it is out of date.
# --ignore-scripts: no install hook of any dependency runs here; esbuild ships its native binary
# as an optional dependency and needs no postinstall.
COPY package.json package-lock.json ./
RUN PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm ci --ignore-scripts --no-audit --no-fund

COPY tsconfig.json vitest.config.ts ./
COPY scripts/ scripts/
COPY src/ src/
COPY static/ static/
COPY test/unit/ test/unit/
RUN npm run lint && npm test && npm run build

# nginx-unprivileged rather than nginx because the stock image starts as root to bind :80, which
# PSS `restricted` forbids (see cluster/infra/hello/deployment.yaml).
FROM nginxinc/nginx-unprivileged:1.31.6-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af

# Build-time only; the running container never reads these. USER is restored below.
USER root

# Our nginx.conf includes no conf.d, so the shipped default vhost is dead config. It is removed
# rather than left in place because the base image's 10-listen-on-ipv6-by-default.sh entrypoint
# edits that file in place at startup, which a read-only root filesystem would reject.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf
COPY security-headers.conf /etc/nginx/security-headers.conf
COPY --from=build /src/dist/ /usr/share/nginx/html/

# Owned by root, readable by all: the content must not be writable by the uid serving it.
RUN chown -R root:root /usr/share/nginx/html \
 && chmod -R a=rX /usr/share/nginx/html \
 && chmod a=r /etc/nginx/nginx.conf /etc/nginx/security-headers.conf

# 101 is the `nginx` user baked into the base image; the Deployment asserts the same uid.
USER 101

EXPOSE 8080

LABEL org.opencontainers.image.title="self-defending-portfolio web" \
      org.opencontainers.image.description="Static site for hubertjablon.ski, served by nginx-unprivileged on :8080" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="MIT"

# nginx runs in the foreground: the container must be the process, not its supervisor.
CMD ["nginx", "-g", "daemon off;"]
