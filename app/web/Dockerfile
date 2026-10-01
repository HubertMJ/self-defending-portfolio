# The image behind https://hubertjablon.ski. Built, scanned, SBOM'd and signed by
# .github/workflows/build-web.yml; Kyverno refuses to admit it unsigned (ADR 0011).
#
# Single stage on purpose: the payload is static files, so there is nothing to compile and no
# builder layer worth the extra attack surface. nginx-unprivileged rather than nginx because the
# stock image starts as root to bind :80, which PSS `restricted` forbids (see
# cluster/infra/hello/deployment.yaml). Pinned by tag *and* digest (ADR 0008) to the same digest
# the Deployment used before this image existed, so the base did not silently change in the move.
FROM nginxinc/nginx-unprivileged:1.31.6-alpine@sha256:26b0bf6fbf07297983cb341998d79c831508787de26627dd2a112321b9c3a4af

# Build-time only; the running container never reads these. USER is restored below.
USER root

# Our nginx.conf includes no conf.d, so the shipped default vhost is dead config. It is removed
# rather than left in place because the base image's 10-listen-on-ipv6-by-default.sh entrypoint
# edits that file in place at startup, which a read-only root filesystem would reject.
RUN rm -f /etc/nginx/conf.d/default.conf

COPY nginx.conf /etc/nginx/nginx.conf
COPY public/ /usr/share/nginx/html/

# Owned by root, readable by all: the content must not be writable by the uid serving it.
RUN chmod -R a=rX /usr/share/nginx/html && chmod a=r /etc/nginx/nginx.conf

# 101 is the `nginx` user baked into the base image; the Deployment asserts the same uid.
USER 101

EXPOSE 8080

LABEL org.opencontainers.image.title="self-defending-portfolio web" \
      org.opencontainers.image.description="Static site for hubertjablon.ski, served by nginx-unprivileged on :8080" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="MIT"

# nginx runs in the foreground: the container must be the process, not its supervisor.
CMD ["nginx", "-g", "daemon off;"]
