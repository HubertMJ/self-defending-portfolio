# The target image for the phase 5 attack scenarios (ADR 0017). The portfolio API creates one pod from
# it per scenario run in `sandbox` (cluster/infra/sandbox/scenarios/scenarios.yaml) and execs into it;
# Falco detects what the exec does and Falco Talon answers (ADR 0018).
#
# Nothing in here is an attack tool. The scenarios use what every Alpine container already has:
# busybox `sh`, `id`, `cat`, `cp`, `wget`, `sleep`. Their danger is the *behaviour* Falco keys on (a
# terminal shell, a network tool, a read of /etc/shadow, a binary that was not in the image being
# executed), not a payload. The image ships no malware, no exploit, no credentials and no target list,
# and has nowhere to send anything: `sandbox` allows DNS and nothing else.
#
# Alpine rather than busybox:musl: the image goes through the same Trivy gate, SBOM and signature as
# every other image of this project (ADR 0011), and Trivy only knows what an image contains when it can
# read an OS package database. busybox's image has none, so it would always scan "clean" without having
# been looked at. Pinned by tag *and* digest (ADR 0008).
FROM alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6

# Everything the scenarios do not need goes, so the image is busybox + musl + the base layout:
#   * apk-tools/libapk - no package manager inside: a scenario cannot install anything, and the 4th
#     scenario's "new binary" can only be a copy of what is already there (and there is no network to
#     fetch anything from anyway);
#   * ssl_client, libssl3, libcrypto3, ca-certificates-bundle - busybox `wget` only needs these for
#     https, and the network-tool scenario never leaves the pod's loopback;
#   * scanelf, musl-utils, zlib - build and package tooling.
# alpine-keys stays: alpine-release depends on it, and alpine-release is how Trivy identifies the OS.
# `apk del` runs first and removes itself last; the package database it leaves behind still lists the
# remaining packages correctly, which is what Trivy reads.
#
# The scenario user: uid/gid 10001, no home, no login shell, no password (`!` in /etc/shadow, like every
# other account in the base image). /etc/shadow itself keeps Alpine's root:shadow 0640: the
# sensitive-file-read scenario gets read access through the shadow group (supplementalGroups in its pod
# spec), not through a weakened file mode in the image.
RUN apk del --no-network --purge \
      apk-tools libapk ssl_client libssl3 libcrypto3 ca-certificates-bundle scanelf musl-utils zlib \
 && rm -rf /etc/apk/cache /var/cache/apk \
 && addgroup -g 10001 scenario \
 && adduser -D -H -h /nonexistent -s /sbin/nologin -G scenario -u 10001 scenario

USER 10001:10001

LABEL org.opencontainers.image.title="self-defending-portfolio scenario" \
      org.opencontainers.image.description="Target pod for the controlled attack scenarios in the sandbox namespace (busybox only)" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="MIT"

# The pod specs override this with their own `sleep`; it is here so the image does something bounded
# when run on its own. 120 s is the longest a scenario pod may live (activeDeadlineSeconds, contract).
CMD ["sleep", "120"]
