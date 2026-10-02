# Hubble Relay (Deployment `hubble-relay` in kube-system, ADR 0004), built here from the pinned
# upstream release commit with fixed dependencies (ADR 0028). Built, Trivy-gated, SBOM'd and signed by
# .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image: quay.io/cilium/hubble-relay:v1.19.8 compiles hubble-relay against
# google.golang.org/grpc v1.79.3: 3 HIGH with Trivy 0.75.0 on 2026-10-02, nothing else.
#
# Same source, same commit, same raised dependencies and same reasoning as app/cilium/Dockerfile,
# which documents them; modules/ here is identical to app/cilium/modules (scripts/check-cilium-values.sh
# refuses a difference). The image is upstream's images/hubble-relay/Dockerfile `release` stage at
# CILIUM_COMMIT with the one binary rebuilt: the same distroless static nonroot base by the same
# digest (upstream names it gcr.io/distroless/static:nonroot; static-debian13:nonroot is the same
# manifest, and the name app/api, app/talon and app/ksops use), gops taken from the upstream image
# itself, the relay binary, LICENSE.all, /home/gops, uid 65532, `hubble-relay serve`.
#
# Tests: upstream's unit tests for the relay and what it is built from - ./hubble-relay/...,
# ./pkg/hubble/relay/..., ./pkg/hubble/peer/... (unprivileged, --network=none).
#
# Bumping: together with app/cilium (see there).
#
# Bases pinned by tag and digest (ADR 0008):
#   golang:1.26.8                     docker.io  (the pin app/api, app/talon and app/ksops use)
#   distroless/static-debian13:nonroot gcr.io    (upstream's BASE_IMAGE digest at CILIUM_COMMIT)
#   hubble-relay:v1.19.8              quay.io    (the chart's relay image at 1.19.8; source of gops only)
FROM quay.io/cilium/hubble-relay:v1.19.8@sha256:f78768be216b5c00137c7d4da440724d0b49986805d361e7458cc8fe9ff976ff AS upstream

FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS deps
# cilium/cilium tag v1.19.8 (annotated tag 9f826a3d..., commit below).
ARG CILIUM_COMMIT=5791d208dda456da8d08e9389c3d22514dc2db77
# Upstream's path: the Makefiles and a few tests derive paths from it.
WORKDIR /go/src/github.com/cilium/cilium
# Fetch exactly one commit by its hash (GitHub serves any reachable commit by id), then refuse to go
# on unless that is what was checked out.
RUN git init -q . \
 && git remote add origin https://github.com/cilium/cilium.git \
 && git fetch -q --depth 1 origin "$CILIUM_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$CILIUM_COMMIT"
COPY modules/go.mod modules/go.sum ./
# The module cache is dropped once vendor/ is written: everything after this builds from vendor/
# (upstream's -mod=vendor, and Go's default when vendor/modules.txt is consistent), and the layer -
# which CI caches - shrinks from 1.2 GB to the 0.4 GB of vendor/.
RUN go mod download && go mod verify \
 && rm -rf vendor && go mod vendor \
 && go clean -modcache

FROM deps AS test
# --network=none: upstream's tests, run against dependencies we raised; every module is in vendor/.
RUN --network=none go test -mod=vendor -count=1 -timeout 1200s \
      ./hubble-relay/... ./pkg/hubble/relay/... ./pkg/hubble/peer/... \
 && touch /tested

FROM deps AS build
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
# The extra ldflag is for scanners only and changes nothing at run time (app/cilium/Dockerfile,
# "One ldflag is added").
ARG SCANNER_VERSION_LDFLAG="-X github.com/cilium/cilium/pkg/version.Version=v1.19.8"
# GIT_VERSION as upstream's Makefile.defs computes it (`git show -s --format='%h %aI'`), but
# with the UTC offset spelled +00:00: the golang image's git 2.47 prints a UTC author date as "Z",
# the git upstream's builder ran printed "+00:00", and the version string should be upstream's.
RUN GIT_VERSION="$(git show -s --format='%h %aI' | sed 's/Z$/+00:00/')" \
 && make GIT_VERSION="$GIT_VERSION" GOARCH=amd64 DESTDIR=/out EXTRA_GO_BUILD_LDFLAGS="$SCANNER_VERSION_LDFLAG" \
      build-container-hubble-relay install-container-binary-hubble-relay licenses-all \
 && mv LICENSE.all /out/LICENSE.all \
 && /out/usr/bin/hubble-relay version | grep -qx 'Hubble-relay: 1\.19\.8 5791d208 2026-09-15T18:23:52+00:00 go version go1\.26\.8 linux/amd64'

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
LABEL maintainer="maintainer@cilium.io"
COPY --from=upstream /usr/bin/gops /usr/bin/gops
COPY --from=build /out/usr/bin/hubble-relay /usr/bin/hubble-relay
COPY --from=build /out/LICENSE.all /LICENSE.all
# Configure gops to use a temporary directory, to prevent permission
# issues depending on the UID configured to run the entrypoint.
COPY --chmod=777 --from=scratch / /home/gops
ENV GOPS_CONFIG_DIR=/home/gops
# use uid:gid for the nonroot user for compatibility with runAsNonRoot
USER 65532:65532
ENTRYPOINT ["/usr/bin/hubble-relay"]
CMD ["serve"]
LABEL org.opencontainers.image.title="self-defending-portfolio hubble-relay" \
      org.opencontainers.image.description="Hubble Relay v1.19.8 built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v1.19.8"
