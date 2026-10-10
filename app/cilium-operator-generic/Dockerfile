# cilium-operator, generic variant (Deployment `cilium-operator` in kube-system, ADR 0004), built here
# from the pinned upstream release commit with fixed dependencies (ADR 0028). Built, Trivy-gated,
# SBOM'd and signed by .github/workflows/build-images.yml like every image under app/ (ADR 0016).
#
# Why not the upstream image: quay.io/cilium/operator-generic:v1.19.8 compiles cilium-operator-generic
# against google.golang.org/grpc v1.79.3: 3 HIGH with Trivy 0.75.0 on 2026-10-02, nothing else.
#
# Same source, same commit, same raised dependencies and same reasoning as app/cilium/Dockerfile,
# which documents them; modules/ here is identical to app/cilium/modules (scripts/check-cilium-values.sh
# refuses a difference). The image is upstream's images/operator/Dockerfile `release` stage at
# CILIUM_COMMIT with the one binary rebuilt: scratch, the CA bundle taken from the upstream image
# itself (by digest, so it is byte-for-byte upstream's), gops, the operator binary, LICENSE.all, the
# world-writable /home/gops and GOPS_CONFIG_DIR. gops is the release upstream's image carries,
# compiled again with the Go below (the tools stage; until 2026-10-10 it was copied out of upstream's
# image). The chart sets the container's command
# (cilium-operator-generic) and its security context, so neither depends on this image's metadata.
#
# Tests: upstream's unit tests under ./operator/... (unprivileged, --network=none).
#
# Bumping: together with app/cilium (see there).
#
# Bases pinned by tag and digest (ADR 0008):
#   golang:1.26.9                     docker.io  (as app/talon; 1.26.8's standard library has fixed
#                                                 findings, HIGH among them)
#   operator-generic:v1.19.8          quay.io    (the chart's operator image at 1.19.8; source of the
#                                                 CA bundle only)
FROM quay.io/cilium/operator-generic:v1.19.8@sha256:786ec9bb1a9344435e3e3f994bc4ed3a4a85afa6a314e98681af241f8be79833 AS upstream

FROM docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS tools
# gops as upstream's images/runtime/build-gops.sh at CILIUM_COMMIT builds it - the same release,
# `go build` with the same flags - but with this stage's Go instead of upstream's 1.26.8, fetched by
# the commit the tag points at instead of a tag tarball (app/cilium/Dockerfile, the tools stage).
# google/gops tag v0.3.29.
ARG GOPS_COMMIT=a2d8f7790eac63a6668583a060cb45903410a91b
WORKDIR /go/src/github.com/google/gops
RUN git init -q . \
 && git remote add origin https://github.com/google/gops.git \
 && git fetch -q --depth 1 origin "$GOPS_COMMIT" \
 && git checkout -q FETCH_HEAD \
 && test "$(git rev-parse HEAD)" = "$GOPS_COMMIT" \
 && CGO_ENABLED=0 go build -buildvcs=false -ldflags "-s -w" -o /out/usr/bin/gops github.com/google/gops

FROM docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS deps
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
RUN --network=none go test -mod=vendor -count=1 -timeout 1200s ./operator/... \
 && touch /tested

FROM deps AS build
# Depending on the test stage's marker is what makes BuildKit run it (see app/api/Dockerfile).
COPY --from=test /tested /tmp/tested
# Upstream's builder stage, without the debug-symbol split. The extra ldflag is for scanners only and
# changes nothing at run time (app/cilium/Dockerfile, "One ldflag is added").
ARG SCANNER_VERSION_LDFLAG="-X github.com/cilium/cilium/pkg/version.Version=v1.19.8"
# GIT_VERSION as upstream's Makefile.defs computes it (`git show -s --format='%h %aI'`), but
# with the UTC offset spelled +00:00: the golang image's git 2.47 prints a UTC author date as "Z",
# the git upstream's builder ran printed "+00:00", and the version string should be upstream's.
RUN GIT_VERSION="$(git show -s --format='%h %aI' | sed 's/Z$/+00:00/')" \
 && make GIT_VERSION="$GIT_VERSION" GOARCH=amd64 DESTDIR=/out EXTRA_GO_BUILD_LDFLAGS="$SCANNER_VERSION_LDFLAG" \
      build-container-operator-generic install-container-binary-operator-generic licenses-all \
 && mv LICENSE.all /out/LICENSE.all \
 && /out/usr/bin/cilium-operator-generic --version | grep -qx 'Cilium-Operator 1\.19\.8 5791d208 2026-09-15T18:23:52+00:00 go version go1\.26\.9 linux/amd64'

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=upstream /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=tools /out/usr/bin/gops /usr/bin/gops
COPY --from=build /out/usr/bin/cilium-operator-generic /usr/bin/cilium-operator-generic
COPY --from=build /out/LICENSE.all /LICENSE.all
WORKDIR /
# Configure gops directory to prevent permission
# issues depending on the UID configured to run the entrypoint.
COPY --chmod=777 --from=scratch / /home/gops
ENV GOPS_CONFIG_DIR=/home/gops
CMD ["/usr/bin/cilium-operator-generic"]
LABEL org.opencontainers.image.title="self-defending-portfolio cilium-operator-generic" \
      org.opencontainers.image.description="cilium-operator (generic) v1.19.8 built from the pinned upstream release with fixed dependencies" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="v1.19.8"
