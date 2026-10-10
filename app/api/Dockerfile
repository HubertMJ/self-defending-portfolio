# portfolio-api (ADR 0015). Built, Trivy-gated, SBOM'd and signed by .github/workflows/build-images.yml
# like every image under app/ (ADR 0016); Kyverno refuses to admit it unsigned (ADR 0011).
#
# Three stages: the tests (with the race detector) must pass for the image to exist at all, the
# binary is built static (CGO off, so no libc to patch), and the runtime is distroless `static`:
# no shell, no package manager, nothing for an attacker who got code execution to live off. It runs
# as distroless's nonroot user (65532), which the Deployment asserts, with a read-only root.
#
# Bases pinned by tag and digest (ADR 0008), resolved from the registries' index manifests:
#   golang:1.26.9                          docker.io  (1.26.8's standard library has fixed HIGH
#                                                     findings; as app/talon and app/cilium)
# go.mod says `go 1.26.0` (x/net 0.60 requires it) and `godebug default=go1.25`: the binary keeps the
# run-time defaults it had under `go 1.25.0` (ADR 0025, amendment 2026-10-10 (b)).
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.9@sha256:d7722066f0b60ceccb6c0643cbed1f5f9e15506ac237146c95333504d7805d89 AS deps
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .

FROM deps AS test
# -race needs cgo, which the golang image has; the shipped binary below does not use it.
RUN CGO_ENABLED=1 go vet ./... && CGO_ENABLED=1 go test -race -count=1 ./... && touch /tested

FROM deps AS build
# Depending on the test stage's marker is what makes BuildKit run it: otherwise a stage the final
# image does not reference is skipped.
COPY --from=test /tested /tmp/tested
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/portfolio-api .

FROM gcr.io/distroless/static-debian13:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3
COPY --from=build /out/portfolio-api /portfolio-api
# The commit this image was built from (build-images.yml passes github.sha), served in
# /api/scenarios/{id}/details so the page links each rule to the source of exactly this build
# (ADR 0021). Declared in the last stage only: a new commit changes this one layer, not the build
# cache of the stages above. A local build without the argument publishes no commit.
ARG GIT_SHA=""
ENV GIT_SHA=${GIT_SHA}
# The Actions run that built this image (build-images.yml passes github.run_id), served in
# /api/provenance so the page links the public run beside the commit (ADR 0035). Same reasoning as
# GIT_SHA: last stage only, and a local build without the argument publishes no run.
ARG CI_RUN_ID=""
ENV CI_RUN_ID=${CI_RUN_ID}
USER 65532:65532
# 8080: the public API behind the Gateway. 8081: the Falcosidekick and Talon webhooks only.
EXPOSE 8080 8081
LABEL org.opencontainers.image.title="self-defending-portfolio api" \
      org.opencontainers.image.description="Attack runner, live event stream and posture summary for hubertjablon.ski" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["/portfolio-api"]
