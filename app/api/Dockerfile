# portfolio-api (ADR 0015). Built, Trivy-gated, SBOM'd and signed by .github/workflows/build-images.yml
# like every image under app/ (ADR 0016); Kyverno refuses to admit it unsigned (ADR 0011).
#
# Three stages: the tests (with the race detector) must pass for the image to exist at all, the
# binary is built static (CGO off, so no libc to patch), and the runtime is distroless `static`:
# no shell, no package manager, nothing for an attacker who got code execution to live off. It runs
# as distroless's nonroot user (65532), which the Deployment asserts, with a read-only root.
#
# Bases pinned by tag and digest (ADR 0008), resolved from the registries' index manifests:
#   golang:1.26.8                          docker.io
#   distroless/static-debian13:nonroot     gcr.io
FROM docker.io/library/golang:1.26.8@sha256:0f063af2d465d8dcae54cce04278ada488b96f77b42449c8d071e47d016cc65a AS deps
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
USER 65532:65532
# 8080: the public API behind the Gateway. 8081: the Falcosidekick and Talon webhooks only.
EXPOSE 8080 8081
LABEL org.opencontainers.image.title="self-defending-portfolio api" \
      org.opencontainers.image.description="Attack runner, live event stream and posture summary for hubertjablon.ski" \
      org.opencontainers.image.source="https://github.com/HubertMJ/self-defending-portfolio" \
      org.opencontainers.image.licenses="MIT"
ENTRYPOINT ["/portfolio-api"]
