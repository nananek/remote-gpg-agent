# syntax=docker/dockerfile:1
# PWA は web/dist にビルド済みのものが commit されている前提（npm はイメージ内で動かさない）。
# dist とソースの一致は CI（.github/workflows/ci.yml）が検証する。
#
# 実行イメージは distroless static の nonroot（uid/gid 65532）固定。
# shell も curl も無いので、healthcheck は /rga-server healthcheck を直接叩く
# （deploy/docker-compose.yml）。

ARG GO_VERSION=1.27

# BUILDPLATFORM 上で動かし TARGETARCH へクロスコンパイルする。
# arm64 イメージを作るときも Go のビルドを QEMU で走らせない。
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .

ARG TARGETOS=linux
ARG TARGETARCH
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -mod=vendor -trimpath -buildvcs=false -tags netgo,osusergo \
    -ldflags="-s -w" -o /out/rga-server ./cmd/rga-server

FROM gcr.io/distroless/static-debian12:nonroot

ARG VERSION=dev
LABEL org.opencontainers.image.title="remote-gpg-agent" \
      org.opencontainers.image.description="Passkey-sealed OpenPGP signing server for rga client and PWA" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"

COPY --from=build /out/rga-server /rga-server

# ベースイメージも nonroot だが、ここが崩れたら CI が落ちるように明示する。
USER nonroot:nonroot
EXPOSE 3080 8443
ENTRYPOINT ["/rga-server"]
