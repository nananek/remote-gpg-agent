# syntax=docker/dockerfile:1
# PWA は web/dist にビルド済みのものが commit されている前提（npm はイメージ内で動かさない）。
FROM golang:1.27 AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -mod=vendor -trimpath -buildvcs=false -tags netgo,osusergo \
    -ldflags="-s -w" -o /out/rga-server ./cmd/rga-server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/rga-server /rga-server
USER nonroot:nonroot
EXPOSE 3080 8443
ENTRYPOINT ["/rga-server"]
