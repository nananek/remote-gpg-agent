GO_IMAGE ?= golang:1.27
# このホストの Docker は rootless。コンテナの root がホストの uid と等しく対応するので、
# -u を渡さず root のまま動かすのが正しい（-u 1000:1000 は書けない subuid になる）。
# -buildvcs=false: コンテナ内の git は dubious ownership で VCS 情報を読めない。
GO_RUN = docker run --rm -e HOME=/tmp -e GOCACHE=/tmp/gocache \
	-e GOFLAGS="-mod=vendor -buildvcs=false" -e GOPROXY=off \
	-v $(CURDIR):/src -w /src $(GO_IMAGE) go

.PHONY: build test vet fmt web vapid

build:
	$(GO_RUN) build -o bin/rga-server ./cmd/rga-server
	$(GO_RUN) build -o bin/rga ./cmd/rga

test:
	$(GO_RUN) test ./...

vet:
	$(GO_RUN) vet ./...

fmt:
	$(GO_RUN) fmt ./...

web:
	cd web && npm ci && npm run build

vapid:
	$(GO_RUN) run ./cmd/rga-server vapid
