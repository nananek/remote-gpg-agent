GO_IMAGE ?= golang:1.27
GO_RUN = docker run --rm -u $(shell id -u):$(shell id -g) -e HOME=/tmp \
	-e GOFLAGS=-mod=vendor -e GOPROXY=off \
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
	rm -rf internal/server/webdist && cp -R web/dist internal/server/webdist

vapid:
	$(GO_RUN) run ./cmd/rga-server vapid
