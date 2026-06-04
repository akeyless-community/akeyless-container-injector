.PHONY: build test docker check-secrets ci

BINARY := bin/akeyless-inject

build:
	go build -buildvcs=false -o $(BINARY) ./cmd/akeyless-inject

test:
	go test -race ./...

docker:
	docker build -t akeyless-container-injector:local .

check-secrets:
	@chmod +x scripts/check-secrets.sh
	@./scripts/check-secrets.sh

ci: check-secrets test build
