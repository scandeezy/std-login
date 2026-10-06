.PHONY: generate lint test build run keygen

generate: ## Regenerate Go code from proto/ into gen/
	go tool buf generate

lint:
	go tool buf lint
	go vet ./...
	@test -z "$$(gofmt -l cmd internal)" || (gofmt -l cmd internal; exit 1)

test:
	go test -race ./...

build:
	go build -o bin/std-login ./cmd/std-login

run: ## Local dev server: SQLite file, ephemeral signing key, login links logged
	DEV=true go run ./cmd/std-login

keygen: ## Write a signing key for JWT_PRIVATE_KEY_FILE
	go run ./cmd/std-login keygen > jwt-key.pem && chmod 600 jwt-key.pem
