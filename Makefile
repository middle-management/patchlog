# Common tasks. `make up` starts the whole stack in Docker; `make dev` runs
# just the core server natively.
.PHONY: help build test vet fmt check dev up down logs seed clean

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-8s %s\n", $$1, $$2}'

build: ## build ./patchlog
	go build -o patchlog ./cmd/patchlog

test: ## run all tests
	go test ./...

vet: ## go vet
	go vet ./...

fmt: ## gofmt the tree
	gofmt -w internal cmd

check: vet test ## vet and test, and fail on unformatted files
	@test -z "$$(gofmt -l internal cmd)" || (gofmt -l internal cmd; exit 1)

dev: ## run the core server natively in dev mode on :8080 (dev.db)
	go run ./cmd/patchlog serve -dev -db dev.db

up: ## build and start the whole stack (core, seed, index, tree, janitor)
	docker compose up --build -d
	@echo "core http://localhost:8080  playground http://localhost:8080/playground/  index http://localhost:8081  tree http://localhost:8082"

down: ## stop the stack (data is kept; `docker compose down -v` wipes it)
	docker compose down

logs: ## follow the stack's logs
	docker compose logs -f

seed: ## re-run the seed against the running stack
	docker compose run --rm seed

clean: ## remove built binaries and local dev databases
	rm -f patchlog dev.db dev.db-wal dev.db-shm
