# Common tasks. `make up` starts the whole stack in Docker; `make dev` runs
# just the core server natively.
.PHONY: help build test test-pg vet fmt check dev up up-pg down logs seed cdn-check cdn-restart clean fixture

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

build: ## build ./patchlog
	go build -tags grpcnotrace -o patchlog ./cmd/patchlog

test: ## run all tests
	go test ./...

PG_PACKAGES = ./internal/...

test-pg: ## run the tests on Postgres (PATCHLOG_TEST_PG=postgres://user@host:port/postgres; a fresh database per test)
	@test -n "$$PATCHLOG_TEST_PG" || (echo "set PATCHLOG_TEST_PG to a Postgres URL whose user may create databases"; exit 1)
	go test $(PG_PACKAGES)

vet: ## go vet
	go vet ./...

fmt: ## gofmt the tree
	gofmt -w internal cmd

check: vet test ## vet and test, and fail on unformatted files
	@test -z "$$(gofmt -l internal cmd)" || (gofmt -l internal cmd; exit 1)

dev: ## run the core server natively in dev mode on :8080 (dev.db; dev.key enables sealed/e2e namespaces)
	go run ./cmd/patchlog serve -dev -db dev.db -master-key dev.key -master-key-create

up: ## build and start the whole stack (core, seed, index, tree, janitor, cdn)
	docker compose up --build -d
	@echo "through the CDN: core http://localhost:8080  playground http://localhost:8080/playground/  index http://localhost:8081  tree http://localhost:8082 (/cat/roots, /topics/roots; and /playground/tree/)"
	@echo "origins, bypassing it: core http://localhost:9080  index http://localhost:9081  tree http://localhost:9082"

up-pg: ## the same, with the core on Postgres (compose.postgres.yaml, Addendum D.8)
	docker compose -f compose.yaml -f compose.postgres.yaml up --build -d

up-host: ## the same, with host networking (hosts where Docker can't create network namespaces, e.g. sprites)
	docker compose -f compose.yaml -f compose.host.yaml up --build -d
	@echo "through the CDN: core http://localhost:8080 (playground /playground/), index :8081, tree :8082; origins directly on :9080-9082"

down: ## stop the stack (data is kept; `docker compose down -v` wipes it)
	docker compose down

logs: ## follow the stack's logs
	docker compose logs -f

seed: ## re-run the seed against the running stack
	docker compose run --rm seed

cdn-check: ## smoke-test the CDN of the running stack: HIT/MISS, head micro-caching, long-poll collapsing, tag purge
	sh deploy/cdn-check.sh

cdn-restart: ## restart the CDN (reloads deploy/varnish/default.vcl and empties the cache)
	docker compose restart cdn

clean: ## remove built binaries and local dev databases
	rm -f patchlog dev.db dev.db-wal dev.db-shm dev.key

fixture: ## regenerate the playground's crypto vectors (static/selftest.json; with node, also the JS->Go part)
	go test ./internal/playground -run TestSelfTestFixture -update
