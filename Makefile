# Common targets for tiny-url. Mostly muscle memory for contributors;
# CI runs the same commands directly.

# Inject the git SHA into the binary so `tiny-url --version` prints
# something useful even when not built via `go install`.
GIT_SHA := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X main.buildSHA=$(GIT_SHA)
BIN     := tiny-url

.PHONY: help build run test fuzz fmt vet lint check docker docker-run clean

help: ## list available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## compile the binary into ./tiny-url
	go build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN) .

run: build ## build and run with default config (memory backend, :8080)
	./$(BIN)

test: ## go vet + go test (race detector, coverage)
	go vet ./...
	go test -race -cover ./...

fuzz: ## run fuzz tests for 60s each (CI does the same)
	go test ./services/ -run='^$$' -fuzz=FuzzValidateDestinationURL -fuzztime=60s
	go test ./services/ -run='^$$' -fuzz=FuzzValidateCustomCode -fuzztime=60s

fmt: ## format every Go file
	gofmt -w .

vet: ## go vet only
	go vet ./...

lint: fmt vet ## fmt + vet (no third-party linter)
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "Unformatted Go files:" && echo "$$unformatted" && exit 1; \
	fi

check: lint test ## what CI runs: fmt + vet + test

docker: ## build the distroless image
	docker build -t tiny-url:dev .

docker-run: docker ## run the container on :8080 with memory backend
	docker run --rm -p 8080:8080 tiny-url:dev

clean: ## remove build outputs
	rm -f $(BIN) $(BIN).exe coverage.* *.test
