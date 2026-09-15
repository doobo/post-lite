BINARY := bin/postlite
PKG := ./cmd/postlite

.PHONY: build run vet test clean web

build:
	go build -ldflags="-s -w" -o $(BINARY) $(PKG)

run: build
	./$(BINARY) -addr :5680 -data ./data -timeout 60s -max-history 1000

run-plain: build
	./$(BINARY) -plain -addr 127.0.0.1:5681 -data ./data

vet:
	go vet ./...

test:
	go test ./...

clean:
	rm -rf bin data

# Frontend is plain static files under internal/web/static (no build step);
# edit them directly, they are embedded into the binary via go:embed.
web:
	@echo "static UI lives in internal/web/static (embedded, no build step)"
