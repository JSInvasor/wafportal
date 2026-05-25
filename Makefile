BINARY := wafportal
PKG := ./cmd/wafportal

.PHONY: all build frontend backend run clean

# Build the frontend, embed it, and produce a single static binary.
all: build

build: frontend backend

frontend:
	cd web && npm ci && npm run build

backend:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BINARY) $(PKG)

# Run locally against ./config.yaml (uses the committed frontend build).
run:
	go run $(PKG) -config config.yaml

clean:
	rm -f $(BINARY)
