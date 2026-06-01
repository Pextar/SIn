TARGET := aarch64-unknown-linux-gnu
RELEASE := target/$(TARGET)/release

# Build cross-compiled binaries for the Pi
.PHONY: build-pi
build-pi:
	@if command -v cross >/dev/null 2>&1; then \
		cross build --release --target $(TARGET) -p sin-server -p sin-cli; \
	else \
		cargo build --release --target $(TARGET) -p sin-server -p sin-cli; \
	fi

# Build the web PWA
.PHONY: web
web:
	cd web && npm ci --silent && npm run build

# Full deploy to Pi — requires PI variable: make deploy PI=user@raspberrypi.local
.PHONY: deploy
deploy:
	@test -n "$(PI)" || (echo "Usage: make deploy PI=user@host"; exit 1)
	./deploy/deploy.sh $(PI)

# First-time Pi setup — requires PI variable
.PHONY: setup-pi
setup-pi:
	@test -n "$(PI)" || (echo "Usage: make setup-pi PI=user@host"; exit 1)
	chmod +x deploy/setup-pi.sh deploy/deploy.sh
	./deploy/setup-pi.sh $(PI)

# Build a native release (for local testing)
.PHONY: build
build:
	cargo build --release -p sin-server -p sin-cli

# Run the auth server locally for development
.PHONY: dev
dev:
	SIN_BASE=http://localhost:8080 cargo run -p sin-server

.PHONY: test
test:
	cargo test --workspace
