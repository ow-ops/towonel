.PHONY: build test lint fmt check docker docker-agent docker-node up down e2e e2e-tls release clean mesh-android mesh-bindings e2e-mesh

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

build:
	cargo build --release -p towonel-agent -p towonel-node

test:
	cargo test --all-targets

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --check

check: fmt lint test

docker:
	docker build -t towonel:$(VERSION) .

docker-agent:
	docker build -f Dockerfile.agent -t towonel-agent:$(VERSION) .

docker-node:
	docker build -f Dockerfile.node -t towonel-node:$(VERSION) .

up:
	docker compose up --build -d

down:
	docker compose down

# NB: run detached and `docker wait` on the runner instead of
# --abort-on-container-exit; the route_recovery case restarts the hub, which
# would otherwise trip the abort and kill the runner mid-test.
E2E_FILES ?= -f docker-compose.e2e.yml

e2e:
	./tests/e2e/fixtures/make-fixtures.sh
	docker compose --env-file .env.e2e $(E2E_FILES) down -v
	docker compose --env-file .env.e2e $(E2E_FILES) up --build --no-start
	docker compose --env-file .env.e2e $(E2E_FILES) cp tests/e2e/fixtures/. pebble:/certs
	docker compose --env-file .env.e2e $(E2E_FILES) up --detach || { \
		docker compose --env-file .env.e2e $(E2E_FILES) logs --no-color; \
		docker compose --env-file .env.e2e $(E2E_FILES) down -v; \
		exit 1; }
	@code=$$(docker wait towonel-e2e-runner); \
		docker compose --env-file .env.e2e $(E2E_FILES) logs --no-color test-runner; \
		echo "test-runner exit code: $$code"; \
		docker compose --env-file .env.e2e $(E2E_FILES) down -v; \
		exit $$code

# Same suite with the agent's outbound UDP to the edge's QUIC port dropped, so it runs over TLS.
e2e-tls:
	$(MAKE) e2e E2E_FILES="-f docker-compose.e2e.yml -f docker-compose.e2e-tls.yml"

# Mesh with real TUN devices in containers.
e2e-mesh:
	cargo build --release -p towonel-node
	./tests/e2e/mesh.sh

# Mesh client library for the mobile apps (crates/towonel-mesh-ffi).
# arm64 for phones, x86_64 for the emulator. Needs ANDROID_NDK_HOME.
ANDROID_API ?= 26
NDK_BIN = $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin

mesh-android:
	for target in aarch64-linux-android x86_64-linux-android; do \
		t=$$(echo $$target | tr - _); T=$$(echo $$t | tr a-z A-Z); \
		env CC_$$t=$(NDK_BIN)/$${target}$(ANDROID_API)-clang AR_$$t=$(NDK_BIN)/llvm-ar \
			CARGO_TARGET_$${T}_LINKER=$(NDK_BIN)/$${target}$(ANDROID_API)-clang \
			cargo build --release -p towonel-mesh-ffi --target $$target || exit 1; \
	done

# Kotlin and Swift sources for the FFI, into target/bindings.
mesh-bindings:
	cargo build -p towonel-mesh-ffi
	for lang in kotlin swift; do \
		cargo run -p towonel-mesh-ffi --features bindgen --bin uniffi-bindgen -- \
			generate --library target/debug/libtowonel_mesh_ffi.so --language $$lang \
			--out-dir target/bindings/$$lang --no-format || exit 1; \
	done

release:
	@test -n "$(V)" || (echo "usage: make release V=0.1.0" && exit 1)
	git tag -a "v$(V)" -m "v$(V)"
	@echo "Tagged v$(V). Push with: git push origin v$(V)"

clean:
	cargo clean
	docker compose --env-file .env.e2e -f docker-compose.e2e.yml down -v 2>/dev/null || true
