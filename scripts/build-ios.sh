#!/usr/bin/env bash
# Build Libcrust.xcframework for iOS via gomobile bind.
#
# Usage:
#   ./scripts/build-ios.sh              # build xcframework
#   ./scripts/build-ios.sh --install    # also install gomobile if missing
#
# Output: build/ios/Libcrust.xcframework
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT_DIR/build/ios"

# --- helpers ----------------------------------------------------------------
info()  { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
error() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

check_go() {
    command -v go >/dev/null 2>&1 || error "go not found in PATH"
    info "Go $(go version | awk '{print $3}')"
}

ensure_gomobile() {
    if ! command -v gomobile >/dev/null 2>&1; then
        if [[ "${1:-}" == "--install" ]]; then
            info "Installing gomobile..."
            go install golang.org/x/mobile/cmd/gomobile@latest
            go install golang.org/x/mobile/cmd/gobind@latest
            gomobile init
        else
            error "gomobile not found. Run with --install or: go install golang.org/x/mobile/cmd/gomobile@latest"
        fi
    fi
    info "gomobile: $(command -v gomobile)"
}

# --- build ------------------------------------------------------------------
build_xcframework() {
    mkdir -p "$OUT_DIR"
    cd "$ROOT_DIR"

    info "Building Libcrust.xcframework..."

    # Version info via ldflags
    local version commit build_date ldflags
    version="$(git describe --tags --always --dirty 2>/dev/null || echo "dev")"
    commit="$(git rev-parse --short HEAD 2>/dev/null || echo "none")"
    build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    ldflags="-X github.com/BakeLens/crust/pkg/libcrust.Version=${version}"
    ldflags+=" -X github.com/BakeLens/crust/pkg/libcrust.Commit=${commit}"
    ldflags+=" -X github.com/BakeLens/crust/pkg/libcrust.BuildDate=${build_date}"

    gomobile bind \
        -target ios \
        -tags libcrust \
        -ldflags "$ldflags" \
        -o "$OUT_DIR/Libcrust.xcframework" \
        ./pkg/libcrust/

    info "Output: $OUT_DIR/Libcrust.xcframework"
    info "Done! Add Libcrust.xcframework to your Xcode project."
}

# --- main -------------------------------------------------------------------
check_go
ensure_gomobile "${1:-}"
build_xcframework
