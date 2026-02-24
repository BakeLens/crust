#!/bin/bash
#
# Crust Installer (Open Source)
# https://getcrust.io
#
# Installs the Crust Go binary only.
#
# Usage:
#   curl -fsSL https://install.cat/BakeLens/crust | bash
#
# Or with options:
#   curl -fsSL https://install.cat/BakeLens/crust | bash -s -- --version v2.0.0
#   curl -fsSL https://install.cat/BakeLens/crust | bash -s -- --version main
#

set -e

# Source shared functions (works for both local and piped execution)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/scripts/install-common.sh" ]; then
    # shellcheck source=scripts/install-common.sh
    source "$SCRIPT_DIR/scripts/install-common.sh"
else
    # When piped via curl, download common script to temp
    _common_tmp=$(mktemp)
    trap 'rm -f "$_common_tmp"' EXIT
    if command -v curl &> /dev/null; then
        curl -fsSL "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -o "$_common_tmp"
    elif command -v wget &> /dev/null; then
        wget -q "https://raw.githubusercontent.com/BakeLens/crust/main/scripts/install-common.sh" -O "$_common_tmp"
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$_common_tmp"
fi

main() {
    parse_args "$@"

    if [ -n "$DO_UNINSTALL" ]; then
        run_uninstall
        exit 0
    fi

    print_banner ""
    detect_platform
    check_requirements "go"
    resolve_version

    # Create temp directory
    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    clone_repo "$VERSION" "$tmp_dir/crust"
    build_go_binary "$tmp_dir/crust" "$VERSION"
    install_go_binary "$tmp_dir/crust"
    setup_data_dir
    setup_completion
    setup_font

    # Success
    echo ""
    echo -e "${GREEN}${BOLD}Crust installed successfully!${NC}"
    echo ""
    echo -e "  Binary: ${BLUE}${INSTALL_DIR}/${BINARY_NAME}${NC}"
    echo -e "  Data:   ${BLUE}${DATA_DIR}/${NC}"
    echo ""

    setup_path_hint

    echo -e "${BOLD}Quick Start:${NC}"
    echo ""
    echo "  crust start                    # Start with interactive setup"
    echo "  crust status                   # Check status"
    echo "  crust logs -f                  # Follow logs"
    echo "  crust stop                     # Stop crust"
    echo ""
}

main "$@"
