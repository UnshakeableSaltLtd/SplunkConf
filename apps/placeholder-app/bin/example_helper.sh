#!/usr/bin/env bash
# example_helper.sh — template bash helper script
# Usage: ./example_helper.sh <argument>
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $(basename "$0") <argument>"
    exit 1
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
    fi

    local arg="$1"
    echo "Processing: ${arg}"
    # Add your logic here
}

main "$@"
