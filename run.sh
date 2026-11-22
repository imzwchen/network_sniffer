#!/usr/bin/env bash
set -euo pipefail

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec uv run --project "$project_dir" python -c \
    'from network_sniffer import main; raise SystemExit(main(elevate_live=True))' "$@"
