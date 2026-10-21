#!/usr/bin/env bash
# Regenerate the Python stubs for OpenShell's supervisor-middleware contract.
# The .proto files are vendored from https://github.com/NVIDIA/OpenShell/tree/main/proto (Apache-2.0).
#   bash scripts/gen_proto.sh            # regenerate from the vendored protos
#   bash scripts/gen_proto.sh --refresh  # re-download main first (the contract is a research preview and changes)
set -euo pipefail
cd "$(dirname "$0")/.."
SRC=piiguard/middleware/proto; OUT=piiguard/middleware/pb
if [ "${1:-}" = "--refresh" ]; then
  for f in supervisor_middleware.proto extension.proto; do
    curl -sfL "https://raw.githubusercontent.com/NVIDIA/OpenShell/main/proto/$f" -o "$SRC/$f"
  done
fi
.venv/bin/python -m grpc_tools.protoc -I "$SRC" --python_out="$OUT" --grpc_python_out="$OUT" "$SRC"/extension.proto "$SRC"/supervisor_middleware.proto
# protoc emits absolute imports; make them package-relative
sed -i '' -E 's/^import (extension_pb2|supervisor_middleware_pb2)( as |$)/from . import \1\2/' "$OUT"/*.py
echo "stubs regenerated in $OUT"
