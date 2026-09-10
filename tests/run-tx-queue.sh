#!/bin/sh
set -eu
tx_test_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tx_test_dir=$(mktemp -d)
trap 'rm -rf "$tx_test_dir"' EXIT HUP INT TERM
# Run outside the firmware workspace so its ESP linker flags/build-std config
# cannot affect this host-only crate.
cd "$tx_test_dir"
export CARGO_TARGET_DIR="$tx_test_root/target/host-tx-queue"
exec_cargo=${CARGO:-cargo}
"$exec_cargo" test --locked --manifest-path "$tx_test_root/tests/tx-queue/Cargo.toml" "$@"
