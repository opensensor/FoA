#!/bin/sh
set -eu
replay_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
replay_temp=$(mktemp -d)
trap 'rm -rf "$replay_temp"' EXIT HUP INT TERM
cd "$replay_temp"
export CARGO_TARGET_DIR="$replay_root/target/host-sta-replay"
"${CARGO:-cargo}" test --locked --manifest-path "$replay_root/tests/sta-replay/Cargo.toml" "$@"
