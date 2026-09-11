#!/bin/sh
set -eu
deauth_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
deauth_temp=$(mktemp -d)
trap 'rm -rf "$deauth_temp"' EXIT HUP INT TERM
cd "$deauth_temp"
export CARGO_TARGET_DIR="$deauth_root/target/host-stale-deauth"
"${CARGO:-cargo}" test --locked --manifest-path "$deauth_root/tests/stale-deauth/Cargo.toml" "$@"
