#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <cargo> <crate-dir> <output>" >&2
  exit 1
fi

cargo_bin="$1"
crate_dir="$2"
output="$3"
target_dir="$(dirname "$output")/rust-policy-helper-target"

"$cargo_bin" build \
  --manifest-path "$crate_dir/Cargo.toml" \
  --release \
  --locked \
  --target-dir "$target_dir"

cp "$target_dir/release/landlockd-policy-helper-rs" "$output"
chmod 0755 "$output"
