#!/bin/sh
# check-version.sh <version> — fails unless the Rust CLI crate's version (the
# value `wapps --version` prints) equals <version>, the release tag without its
# "v". GoReleaser runs it as a `before` hook (.goreleaser.yml), so a tag whose
# version Cargo.toml does not carry stops the release before anything is built.
set -eu
want="${1:?usage: check-version.sh <version>}"
manifest="$(dirname "$0")/crates/cli/Cargo.toml"
have="$(sed -n 's/^version = "\(.*\)"$/\1/p' "$manifest" | head -n 1)"
if [ "$have" != "$want" ]; then
  echo "release version $want does not match $manifest version $have; bump Cargo.toml to $want in the tagged commit" >&2
  exit 1
fi
