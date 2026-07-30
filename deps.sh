#!/usr/bin/env bash
# Fetches the pinned dependency set into lib/ (which is gitignored — run this
# once after a fresh clone, and in CI before `forge build`).
# Versions are PINS, not floats: bump them here deliberately, never implicitly.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p lib

fetch_tag() { # name url tag
  rm -rf "lib/$1"
  git clone --quiet --depth 1 --branch "$3" "$2" "lib/$1"
  rm -rf "lib/$1/.git"
  echo "lib/$1 @ $3"
}

fetch_commit() { # name url sha
  rm -rf "lib/$1"
  git clone --quiet "$2" "lib/$1"
  git -C "lib/$1" checkout --quiet "$3"
  rm -rf "lib/$1/.git"
  echo "lib/$1 @ $3"
}

fetch_tag forge-std https://github.com/foundry-rs/forge-std.git v1.9.6
fetch_tag openzeppelin-contracts https://github.com/OpenZeppelin/openzeppelin-contracts.git v5.1.0
fetch_tag openzeppelin-contracts-upgradeable https://github.com/OpenZeppelin/openzeppelin-contracts-upgradeable.git v5.1.0
fetch_commit base-std https://github.com/base/base-std.git 4658f1b7b54ccc61b036adc32830594018ea507e

echo "deps ready — forge build"
