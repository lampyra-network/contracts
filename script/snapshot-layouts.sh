#!/usr/bin/env bash
# Snapshot the storage layouts of the four UUPS-upgradeable contracts into
# deployments/layouts/<Contract>.json. upgrade.sh diffs the current source's
# layout against these snapshots before every upgrade — an existing variable
# that moved slot/offset or changed type means the new implementation would
# read garbage from the proxy's storage (funds-loss class bug), so the
# upgrade refuses to proceed.
#
# Run this ONCE after a genesis (baseline = what's deployed) and again after
# every successful upgrade (upgrade.sh does it for you). Commit the files.
set -euo pipefail
cd "$(dirname "$0")/.."

CONTRACTS=(PyraTreasury WorkerRegistry EscrowPool PyraPresale)
mkdir -p deployments/layouts

forge build --silent

for c in "${CONTRACTS[@]}"; do
  # Reduce to the fields that define binary compatibility. astId/contract
  # metadata churn on unrelated edits — excluded so diffs stay meaningful.
  forge inspect "src/${c}.sol:${c}" storage-layout --json \
    | jq '[.storage[] | {label, slot, offset, type: .type}]' \
    > "deployments/layouts/${c}.json"
  echo "✓ deployments/layouts/${c}.json ($(jq length "deployments/layouts/${c}.json") entries)"
done
