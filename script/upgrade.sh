#!/usr/bin/env bash
# upgrade.sh — UUPS upgrade ceremony for one Lampyra proxy contract.
#
#   ./script/upgrade.sh <PyraTreasury|WorkerRegistry|EscrowPool|PyraPresale>
#
# What it does, in order:
#   1. forge build + STORAGE-LAYOUT GUARD: the current source's layout must
#      be append-only compatible with deployments/layouts/<Contract>.json
#      (the layout that's live behind the proxy). A moved/retyped/deleted
#      variable makes the new code read garbage from proxy storage, and
#      nothing on-chain stops you from shipping it: an incompatible layout
#      deploys and corrupts silently. This guard is the stop.
#   2. Deploys the new implementation (plain `forge create`, deployer key).
#   3. Executes proxy.upgradeToAndCall(newImpl, "") — or, when the admin
#      is on the Ledger (mainnet), prints the exact `cast send --ledger`
#      command instead of executing.
#   4. Verifies the EIP-1967 implementation slot now points at the new
#      impl, updates deployments/<chainid>.env, re-snapshots the layout.
#
# Required env: RPC_URL, PRIVATE_KEY (implementation deployer — any funded
#               key; deploying an impl needs no authority).
# Upgrade authority (PyraAdmin DEFAULT_ADMIN) — one of:
#   ADMIN_PRIVATE_KEY  — testnet: the deployer EOA that still holds
#                        DEFAULT_ADMIN. Executes the upgrade directly.
#   ADMIN_LEDGER=1     — mainnet: prints the cast --ledger command for the
#                        founder to run (the key never leaves the device).
#
# Migration functions: pass INIT_CALLDATA=0x… to run a reinitializer in the
# same tx (upgradeToAndCall's data arg). Default: empty (state untouched).
set -euo pipefail
cd "$(dirname "$0")/.."

CONTRACT="${1:?usage: upgrade.sh <PyraTreasury|WorkerRegistry|EscrowPool|PyraPresale>}"
: "${RPC_URL:?set RPC_URL}"
: "${PRIVATE_KEY:?set PRIVATE_KEY (impl deployer)}"
INIT_CALLDATA="${INIT_CALLDATA:-0x}"

case "$CONTRACT" in
  PyraTreasury)   PROXY_KEY=TREASURY;        IMPL_KEY=TREASURY_IMPL ;;
  WorkerRegistry) PROXY_KEY=WORKER_REGISTRY; IMPL_KEY=WORKER_REGISTRY_IMPL ;;
  EscrowPool)     PROXY_KEY=ESCROW;          IMPL_KEY=ESCROW_IMPL ;;
  PyraPresale)    PROXY_KEY=PRESALE;         IMPL_KEY=PRESALE_IMPL ;;
  *) echo "FATAL: unknown contract $CONTRACT"; exit 1 ;;
esac

CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
DEPLOY_ENV="deployments/${CHAIN_ID}.env"
[ -f "$DEPLOY_ENV" ] || { echo "FATAL: $DEPLOY_ENV missing — no genesis on chain $CHAIN_ID?"; exit 1; }
PROXY=$(grep -E "^${PROXY_KEY}=" "$DEPLOY_ENV" | tail -1 | cut -d= -f2)
[ -n "$PROXY" ] || { echo "FATAL: $PROXY_KEY not in $DEPLOY_ENV"; exit 1; }

SNAPSHOT="deployments/layouts/${CONTRACT}.json"
[ -f "$SNAPSHOT" ] || { echo "FATAL: $SNAPSHOT missing — run script/snapshot-layouts.sh at genesis first"; exit 1; }

echo "== upgrading $CONTRACT (proxy $PROXY) on chain $CHAIN_ID"

echo "== 1/4 build + storage-layout guard"
forge build --silent
NEW_LAYOUT=$(forge inspect "src/${CONTRACT}.sol:${CONTRACT}" storage-layout --json \
  | jq '[.storage[] | {label, slot, offset, type: .type}]')

# Append-only check, __gap-aware: every non-gap entry in the DEPLOYED
# layout must appear unchanged (same label/slot/offset/type) at the same
# position in the new layout. New variables may only be added by consuming
# __gap (which shrinks the gap entry's type — allowed) or appending after
# the last entry of the final inheritance gap (verify gap math manually).
GUARD=$(jq -n --argjson old "$(jq '[.[] | select(.label != "__gap")]' "$SNAPSHOT")" \
              --argjson new "$(echo "$NEW_LAYOUT" | jq '[.[] | select(.label != "__gap")]')" '
  ($old | length) as $n
  | if ($new | length) < $n then "DELETED: new layout has fewer variables than deployed"
    else ([range(0; $n) | select($old[.] != $new[.])
           | "MOVED/RETYPED at index \(.): deployed \($old[.] | tostring) vs new \($new[.] | tostring)"]
          | if length == 0 then "OK" else .[0] end)
    end')
if [ "$GUARD" != '"OK"' ]; then
  echo "FATAL: storage layout is NOT upgrade-compatible:"
  echo "  $GUARD"
  echo "  An existing variable moved, changed type, or vanished — the new"
  echo "  implementation would misread live proxy storage. Restructure the"
  echo "  change (append via __gap) or plan a fresh deploy + migration."
  exit 1
fi
echo "   layout OK (append-only vs deployed snapshot)"

echo "== 2/4 deploying new implementation"
# --broadcast is REQUIRED on forge 1.x — without it `create` only
# simulates and prints a tx skeleton with no deployedTo (2026-07-16 lesson).
NEW_IMPL=$(forge create "src/${CONTRACT}.sol:${CONTRACT}" --broadcast \
  --rpc-url "$RPC_URL" --private-key "$PRIVATE_KEY" --json | jq -r .deployedTo)
[ -n "$NEW_IMPL" ] && [ "$NEW_IMPL" != "null" ] || { echo "FATAL: forge create produced no address"; exit 1; }
echo "   new implementation: $NEW_IMPL"

echo "== 3/4 upgradeToAndCall"
# sepolia.base.org is load-balanced with LAGGING replicas — a send right
# after the impl-deploy tx races its nonce ("replacement transaction
# underpriced"). Sleep + one retry, same discipline as genesis-b20.sh.
sleep 3
if [ -n "${ADMIN_PRIVATE_KEY:-}" ]; then
  if ! cast send --private-key "$ADMIN_PRIVATE_KEY" --rpc-url "$RPC_URL" \
    "$PROXY" "upgradeToAndCall(address,bytes)" "$NEW_IMPL" "$INIT_CALLDATA" >/dev/null; then
    echo "   send failed (replica nonce lag?) — retrying once in 5s"
    sleep 5
    cast send --private-key "$ADMIN_PRIVATE_KEY" --rpc-url "$RPC_URL" \
      "$PROXY" "upgradeToAndCall(address,bytes)" "$NEW_IMPL" "$INIT_CALLDATA" >/dev/null
  fi
  sleep 2
elif [ "${ADMIN_LEDGER:-}" = "1" ]; then
  echo "   DEFAULT_ADMIN is on the Ledger — run this yourself, then re-run"
  echo "   this script with SKIP_TO_VERIFY=1 to finish bookkeeping:"
  echo
  echo "   cast send --ledger --rpc-url $RPC_URL \\"
  echo "     $PROXY 'upgradeToAndCall(address,bytes)' $NEW_IMPL $INIT_CALLDATA"
  echo
  [ "${SKIP_TO_VERIFY:-}" = "1" ] || exit 0
else
  echo "FATAL: set ADMIN_PRIVATE_KEY (testnet) or ADMIN_LEDGER=1 (mainnet)"; exit 1
fi

echo "== 4/4 verify + bookkeeping"
# EIP-1967 implementation slot.
LIVE_IMPL=$(cast storage "$PROXY" \
  0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc \
  --rpc-url "$RPC_URL")
LIVE_IMPL="0x$(echo "$LIVE_IMPL" | cut -c27-66)"
if [ "$(echo "$LIVE_IMPL" | tr 'A-F' 'a-f')" != "$(echo "$NEW_IMPL" | tr 'A-F' 'a-f')" ]; then
  echo "FATAL: proxy implementation slot is $LIVE_IMPL, expected $NEW_IMPL — upgrade did NOT land"
  exit 1
fi
# Update the impl line in the deployments env + refresh the layout snapshot.
tmp=$(mktemp)
grep -vE "^${IMPL_KEY}=" "$DEPLOY_ENV" > "$tmp" || true
echo "${IMPL_KEY}=${NEW_IMPL}" >> "$tmp"
mv "$tmp" "$DEPLOY_ENV"
echo "$NEW_LAYOUT" > "$SNAPSHOT"
echo
echo "UPGRADE COMPLETE: $CONTRACT proxy $PROXY → impl $NEW_IMPL"
echo "Commit the updated $DEPLOY_ENV + $SNAPSHOT."
echo "Proxy addresses do NOT change on upgrade, so no downstream re-seeding of"
echo "deployment config is required unless a PROXY address changed (it didn't)."
