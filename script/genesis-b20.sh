#!/usr/bin/env bash
# Lampyra ($PYRA) genesis on a real Base network (Sepolia or mainnet).
#
# Vanilla forge cannot execute the B20 factory precompile locally, so the token
# part of the ceremony goes through `cast` (executed by the live node, which has
# the precompile); everything EVM-side then runs in one `forge script Deploy.s.sol`.
#
# Sequence: create B20 -> mint 10B to DEPLOYER -> renounce (supply fixed forever)
#           -> Deploy.s.sol (admin, proxies, treasury funding, presale pull,
#              payout cap, role grants, super-admin handoff) -> verify.
#
# Required env: RPC_URL, PRIVATE_KEY
# Optional env: B20_SALT, SUPER_ADMIN, ORCHESTRATOR, ADMIN_DELAY, USDC,
#               PAYOUT_CAP (PYRA base units), PAYOUT_WINDOW (seconds)
set -euo pipefail
cd "$(dirname "$0")/.."

: "${RPC_URL:?set RPC_URL (e.g. https://sepolia.base.org)}"
: "${PRIVATE_KEY:?set PRIVATE_KEY (funded deployer)}"

FACTORY=0xB20f000000000000000000000000000000000000
REGISTRY=0x8453000000000000000000000000000000000001
TOTAL_SUPPLY=10000000000000000000 # 10B PYRA @ 9 decimals
DEPLOYER=$(cast wallet address --private-key "$PRIVATE_KEY")
CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
SEND=(cast send --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL")

echo "== deployer $DEPLOYER on chain $CHAIN_ID"
echo "== deployer balance: $(cast balance "$DEPLOYER" --rpc-url "$RPC_URL" --ether) ETH"

echo "== 0/6 preflight: B20 asset variant activated?"
ACTIVE=$(cast call $REGISTRY "isActivated(bytes32)(bool)" "$(cast keccak "base.b20_asset")" --rpc-url "$RPC_URL")
[ "$ACTIVE" = "true" ] || { echo "FATAL: base.b20_asset not activated on chain $CHAIN_ID"; exit 1; }

echo "== 1/6 building createB20 calldata (official base-std encoders)"
CALLDATA=$(forge script script/B20Params.s.sol 2>/dev/null | grep -o '0x[0-9a-fA-F]\{10,\}' | tail -1)
[ -n "$CALLDATA" ] || { echo "FATAL: could not extract calldata"; exit 1; }

echo "== 2/6 predicting token address (read-only createB20)"
# --from MATTERS: the B20 address derives from the CREATOR — a call without
# --from simulates as address(0) and predicts the wrong address (2026-07-16
# Sepolia lesson).
RAW=$(cast call $FACTORY --data "$CALLDATA" --from "$DEPLOYER" --rpc-url "$RPC_URL")
TOKEN=$(cast parse-bytes32-address "$RAW")
echo "   \$PYRA will live at: $TOKEN"

echo "== 3/6 creating the \$PYRA B20"
# Parse the REAL address from the B20Created event (topic 1) rather than
# trusting the prediction; sepolia.base.org is load-balanced and replicas lag —
# sleep between txs and never pipe cast errors into the void.
RECEIPT=$("${SEND[@]}" --json $FACTORY --data "$CALLDATA")
ACTUAL=0x$(echo "$RECEIPT" | grep -o '"0x000000000000000000000000b2[0-9a-f]*"' | head -1 | tr -d '"' | cut -c27-66)
if [ -n "${ACTUAL#0x}" ] && [ "$ACTUAL" != "$TOKEN" ]; then
  echo "   WARNING: created at $ACTUAL (prediction $TOKEN was wrong) — using actual"
  TOKEN=$ACTUAL
fi
sleep 2
CODE=$(cast code "$TOKEN" --rpc-url "$RPC_URL")
echo "   created. code at token address: ${CODE:0:40}... (len $(( (${#CODE}-2)/2 )) bytes)  <-- audit-H1 probe"
echo "   name=$(cast call "$TOKEN" 'name()(string)' --rpc-url "$RPC_URL")  symbol=$(cast call "$TOKEN" 'symbol()(string)' --rpc-url "$RPC_URL")  decimals=$(cast call "$TOKEN" 'decimals()(uint8)' --rpc-url "$RPC_URL")"

echo "== 4/6 minting 10B PYRA to the deployer, then renouncing all token authority"
"${SEND[@]}" "$TOKEN" "mintWithMemo(address,uint256,bytes32)" "$DEPLOYER" $TOTAL_SUPPLY "$(cast format-bytes32-string "lampyra-genesis")" >/dev/null
"${SEND[@]}" "$TOKEN" "renounceRole(bytes32,address)" "$(cast keccak "MINT_ROLE")" "$DEPLOYER" >/dev/null
"${SEND[@]}" "$TOKEN" "renounceLastAdmin()" >/dev/null
echo "   supply fixed forever: totalSupply=$(cast call "$TOKEN" 'totalSupply()(uint256)' --rpc-url "$RPC_URL")"

echo "== 5/6 EVM-side genesis (forge script Deploy.s.sol)"
PYRA_MODE=b20 PYRA_TOKEN=$TOKEN forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --broadcast
# shellcheck disable=SC1090
source "deployments/${CHAIN_ID}.env"

echo "== 6/6 verification"
echo "   treasury PYRA balance: $(cast call "$TOKEN" 'balanceOf(address)(uint256)' "$TREASURY" --rpc-url "$RPC_URL")"
echo "   presale PYRA balance:  $(cast call "$TOKEN" 'balanceOf(address)(uint256)' "$PRESALE" --rpc-url "$RPC_URL") (expect 2500000000000000000)"
echo "   mint-after-renounce must FAIL:"
if "${SEND[@]}" "$TOKEN" "mint(address,uint256)" "$DEPLOYER" 1 >/dev/null 2>&1; then
  echo "   FATAL: mint still possible after renounce!"; exit 1
else
  echo "   ok - mint reverts."
fi
echo
echo "GENESIS COMPLETE - addresses in deployments/${CHAIN_ID}.env"
cat "deployments/${CHAIN_ID}.env"
