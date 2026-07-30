# Lampyra ($PYRA) contracts — Base

The on-chain layer of [Lampyra](https://lampyra.io), a decentralized video
transcoding network: the $PYRA token, worker registry, customer escrow with
batched settlement, treasury, and the USDC presale. Job orchestration is
deliberately off-chain — a per-source-minute workload generates thousands of
micro-transactions — so these contracts hold only what has to be trustless,
and the orchestrator reconciles to them every four hours.

Five UUPS proxies plus a B20 token, MIT-licensed, 304 passing Foundry tests
(unit + invariant). Live on Base Sepolia — addresses in
[deployments/84532.env](deployments/84532.env).

Structural rules live in [CONVENTIONS.md](CONVENTIONS.md); the token ceremony
in [B20.md](B20.md).

| Contract | Shape |
|---|---|
| *(none — $PYRA is a **B20**)* | Base-native precompile token via the B20 factory: name "Lampyra", symbol "PYRA", **9 decimals**, fixed 10B supply, admin renounced at genesis — see [B20.md](B20.md). Tests mock it (`test/mocks/MockPYRA.sol`) |
| `PyraAdmin` | `AccessControlDefaultAdminRules` — delayed two-step super-admin, `ADMIN_ROLE`, `ORCHESTRATOR_ROLE` |
| `PyraTreasury` | UUPS — pools, withdrawal caps, vesting |
| `WorkerRegistry` | UUPS — wallet→workers, per-wallet tier via `balanceOf` |
| `EscrowPool` | UUPS — `deposit(amount, ref)`, `settleBatch(cycleId, …)` with built-in cycle dedup, fee ≤5% |
| `PyraPresale` | UUPS — 5 USD-priced stages paid in USDC, freeze-on-first-buy, 25% TGE + 90d linear vesting |

## Build / test

```sh
./deps.sh    # once after clone (and in CI): fetches pinned deps into lib/
forge build
forge test
```

`lib/` is gitignored; `deps.sh` pins exact versions (forge-std v1.9.6,
OpenZeppelin + upgradeable v5.1.0, base-std @ commit) — bump pins there
deliberately, never implicitly.

Testnet target: **Base Sepolia** (chain 84532). USDC there:
`0x036CbD53842c5426634e7929541eC2318f3dCF7e`; Base mainnet USDC:
`0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`.
