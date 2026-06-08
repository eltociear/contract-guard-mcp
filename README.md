# contract-guard-mcp

MCP server for a **pre-interaction risk check** on any EVM contract/token — what an
agent needs before it approves, swaps, or trusts an address.

**Tool:** `check_contract(address, chain="base")` →
- is-contract vs EOA / self-destructed
- **EIP-7702 delegated-EOA** detection
- **upgradeable proxy** detection (EIP-1967 + legacy zeppelinos)
- ERC20 metadata (name / symbol / decimals / totalSupply)
- risk score + actionable flags

Chains: Base, Ethereum. Pure public JSON-RPC, zero dependencies, no signing.

Also available as a pay-per-call x402 HTTP endpoint:
<https://eltociear-contract-guard.hf.space> (`POST /check`, $0.005 USDC on Base).

## Run

```bash
docker run -i --rm ghcr.io/eltociear/contract-guard-mcp:mcp-latest
# or
python3 server.py
```

MIT licensed.

## Tools

- `check_contract(address, chain)` — is-contract/EOA, EIP-7702, proxy, ERC20 metadata, risk score
- `check_approval(token, owner, spender, chain)` — ERC20 allowance audit; flags **unlimited approvals** (the #1 drain vector)

## Free MCP vs paid x402

This MCP server is **free** (run it locally / via your client). For **server-side, batch, or no-install** use, the same engine is a pay-per-call **x402** HTTP API — `POST https://eltociear-contract-guard.hf.space/check` ($0.005 USDC on Base, no signup). Your agent's wallet pays per call.
