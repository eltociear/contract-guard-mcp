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
