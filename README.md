# contract-guard-mcp

[![smithery badge](https://smithery.ai/badge/eltociear/contract-guard-mcp)](https://smithery.ai/server/eltociear/contract-guard-mcp) [![MCP Registry](https://img.shields.io/badge/MCP_Registry-active-2da44e)](https://registry.modelcontextprotocol.io)

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

## Professional audit services

Maintained by the same author — paid services on Polar (Stripe checkout):

- **[MCP Security Audit Report — $5](https://buy.polar.sh/polar_cl_sut9rtngBRutEhBAGk1FmwRYSLrAebowkPw8g2C5Op7)** — one-off audit of your MCP server: 68 attack patterns, severity-rated PDF report with concrete fixes.
- **[Security Pulse — $5/mo](https://buy.polar.sh/polar_cl_jKHyL3Ge9u5YGAsjgixp16UYrhU0WGldxvRmN03expZ)** ([annual $50](https://buy.polar.sh/polar_cl_rEcqwjLJ83vlfa3C8vhAtDLOa6fPVxWeHZyd31BdIPT)) — monthly briefing on newly disclosed MCP server vulnerabilities, scan stats across 100+ tracked repos, mitigation playbooks.
- **[Pro Audit Stack — $20/mo](https://buy.polar.sh/polar_cl_C37THjfoFMdOnu6xc1TnMIezYNuBbbivXbvFb3DCpZa)** — for teams running MCP servers in CI/CD: 50 hosted scans/month, Discord access, 24h SLA on vulnerability questions.

Full catalog: [polar.sh/eltociear](https://polar.sh/eltociear)

### Also live: clean-read ($0.005 / call)

Same operator, same x402 rails: **[clean-read](https://eltociear-skill-audit.hf.space/read)** turns any URL into clean Markdown for AI agents — fetches the page, strips nav/ads/boilerplate (trafilatura), returns the main content with title and word count. `POST https://eltociear-skill-audit.hf.space/read` — $0.005 USDC on Base, no signup.
