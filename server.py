#!/usr/bin/env python3
"""contract-guard engine — pre-interaction risk signals for an EVM contract/token.

Pure JSON-RPC (no signing, no upstream cost). Given a contract address it reports:
  - is it a contract (eth_getCode) or an EOA / self-destructed
  - upgradeable proxy detection (EIP-1967 implementation + admin slots)
  - ERC20 metadata (name / symbol / decimals / totalSupply via eth_call)
  - a risk score + human-readable flags an agent can act on before interacting

Why agents pay for this: the on-chain-data category is the busiest on the x402
discovery layer, but it's all raw RPC proxies. This adds a security verdict
(mutable-logic proxy = rug vector, non-standard token, dead address) on top.
"""
import json
import urllib.request

RPCS = {
    "base":     ["https://mainnet.base.org", "https://base-rpc.publicnode.com", "https://base.drpc.org"],
    "ethereum": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org"],
}
CHAIN_IDS = {"base": 8453, "ethereum": 1}

# EIP-1967 storage slots (+ legacy zeppelinos slot used by older proxies e.g. USDC)
SLOT_IMPL    = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
SLOT_ADMIN   = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
SLOT_LEGACY  = "0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3"
# Common ERC20 view selectors
SEL = {
    "name":        "0x06fdde03",
    "symbol":      "0x95d89b41",
    "decimals":    "0x313ce567",
    "totalSupply": "0x18160ddd",
}


def _rpc(rpc_urls, method, params):
    if isinstance(rpc_urls, str):
        rpc_urls = [rpc_urls]
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    last = None
    for url in rpc_urls:
        try:
            req = urllib.request.Request(url, data=body, headers={
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (contract-guard x402)",
            }, method="POST")
            with urllib.request.urlopen(req, timeout=12) as r:
                d = json.loads(r.read().decode())
            if "error" in d:
                last = RuntimeError(d["error"].get("message", "rpc error"))
                continue
            return d.get("result")
        except Exception as e:
            last = e
            continue
    if last:
        raise last
    return None


def _eth_call(rpc_url, to, data):
    try:
        return _rpc(rpc_url, "eth_call", [{"to": to, "data": data}, "latest"])
    except Exception:
        return None


def _dec_uint(hexstr):
    if not hexstr or hexstr == "0x":
        return None
    try:
        return int(hexstr, 16)
    except Exception:
        return None


def _dec_string(hexstr):
    """Decode an ABI string return, falling back to bytes32-style tokens."""
    if not hexstr or hexstr == "0x":
        return None
    raw = bytes.fromhex(hexstr[2:])
    # dynamic string: [offset(32)][length(32)][data]
    if len(raw) >= 64:
        try:
            length = int.from_bytes(raw[32:64], "big")
            if 0 < length <= len(raw) - 64:
                s = raw[64:64 + length].decode("utf-8", "replace").strip("\x00")
                if s:
                    return s
        except Exception:
            pass
    # bytes32 fallback (non-standard tokens)
    s = raw.rstrip(b"\x00").decode("utf-8", "replace").strip("\x00")
    return s or None


def _addr_from_slot(hexstr):
    if not hexstr:
        return None
    h = hexstr[2:].rjust(64, "0")
    addr = "0x" + h[-40:]
    return None if int(addr, 16) == 0 else addr.lower()


def analyze(address, chain="base"):
    chain = (chain or "base").lower()
    if chain not in RPCS:
        return {"error": "unsupported chain '%s' (use: %s)" % (chain, ", ".join(RPCS))}
    a = (address or "").strip()
    if not (a.startswith("0x") and len(a) == 42):
        try:
            int(a, 16)
        except Exception:
            return {"error": "invalid EVM address"}
        return {"error": "invalid EVM address (expected 0x + 40 hex)"}
    rpc = RPCS[chain]

    flags = []
    score = 0

    code = _rpc(rpc, "eth_getCode", [a, "latest"])
    is_contract = bool(code) and code != "0x"
    bytecode_len = (len(code) - 2) // 2 if is_contract else 0

    if not is_contract:
        return {
            "address": a, "chain": chain, "chain_id": CHAIN_IDS[chain],
            "is_contract": False,
            "risk_level": "NOT_A_CONTRACT",
            "risk_score": 0,
            "flags": ["Address has no bytecode — it is an EOA (wallet) or a self-destructed contract, not a token/contract."],
            "summary": "Not a contract.",
        }

    # EIP-7702 delegated EOA: bytecode is exactly 0xef0100 + 20-byte delegate address
    if code[:8].lower() == "0xef0100":
        delegate = "0x" + code[8:48].lower()
        return {
            "address": a, "chain": chain, "chain_id": CHAIN_IDS[chain],
            "is_contract": False,
            "eip7702_delegated": True,
            "delegate": delegate,
            "risk_level": "HIGH",
            "risk_score": 45,
            "flags": ["EIP-7702 delegated EOA — this wallet has set code delegating control to contract %s. The delegate contract can move assets per the wallet's authorization; treat as smart-account, not a plain wallet." % delegate],
            "summary": "HIGH — EIP-7702 delegated EOA -> %s" % delegate,
        }

    # Proxy detection: EIP-1967 (impl + admin) and legacy zeppelinos slot
    impl  = _addr_from_slot(_rpc(rpc, "eth_getStorageAt", [a, SLOT_IMPL, "latest"]))
    admin = _addr_from_slot(_rpc(rpc, "eth_getStorageAt", [a, SLOT_ADMIN, "latest"]))
    if impl is None:
        impl = _addr_from_slot(_rpc(rpc, "eth_getStorageAt", [a, SLOT_LEGACY, "latest"]))
    is_proxy = impl is not None
    if is_proxy:
        score += 40
        flags.append("Upgradeable proxy (EIP-1967): the admin can swap the implementation, so token/transfer logic can change after you interact. impl=%s%s" % (impl, (" admin=%s" % admin) if admin else ""))

    # ERC20 metadata
    name    = _dec_string(_eth_call(rpc, a, SEL["name"]))
    symbol  = _dec_string(_eth_call(rpc, a, SEL["symbol"]))
    decimals = _dec_uint(_eth_call(rpc, a, SEL["decimals"]))
    supply  = _dec_uint(_eth_call(rpc, a, SEL["totalSupply"]))
    looks_erc20 = symbol is not None and decimals is not None

    if not looks_erc20:
        score += 15
        flags.append("No standard ERC20 metadata (symbol/decimals) — non-standard token or a non-token contract; verify intent before approving/swapping.")
    if bytecode_len < 200:
        score += 10
        flags.append("Very small bytecode (%d bytes) — minimal/forwarder contract; confirm it does what you expect." % bytecode_len)

    score = min(100, score)
    level = "CRITICAL" if score >= 50 else "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW" if score > 0 else "OK"

    return {
        "address": a, "chain": chain, "chain_id": CHAIN_IDS[chain],
        "is_contract": True,
        "bytecode_bytes": bytecode_len,
        "is_proxy": is_proxy,
        "implementation": impl,
        "admin": admin,
        "token": {"name": name, "symbol": symbol, "decimals": decimals, "total_supply": str(supply) if supply is not None else None},
        "looks_erc20": looks_erc20,
        "risk_level": level,
        "risk_score": score,
        "flags": flags or ["No elevated risk signals from on-chain checks. (Not a substitute for a full audit.)"],
        "summary": "%s — %s%s" % (
            level,
            ("proxy " if is_proxy else "") + (("%s (%s)" % (name, symbol)) if symbol else "contract"),
            " | %d risk flag(s)" % len(flags) if flags else "",
        ),
    }

ALLOWANCE_SEL = "0xdd62ed3e"  # allowance(address,address)
_UINT_MAX = (1 << 256) - 1


def check_approval(token, owner, spender, chain="base"):
    """How much of `owner`'s `token` the `spender` is approved to move. Flags unlimited approvals."""
    chain = (chain or "base").lower()
    if chain not in RPCS:
        return {"error": "unsupported chain '%s'" % chain}
    for label, a in (("token", token), ("owner", owner), ("spender", spender)):
        if not (isinstance(a, str) and a.startswith("0x") and len(a) == 42):
            return {"error": "invalid %s address" % label}
    rpc = RPCS[chain]
    data = ALLOWANCE_SEL + owner[2:].rjust(64, "0").lower() + spender[2:].rjust(64, "0").lower()
    allowance = _dec_uint(_eth_call(rpc, token, data))
    if allowance is None:
        return {"error": "could not read allowance (not an ERC20, or RPC error)"}
    unlimited = allowance >= (_UINT_MAX >> 1)
    dec = _dec_uint(_eth_call(rpc, token, SEL["decimals"]))
    sym = _dec_string(_eth_call(rpc, token, SEL["symbol"]))
    human = (allowance / (10 ** dec)) if (dec is not None and not unlimited) else None
    flags, score = [], 0
    if unlimited:
        score = 70
        flags.append("UNLIMITED approval — spender %s can move ALL of the owner's %s at any time. Revoke if not actively needed." % (spender, sym or "token"))
    elif allowance > 0:
        score = 20
        flags.append("Active allowance of %s %s to spender %s." % (human if human is not None else allowance, sym or "", spender))
    level = "HIGH" if score >= 70 else "MEDIUM" if score >= 20 else "OK"
    return {
        "token": token, "owner": owner, "spender": spender, "chain": chain,
        "allowance_raw": str(allowance), "allowance": human, "unlimited": unlimited,
        "symbol": sym, "decimals": dec,
        "risk_level": level, "risk_score": score,
        "flags": flags or ["No allowance (0) — spender cannot move this token."],
        "summary": "%s — allowance %s%s to %s" % (
            level, "UNLIMITED" if unlimited else (human if human is not None else allowance),
            (" " + sym) if sym else "", spender[:10]),
    }


# ────────────────────────────────────────────────────────
# MCP stdio server (JSON-RPC 2.0, protocol 2024-11-05)
# ────────────────────────────────────────────────────────
import sys

VERSION = "1.1.0"
PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "contract-guard"

TOOLS = [
    {
        "name": "check_contract",
        "description": (
            "Pre-interaction risk check for an EVM contract/token address. Returns: is-contract vs "
            "EOA, EIP-7702 delegated-EOA detection, upgradeable-proxy detection (EIP-1967 + legacy), "
            "ERC20 metadata (name/symbol/decimals/totalSupply), and a risk score with actionable flags. "
            "Call this before approving, swapping, or trusting a token. Pure public RPC, no signing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {"type": "string", "description": "EVM contract/token address (0x + 40 hex)"},
                "chain": {"type": "string", "enum": ["base", "ethereum"], "description": "Chain (default: base)"},
            },
            "required": ["address"],
        },
    },
    {
        "name": "check_approval",
        "description": (
            "Check how much of an owner's ERC20 token a spender is approved to move (allowance). "
            "Flags UNLIMITED approvals — the #1 wallet-drain vector. Call this to audit existing approvals "
            "or before signing an approve(). Pure public RPC, no signing."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "token": {"type": "string", "description": "ERC20 token contract address"},
                "owner": {"type": "string", "description": "Wallet that granted the approval"},
                "spender": {"type": "string", "description": "Contract/address approved to spend"},
                "chain": {"type": "string", "enum": ["base", "ethereum"], "description": "Chain (default: base)"},
            },
            "required": ["token", "owner", "spender"],
        },
    },
]


def handle_request(req):
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": VERSION},
        }}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params", {}) or {}
        name = params.get("name")
        args = params.get("arguments", {}) or {}
        try:
            if name == "check_contract":
                result = analyze(args.get("address", ""), args.get("chain", "base"))
            elif name == "check_approval":
                result = check_approval(args.get("token", ""), args.get("owner", ""),
                                        args.get("spender", ""), args.get("chain", "base"))
            else:
                return {"jsonrpc": "2.0", "id": rid, "result": {
                    "isError": True, "content": [{"type": "text", "text": "Unknown tool: %s" % name}]}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid, "result": {
                "isError": True, "content": [{"type": "text", "text": "rpc error: %s" % e}]}}
        is_err = "error" in result
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "isError": is_err,
            "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
        }}
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "Method not found: %s" % method}}


def main():
    """Read JSON-RPC messages from stdin, write responses to stdout."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_request(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
