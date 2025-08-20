from typing import List, Dict, Any, Optional
from eth_abi import decode as abi_decode
from eth_utils import to_checksum_address

# ---------------- parsing utils ----------------

def _split_top_level_args(types_str: str) -> List[str]:
    """
    Split a Solidity type list string at top-level commas, preserving tuples/arrays.
    E.g. "(address,address,uint24,int24,address),(bool,int256,uint160),bytes"
    -> ["(address,address,uint24,int24,address)", "(bool,int256,uint160)", "bytes"]
    """
    parts, buf, depth = [], [], 0
    for ch in types_str:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            parts.append(''.join(buf).strip())
            buf = []
            continue
        buf.append(ch)
    if buf:
        parts.append(''.join(buf).strip())
    return [p for p in parts if p != ""]


def _extract_types_from_signature(signature: str) -> List[str]:
    """
    Given 'swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)'
    return the list of argument type strings:
    ["(address,address,uint24,int24,address)", "(bool,int256,uint160)", "bytes"]
    """
    l = signature.find('(')
    r = signature.rfind(')')
    if l == -1 or r == -1 or r < l:
        raise ValueError(f"Malformed signature: {signature}")
    inner = signature[l+1:r].strip()
    if not inner:
        return []
    return _split_top_level_args(inner)


def _postprocess_value(sol_type: str, value: Any) -> Any:
    """
    Niceties for readability:
    - addresses -> checksum 0x...
    - bytes -> 0x-hex
    - tuples and nested structures handled recursively
    """
    # normalize type (strip spaces)
    t = sol_type.replace(" ", "")
    # arrays: T[], T[k]
    if t.endswith(']'):
        # find base type
        base = t[:t.rfind('[')]
        return [_postprocess_value(base, v) for v in value]

    # tuple: (t1,t2,...)
    if t.startswith('(') and t.endswith(')'):
        subtypes = _split_top_level_args(t[1:-1])
        return {f"_{i}": _postprocess_value(subtypes[i], value[i]) for i in range(len(subtypes))}

    # elementary
    if t == 'address':
        return to_checksum_address(value)
    if t.startswith('bytes') and t != 'bytes':
        # fixed-size bytesN -> hex
        return '0x' + value.hex()
    if t == 'bytes':
        return '0x' + value.hex()
    # bool/int/uint* left as-is (Python int/bool)
    return value


def parse_tx_input(calldata_hex: str,
                   selectors: Dict[str, Dict[str, str]]) -> Dict[str, Any]:
    """
    Parse a hex calldata string using a function-selector dictionary.
    Returns a dict with selector, name, signature, arg_types, args_decoded.
    """
    if calldata_hex.startswith('0x'):
        calldata_hex = calldata_hex[2:]
    if len(calldata_hex) < 8:
        raise ValueError("Calldata too short to contain a selector.")
    selector = '0x' + calldata_hex[:8]
    body_hex = calldata_hex[8:]
    body_bytes = bytes.fromhex(body_hex)

    entry: Optional[Dict[str, str]] = selectors.get(selector)
    if not entry:
        return {
            "selector": selector,
            "known": False,
            "error": "Unknown function selector",
        }

    signature = entry['signature']
    name = entry['name']
    arg_types = _extract_types_from_signature(signature)

    if not arg_types:
        # no-arg function
        return {
            "selector": selector,
            "known": True,
            "name": name,
            "signature": signature,
            "arg_types": [],
            "args_decoded": []
        }

    # eth-abi expects a list like ["address","uint256","(bool,int256,uint160)","bytes"]
    decoded = abi_decode(arg_types, body_bytes)

    # Post-process for readability (addresses, bytes, tuples, arrays)
    pretty = []
    for t, v in zip(arg_types, decoded):
        pretty.append(_postprocess_value(t, v))

    return {
        "selector": selector,
        "known": True,
        "name": name,
        "signature": signature,
        "arg_types": arg_types,
        "args_decoded": pretty
    }



# Curated list of topics 0 mapped to Event names
# https://www.4byte.directory/event-signatures/


f_selector_dict = dict()

f_selector_dict['0x70a08231'] = {
    'name': 'balanceOf', 'signature': 'balanceOf(address)'
}


f_selector_dict['0xa9059cbb'] = {
    'name': 'transfer', 'signature': 'transfer(address,uint256)'
}


f_selector_dict['0x128acb08'] = {
    'name': 'swap', 'signature': 'swap(address,bool,int256,uint160,bytes)'
}

f_selector_dict['0x23b872dd'] = {
    'name': 'transferFrom', 'signature': 'transferFrom(address,address,uint256)'
}


f_selector_dict['0x48c89491'] = {
    'name': 'unlock', 'signature': 'unlock(bytes)'
}

f_selector_dict['0x91dd7346'] = {
    'name': 'unlockCallback', 'signature': 'unlockCallback(bytes)'
}

f_selector_dict['0xf3cd914c'] = {
    'name': 'swap', 'signature': 'swap((address,address,uint24,int24,address),(bool,int256,uint160),bytes)'
}

f_selector_dict['0xd0c93a7c'] = {
    'name': 'tickSpacing', 'signature': 'tickSpacing()'
}

f_selector_dict['0x3850c7bd'] = {
    'name': 'slot0', 'signature': 'slot0()'
}

f_selector_dict['0xf135baaa'] = {
    'name': 'exttload', 'signature': 'exttload(bytes32)'
}

f_selector_dict['0xfa461e33'] = {
    'name': 'uniswapV3SwapCallback', 'signature': 'uniswapV3SwapCallback(int256,int256,bytes)'
}

f_selector_dict['0x0b0d9c09'] = {
    'name': 'take', 'signature': 'take(address,address,uint256)'
}

f_selector_dict['0x11da60b4'] = {
    'name': 'settle', 'signature': 'settle()'
}

f_selector_dict['0x1a686502'] = {
    'name': 'liquidity', 'signature': 'liquidity()'
}

f_selector_dict['0x5339c296'] = {
    'name': 'tickBitmap', 'signature': 'tickBitmap(int16)'
}


f_selector_dict['0xb88c9148'] = {
    'name': 'getFee', 'signature': 'getFee(address)'
}


f_selector_dict['0x095ea7b3'] = {
    'name': 'approve', 'signature': 'approve(address,uint256)'
}


f_selector_dict['0x0902f1ac'] = {
    'name': 'getReserves', 'signature': 'getReserves()'
}

f_selector_dict['0xa5841194'] = {
    'name': 'sync', 'signature': 'sync(address)'
}

f_selector_dict['0x2e1a7d4d'] = {
    'name': 'withdraw', 'signature': 'withdraw(uint256)'
}

f_selector_dict['0xddca3f43'] = {
    'name': 'fee', 'signature': 'fee()'
}

f_selector_dict['0xd0e30db0'] = {
    'name': 'deposit', 'signature': 'deposit()'
}

f_selector_dict['0xfeaf968c'] = {
    'name': 'latestRoundData', 'signature': 'latestRoundData()'
}

f_selector_dict['0x35458dcc'] = {
    'name': 'getSwapFee', 'signature': 'getSwapFee(address)'
}

f_selector_dict['0x23a69e75'] = {
    'name': 'pancakeV3SwapCallback', 'signature': 'pancakeV3SwapCallback(int256,int256,bytes)'
}

f_selector_dict['0x022c0d9f'] = {
    'name': 'transfer_attention_tg_invmru_28108a2', 'signature': 'transfer_attention_tg_invmru_28108a2(bool,bool,uint256)'
}

f_selector_dict['0x883bdbfd'] = {
    'name': 'observe', 'signature': 'observe(uint32[])'
}

f_selector_dict['0x72c98186'] = {
    'name': 'onSwap', 'signature': 'onSwap((uint8,uint256,uint256[],uint256,uint256,address,bytes))'
}

f_selector_dict['0x36c78516'] = {
    'name': 'transferFrom', 'signature': 'transferFrom(address,address,uint160,address)'
}

f_selector_dict['0x2bfb780c'] = {
    'name': 'swap', 'signature': 'swap((uint8,address,address,address,uint256,uint256,bytes))'
}

f_selector_dict['0xd15e0053'] = {
    'name': 'getReserveNormalizedIncome', 'signature': 'getReserveNormalizedIncome(address)'
}


f_selector_dict['0xf140a35a'] = {
    'name': 'getAmountOut', 'signature': 'getAmountOut(uint256,address)'
}

f_selector_dict['0x13fb72c7'] = {
    'name': 'executeBatchWithCallback', 'signature': 'executeBatchWithCallback((bytes,bytes)[],bytes)'
}

f_selector_dict['0x380dc1c2'] = {
    'name': 'tickSpacingToFee', 'signature': 'tickSpacingToFee(int24)'
}

f_selector_dict['0xcefa7799'] = {
    'name': 'poolImplementation', 'signature': 'poolImplementation()'
}

f_selector_dict['0x3593564c'] = {
    'name': 'execute', 'signature': 'execute(bytes,bytes[],uint256)'
}

f_selector_dict['0x15afd409'] = {
    'name': 'settle', 'signature': 'settle(address,uint256)'
}

f_selector_dict['0xae639329'] = {
    'name': 'sendTo', 'signature': 'sendTo(address,address,uint256)'
}

f_selector_dict['0x1703e5f9'] = {
    'name': 'isAlive', 'signature': 'isAlive(address)'
}
f_selector_dict['0xe5135ec6'] = {
    'name': 'executeBatch', 'signature': 'executeBatch((bytes,bytes)[],bytes)'
}

f_selector_dict['0xb9a09fd5'] = {
    'name': 'gauges', 'signature': 'gauges(address)'
}
f_selector_dict['0xa15ea89f'] = {
    'name': 'getLatestPeriodInfo', 'signature': 'getLatestPeriodInfo(address)'
}
f_selector_dict['0x50d25bcd'] = {
    'name': 'latestAnswer', 'signature': 'latestAnswer()'
}
f_selector_dict['0x679aefce'] = {
    'name': 'getRate', 'signature': 'getRate()'
}

f_selector_dict['0xcc56b2c5'] = {
    'name': 'getFee', 'signature': 'getFee(address,bool)'
}
f_selector_dict['0x5c60e39a'] = {
    'name': 'market', 'signature': 'market(bytes32)'
}
f_selector_dict['0xb187bd26'] = {
    'name': 'isPaused', 'signature': 'isPaused()'
}
f_selector_dict['0xf30dba93'] = {
    'name': 'ticks', 'signature': 'ticks(int24)'
}
f_selector_dict['0x8c00bf6b'] = {
    'name': 'borrowRateView', 'signature': 'borrowRateView((address,address,address,address,uint256),(uint128,uint128,uint128,uint128,uint128,uint128))'
}
f_selector_dict['0xe468baf0'] = {
    'name': 'allWhitelistedTokens', 'signature': 'allWhitelistedTokens(uint256)'
}
f_selector_dict['0xdaf9c210'] = {
    'name': 'whitelistedTokens', 'signature': 'whitelistedTokens(address)'
}
f_selector_dict['0x0a5ea466'] = {
    'name': 'claimTokens', 'signature': 'claimTokens(address,address,address,uint256)'
}
f_selector_dict['0xee63c1e5'] = {
    'name': 'swapUniV3', 'signature': 'swapUniV3()'
}
f_selector_dict['0x9d2c110c'] = {
    'name': 'onSwap', 'signature': 'onSwap((uint8,address,address,uint256,bytes32,uint256,address,address,bytes),uint256,uint256)'
}
f_selector_dict['0x87517c45'] = {
    'name': 'approve', 'signature': 'approve(address,address,uint160,uint48)'
}
f_selector_dict['0xe55186a1'] = {
    'name': 'getUnit', 'signature': 'getUnit()'
}
f_selector_dict['0x0d335884'] = {
    'name': 'executeWithCallback', 'signature': 'executeWithCallback((bytes,bytes),bytes)'
}

f_selector_dict['0x9dc29fac'] = {
    'name': 'burn', 'signature': 'burn(address,uint256)'
}

f_selector_dict['0x61461954'] = {
    'name': 'execute', 'signature': 'execute()'
}

f_selector_dict['0x0c49ccbe'] = {
    'name': 'decreaseLiquidity', 'signature': 'decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))'
}
f_selector_dict['0xf90c6906'] = {
    'name': 'priceFeeds', 'signature': 'priceFeeds(address,address)'
}


f_selector_dict['0x64ee4b80'] = {
    'name': 'gm', 'signature': 'gm(address,uint8)'
}



f_selector_dict['0x9d63848a'] = {
    'name': 'tokens', 'signature': 'tokens()'
}


f_selector_dict['0x927da105'] = {
    'name': 'allowance', 'signature': 'allowance(address,address,address)'
}

