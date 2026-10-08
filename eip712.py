"""
EIP-712 typed-data hashing in pure Python.

Implements the EIP-712 structured-data hashing standard
(https://eips.ethereum.org/EIPS/eip-712) with zero dependencies:

  encode_type()   -> canonical type string, referenced types sorted
                    alphabetically, dependencies appended
  type_hash()     -> keccak256 of the encoded type string
  encode_data()   -> abi-style encoding of a typed value
  hash_struct()   -> keccak256(type_hash || encode_data)
  domain_separator() -> hash_struct of the EIP712Domain value
  hash_typed_data()  -> keccak256(b"\\x19\\x01" || domain || message)

Supported Solidity types: address, uintN, intN, bool, bytesN, bytes,
string, arrays (T[], T[k]) of any supported type, and user-defined
struct types (encoded as hash_struct).

Keccak-256 is implemented from scratch (Keccak-f[1600], 24 rounds);
no hashlib.sha3 (which is NIST SHA3, a different padding).
"""

# ---------------------------------------------------------------------------
# Keccak-256 (self-contained)
# ---------------------------------------------------------------------------

_KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]

_KECCAK_ROT_OFFSETS = [
     0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
     3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14,
]

_MASK64 = (1 << 64) - 1


def _rotl64(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & _MASK64


def _keccak_f1600(state):
    for rc in _KECCAK_ROUND_CONSTANTS:
        # theta
        c = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= d[x]
        # rho + pi
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl64(
                    state[x + 5 * y], _KECCAK_ROT_OFFSETS[x + 5 * y])
        # chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = (b[x + 5 * y]
                                    ^ ((~b[(x + 1) % 5 + 5 * y] & _MASK64)
                                       & b[(x + 2) % 5 + 5 * y])) & _MASK64
        # iota
        state[0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256 (Ethereum's hash, NOT NIST SHA3-256)."""
    rate = 136  # bytes for 256-bit output
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)

    state = [0] * 25
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            word = int.from_bytes(block[8 * i:8 * i + 8], "little")
            state[i] ^= word
        _keccak_f1600(state)

    out = bytearray()
    for i in range(256 // 64):
        out += state[i].to_bytes(8, "little")
    return bytes(out)


# ---------------------------------------------------------------------------
# EIP-712 encoding
# ---------------------------------------------------------------------------

def _find_dependencies(primary_type, types, found=None):
    if found is None:
        found = set()
    if primary_type in found:
        return found
    fields = types.get(primary_type)
    if fields is None:
        return found
    found.add(primary_type)
    for field in fields:
        t = field["type"]
        # strip array suffixes, e.g. "Person[]" -> "Person"
        while t.endswith("]"):
            t = t[:t.rindex("[")]
        if t in types and t != primary_type:
            _find_dependencies(t, types, found)
    return found


def encode_type(primary_type, types) -> str:
    """encodeType: 'Mail(Person from,...)Person(string name,address wallet)'.

    The primary type comes first; referenced struct types are appended
    sorted alphabetically, each formatted 'TypeName(type name,...)'.
    """
    deps = _find_dependencies(primary_type, types) - {primary_type}
    parts = [_encode_single_type(primary_type, types)]
    parts.extend(_encode_single_type(t, types) for t in sorted(deps))
    return "".join(parts)


def _encode_single_type(type_name, types):
    fields = ",".join(f'{f["type"]} {f["name"]}' for f in types[type_name])
    return f"{type_name}({fields})"


def type_hash(primary_type, types) -> bytes:
    return keccak256(encode_type(primary_type, types).encode())


def _encode_address(value: str) -> bytes:
    if not (isinstance(value, str) and value.startswith(("0x", "0X"))):
        raise ValueError(f"bad address: {value!r}")
    raw = bytes.fromhex(value[2:])
    if len(raw) != 20:
        raise ValueError(f"bad address length: {value!r}")
    return raw.rjust(32, b"\x00")


def _encode_uint(value: int, bits: int) -> bytes:
    if not 0 <= value < (1 << bits):
        raise ValueError(f"uint{bits} out of range: {value}")
    return value.to_bytes(32, "big")


def _encode_int(value: int, bits: int) -> bytes:
    if not -(1 << (bits - 1)) <= value < (1 << (bits - 1)):
        raise ValueError(f"int{bits} out of range: {value}")
    return value.to_bytes(32, "big", signed=True)


def _encode_atomic(typ: str, value, types) -> bytes:
    if typ == "address":
        return _encode_address(value)
    if typ == "bool":
        return _encode_uint(int(bool(value)), 8)
    if typ.startswith("uint"):
        return _encode_uint(int(value), int(typ[4:] or 256))
    if typ.startswith("int"):
        return _encode_int(int(value), int(typ[3:] or 256))
    if typ.startswith("bytes") and typ != "bytes":
        n = int(typ[5:])
        if not 1 <= n <= 32:
            raise ValueError(f"bad fixed bytes: {typ}")
        raw = bytes(value) if not isinstance(value, bytes) else value
        if len(raw) != n:
            raise ValueError(f"bytes{n} wrong length: {len(raw)}")
        return raw.ljust(32, b"\x00")
    if typ in ("bytes", "string"):
        raw = value if isinstance(value, bytes) else str(value).encode()
        return keccak256(raw)                      # atomic keccak of dynamic
    raise TypeError(f"unknown atomic type: {typ}")


def _encode_field_value(typ: str, value, types) -> bytes:
    # array?
    if typ.endswith("]"):
        base, _, size_str = typ[:-1].partition("[")
        items = list(value)
        if size_str and len(items) != int(size_str):
            raise ValueError(f"fixed array {typ} wrong length")
        return keccak256(b"".join(_encode_field_value(base, v, types)
                                  for v in items))
    # custom struct?
    if typ in types:
        return hash_struct(typ, types, value)
    return _encode_atomic(typ, value, types)


def encode_data(primary_type, types, data: dict) -> bytes:
    """typeHash || encoded fields (32 bytes per field)."""
    out = [type_hash(primary_type, types)]
    for field in types[primary_type]:
        name, typ = field["name"], field["type"]
        if name not in data:
            raise KeyError(f"missing field '{name}' for type '{primary_type}'")
        out.append(_encode_field_value(typ, data[name], types))
    return b"".join(out)


def hash_struct(primary_type, types, data: dict) -> bytes:
    return keccak256(encode_data(primary_type, types, data))


_DOMAIN_FIELD_ORDER = ["name", "version", "chainId", "verifyingContract", "salt"]


def domain_separator(domain: dict) -> bytes:
    """EIP712Domain: only defined fields are encoded, in canonical order."""
    domain_types = {
        "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"},
            {"name": "salt", "type": "bytes32"},
        ]
    }
    present = [f for f in domain_types["EIP712Domain"] if f["name"] in domain]
    types = {"EIP712Domain": present}
    return hash_struct("EIP712Domain", types, domain)


def hash_typed_data(types: dict, primary_type: str, domain: dict,
                    message: dict) -> bytes:
    """keccak256(b"\\x19\\x01" || domainSeparator || hashStruct(message))."""
    return keccak256(b"\x19\x01" + domain_separator(domain)
                     + hash_struct(primary_type, types, message))
