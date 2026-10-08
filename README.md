# eip712-typed-data

EIP-712 structured-data hashing in **pure Python** — zero dependencies.

Computes the exact digest wallets sign for typed data (used by MetaMask's
`signTypedData`, permit signatures, DAO votes, etc.):

```
digest = keccak256(0x19 || 0x01 || domainSeparator || hashStruct(message))
```

Implemented from scratch:

- `encode_type` — canonical type string, referenced structs sorted alphabetically
- `hash_struct` — `keccak256(typeHash || encodeData)`
- `domain_separator` — `hashStruct` of `EIP712Domain` (only defined fields encoded)
- `hash_typed_data` — the final `"\x19\x01"`-prefixed digest
- self-contained **Keccak-256** (Keccak-f[1600], 24 rounds) — *not* NIST SHA3

Supports `address`, `uintN`/`intN`, `bool`, `bytesN`, `bytes`, `string`,
arrays (`T[]`, `T[k]`), and nested custom struct types.

## Quick start

```python
from eip712 import hash_typed_data

digest = hash_typed_data(TYPES, "Mail", DOMAIN, MESSAGE)
print(digest.hex())   # 0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2
```

## Verify

```bash
python3 test.py
```

The self-test asserts the well-known EIP-712 spec example
("Ether Mail"): `encodeType` formatting, Keccak-256 of empty input,
the canonical `0xbe60…57bd2` typed-data digest, and deterministic
nested-struct / array encodings.

## Reference

[EIP-712](https://eips.ethereum.org/EIPS/eip-712) — Ethereum typed structured
data hashing and signing.
