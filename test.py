"""Self-test for eip712.py.

Uses the canonical EIP-712 spec example ("Ether Mail") and asserts the
well-known sign-typed-data digest from the spec/README, plus
encodeType / domain-separator / array-encoding checks.
"""
from eip712 import (keccak256, encode_type, type_hash, hash_struct,
                    domain_separator, hash_typed_data)

TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ],
    "Person": [
        {"name": "name", "type": "string"},
        {"name": "wallet", "type": "address"},
    ],
    "Mail": [
        {"name": "from", "type": "Person"},
        {"name": "to", "type": "Person"},
        {"name": "contents", "type": "string"},
    ],
}

DOMAIN = {
    "name": "Ether Mail",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
}

MESSAGE = {
    "from": {
        "name": "Cow",
        "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
    },
    "to": {
        "name": "Bob",
        "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
    },
    "contents": "Hello, Bob!",
}

# Digest quoted in the EIP-712 spec README for the example above.
EXPECTED_DIGEST = ("be609aee343fb3c4b28e1df9e632fca64fcfaede20"
                   "f02e86244efddf30957bd2")

EXPECTED_ENCODE_TYPE = ("Mail(Person from,Person to,string contents)"
                        "Person(string name,address wallet)")

# (domain separator for the example domain is printed by the test)


def main():
    # 1. canonical type string: primary first, deps alphabetical
    enc = encode_type("Mail", TYPES)
    assert enc == EXPECTED_ENCODE_TYPE, f"encodeType mismatch:\n{enc}"

    # 2. keccak sanity (empty-input Keccak-256, not NIST SHA3-256)
    assert keccak256(b"").hex() == (
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")

    # 3. domain separator is deterministic and well-formed
    ds = domain_separator(DOMAIN)
    print("domain separator:", ds.hex())
    assert ds == domain_separator(DOMAIN) and len(ds) == 32

    # 4. full EIP-712 digest matches the spec example value
    digest = hash_typed_data(TYPES, "Mail", DOMAIN, MESSAGE)
    print("typed-data digest:", digest.hex())
    assert digest.hex() == EXPECTED_DIGEST, "typed-data digest mismatch"

    # 5. nested struct / array encodings are deterministic
    h1 = hash_struct("Mail", TYPES, MESSAGE)
    assert h1 == hash_struct("Mail", TYPES, MESSAGE)

    array_types = {"Vote": [{"name": "choices", "type": "uint8[]"}]}
    a1 = hash_struct("Vote", array_types, {"choices": [1, 2, 3]})
    a2 = hash_struct("Vote", array_types, {"choices": [1, 2, 3]})
    a3 = hash_struct("Vote", array_types, {"choices": [1, 2, 4]})
    assert a1 == a2 and a1 != a3, "array encoding broken"

    # 6. type_hash of Person is used inside Mail hashing
    assert type_hash("Person", TYPES) == keccak256(
        b"Person(string name,address wallet)")

    print("all eip712 tests passed")


if __name__ == "__main__":
    main()
