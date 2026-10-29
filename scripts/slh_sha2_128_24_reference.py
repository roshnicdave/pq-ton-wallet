"""SP 800-230 IPD SHA2-128-24 verification, not a finalized standard.

Plain hashlib reference; no signing, secret keys, or prehash interface.
"""
import hashlib


def sha(data):
    return hashlib.sha256(data).digest()


def address(layer, tree, kind, keypair=0, height=0, index=0):
    return (bytes([layer]) + tree.to_bytes(8, "big") + bytes([kind]) +
            keypair.to_bytes(4, "big") + height.to_bytes(4, "big") + index.to_bytes(4, "big"))


def recover(public, signature, message_prime):
    if len(public) != 32 or len(signature) != 3856:
        raise ValueError("wrong public key or signature length")
    seed, root = public[:16], public[16:]
    offset, steps = 0, 0

    def take():
        nonlocal offset
        result = signature[offset:offset + 16]
        offset += 16
        return result

    def thash(adrs, value):
        return sha(seed + bytes(48) + adrs + value)[:16]

    r = take()
    digest = sha(r + seed + sha(r + public + message_prime) + bytes(4))[:21]
    leaf = int.from_bytes(digest[18:], "big") & ((1 << 22) - 1)
    roots = []
    for i in range(6):
        idx = (i << 24) + int.from_bytes(digest[3*i:3*i+3], "big")
        value = thash(address(0, 0, 3, leaf, 0, idx), take())
        for level in range(24):
            sibling = take()
            pair = sibling + value if idx & 1 else value + sibling
            idx >>= 1
            value = thash(address(0, 0, 3, leaf, level + 1, idx), pair)
        roots.append(value)
    value = thash(address(0, 0, 4, leaf), b"".join(roots))
    coeff = [(b >> shift) & 3 for b in value for shift in (6, 4, 2, 0)]
    checksum = sum(3 - x for x in coeff)
    coeff += [(checksum >> shift) & 3 for shift in (6, 4, 2, 0)]
    endpoints = []
    for i, start in enumerate(coeff):
        endpoint = take()
        for j in range(start, 3):
            endpoint = thash(address(0, 0, 0, leaf, i, j), endpoint)
            steps += 1
        endpoints.append(endpoint)
    value = thash(address(0, 0, 1, leaf), b"".join(endpoints))
    idx = leaf
    for level in range(22):
        sibling = take()
        pair = sibling + value if idx & 1 else value + sibling
        idx >>= 1
        value = thash(address(0, 0, 2, 0, level + 1, idx), pair)
    assert offset == len(signature)
    return value, {"leaf": leaf, "wots_chain_hashes": steps,
                   "sha256_invocations": steps + 176}


def verify(public, signature, message, context=b""):
    if len(context) > 255:
        return False
    try:
        root, _ = recover(public, signature, bytes([0, len(context)]) + context + message)
        return root == public[16:]
    except ValueError:
        return False
