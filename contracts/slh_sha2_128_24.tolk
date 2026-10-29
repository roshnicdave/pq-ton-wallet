// Draft SHA2-128-24: n=16, h=22, d=1, a=24, k=6, w=4, len=68.
import "slh_common"

fun slhDraftReader(signature: cell): SlhReader {
    val s = signature.beginParse();
    assert (s.remainingBitsCount() == 896 && s.remainingRefsCount() == 1) throw SlhErrors.Encoding;
    return { current: s, remaining: 241 };
}

@noinline
fun slhDraftChain(prefix: builder, value: uint128, start: int): uint128 {
    var result = value;
    var j = start;
    while (j < 3) {
        var input = prefix;
        result = slhHashNode(input.storeUint(j, 32).storeUint(result, 128));
        j += 1;
    }
    return result;
}

@noinline
fun slhDraftFors(mutate reader: SlhReader, seed: uint128, leaf: int, md: uint144): uint128 {
    val base = slhBase(seed, 0, 0, 3, leaf);
    var indices = beginCell().storeUint(md, 144).endCell().beginParse();
    var packed = beginCell();
    var i = 0;
    while (i < 6) {
        var index = (i << 24) + indices.loadUint(24);
        var prefix = base;
        var value = slhHashNode(
            prefix.storeUint(0, 32).storeUint(index, 32).storeUint(reader.take(), 128),
        );
        var level = 0;
        while (level < 24) {
            val sibling = reader.take();
            var parent = base;
            parent.storeUint(level + 1, 32).storeUint(index >> 1, 32);
            if ((index & 1) == 0) {
                parent.storeUint(value, 128).storeUint(sibling, 128);
            } else {
                parent.storeUint(sibling, 128).storeUint(value, 128);
            }
            value = slhHashNode(parent);
            index >>= 1;
            level += 1;
        }
        packed.storeUint(value, 128);
        i += 1;
    }
    return (slhHashMany([slhBase(seed, 0, 0, 4, leaf).storeUint(0, 64), packed]) >> 128) as uint128;
}

@noinline
fun slhDraftXmss(mutate reader: SlhReader, seed: uint128, leaf: int, message: uint128): uint128 {
    var source = beginCell().storeUint(message, 128).endCell().beginParse();
    var checksum = 0;
    repeat (64) {
        checksum += 3 - source.loadUint(2);
    }
    var coefficients = beginCell()
        .storeUint(message, 128)
        .storeUint(checksum, 8)
        .endCell()
        .beginParse();
    val base = slhBase(seed, 0, 0, 0, leaf);
    var parts: array<builder> = [slhBase(seed, 0, 0, 1, leaf).storeUint(0, 64)];
    var packed = beginCell();
    var i = 0;
    while (i < 68) {
        var prefix = base;
        val endpoint = slhDraftChain(
            prefix.storeUint(i, 32),
            reader.take(),
            coefficients.loadUint(2),
        );
        packed.storeUint(endpoint, 128);
        i += 1;
        if (i % 7 == 0) {
            parts.push(packed);
            packed = beginCell();
        }
    }
    parts.push(packed);
    var value = (slhHashMany(parts) >> 128) as uint128;
    val treeBase = slhBase(seed, 0, 0, 2, 0);
    var index = leaf;
    var level = 0;
    while (level < 22) {
        val sibling = reader.take();
        var parent = treeBase;
        parent.storeUint(level + 1, 32).storeUint(index >> 1, 32);
        if ((index & 1) == 0) {
            parent.storeUint(value, 128).storeUint(sibling, 128);
        } else {
            parent.storeUint(sibling, 128).storeUint(value, 128);
        }
        value = slhHashNode(parent);
        index >>= 1;
        level += 1;
    }
    return value;
}

fun slhDraftRecover(seed: uint128, publicRoot: uint128, signature: cell, prime: cell): uint128 {
    var reader = slhDraftReader(signature);
    val digest = slhMessageDigest(reader.take(), seed, publicRoot, prime) >> 72;
    val leaf = digest & ((1 << 22) - 1);
    val forsRoot = slhDraftFors(mutate reader, seed, leaf, (digest >> 24) as uint144);
    val root = slhDraftXmss(mutate reader, seed, leaf, forsRoot);
    assert (reader.remaining == 0 && reader.current.isEmpty()) throw SlhErrors.Encoding;
    return root;
}
