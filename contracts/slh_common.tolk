enum SlhErrors {
    Encoding = 300
    Signature = 301
}

struct SlhReader {
    current: slice
    remaining: int
}

// SAFETY: <=255 byte-aligned builders; EXPLODEVAR supplies their exact count.
fun slhHashMany(parts: array<builder>): uint256
    asm "255 PUSHINT EXPLODEVAR HASHEXT_SHA256"

fun slhHashNode(input: builder): uint128 {
    return (input.endCell().beginParse().bitsHash() >> 128) as uint128;
}

fun slhBase(seed: uint128, layer: int, tree: uint64, kind: int, keypair: int): builder {
    return beginCell()
        .storeUint(seed, 128)
        .storeUint(0, 256)
        .storeUint(0, 128)
        .storeUint(layer, 8)
        .storeUint(tree, 64)
        .storeUint(kind, 8)
        .storeUint(keypair, 32);
}

@noinline
fun SlhReader.take(mutate self): uint128 {
    assert (self.remaining > 0) throw SlhErrors.Encoding;
    if (self.current.remainingBitsCount() == 0) {
        assert (self.current.remainingRefsCount() == 1) throw SlhErrors.Encoding;
        self.current = self.current.loadRef().beginParse();
        val count = self.remaining < 7 ? self.remaining : 7;
        assert (
            self.current.remainingBitsCount() == count * 128 &&
            self.current.remainingRefsCount() == (self.remaining > 7 ? 1 : 0)
        ) throw SlhErrors.Encoding;
    }
    self.remaining -= 1;
    return self.current.loadUint(128);
}

fun slhMessageParts(prefix: builder, message: cell): array<builder> {
    var parts: array<builder> = [prefix];
    var s = message.beginParse();
    var totalBytes = 0;
    repeat (80) {
        assert (
            s.remainingBitsCount() % 8 == 0 && s.remainingRefsCount() <= 1
        ) throw SlhErrors.Encoding;
        totalBytes += s.remainingBitsCount() / 8;
        assert (totalBytes <= 8450) throw SlhErrors.Encoding;
        parts.push(beginCell().storeSlice(s.loadBits(s.remainingBitsCount())));
        if (s.remainingRefsCount() == 0) {
            return parts;
        }
        s = s.loadRef().beginParse();
    }
    throw SlhErrors.Encoding;
}

fun slhEncodePure(message: cell, context: cell): cell {
    var pieces: array<slice> = [];
    var s = context.beginParse();
    var size = 0;
    var done = false;
    repeat (3) {
        assert (
            s.remainingBitsCount() % 8 == 0 && s.remainingRefsCount() <= 1
        ) throw SlhErrors.Encoding;
        size += s.remainingBitsCount() / 8;
        assert (size <= 255) throw SlhErrors.Encoding;
        pieces.push(s.loadBits(s.remainingBitsCount()));
        if (s.remainingRefsCount() == 0) {
            done = true;
            break;
        }
        s = s.loadRef().beginParse();
    }
    assert (done) throw SlhErrors.Encoding;
    var tail = message;
    var i = pieces.size();
    while (i > 0) {
        i -= 1;
        tail = beginCell().storeSlice(pieces.get(i)).storeRef(tail).endCell();
    }
    return beginCell().storeUint(0, 8).storeUint(size, 8).storeRef(tail).endCell();
}

fun slhMessageDigest(randomizer: uint128, seed: uint128, root: uint128, prime: cell): uint240 {
    val prefix = beginCell().storeUint(randomizer, 128).storeUint(seed, 128).storeUint(root, 128);
    val inner = slhHashMany(slhMessageParts(prefix, prime));
    return (beginCell()
        .storeUint(randomizer, 128)
        .storeUint(seed, 128)
        .storeUint(inner, 256)
        .storeUint(0, 32)
        .endCell()
        .beginParse()
        .bitsHash() >>
        16) as uint240;
}
