import "@stdlib/gas-payments"

enum SlhWalletErrors {
    Encoding = 400
    Network = 401
    Wallet = 402
    Sequence = 403
    Epoch = 404
    Expired = 405
    Funding = 406
    Signature = 407
}

struct SlhWalletState {
    seed: uint128
    root: uint128
    sequence: uint64
    epoch: uint32
}

struct SlhPayment {
    network: int32
    wallet: address
    recipient: address
    amount: uint64
    expires: uint32
    sequence: uint64
    epoch: uint32
    message: cell
}

fun parseSlhPayment(payload: cell): SlhPayment {
    var s = payload.beginParse();
    assert (
        s.remainingBitsCount() == 790 && s.remainingRefsCount() == 1
    ) throw SlhWalletErrors.Encoding;
    assert (s.loadUint(32) == 0x50515331) throw SlhWalletErrors.Encoding;
    val p: SlhPayment = {
        network: s.loadInt(32),
        wallet: s.loadAddress(),
        recipient: s.loadAddress(),
        amount: s.loadUint(64),
        expires: s.loadUint(32),
        sequence: s.loadUint(64),
        epoch: s.loadUint(32),
        message: s.loadRef(),
    };
    s.assertEnd();
    val body = p.message.beginParse();
    assert (
        body.remainingRefsCount() == 0 && body.remainingBitsCount() >= 32 &&
        body.remainingBitsCount() <= 984 &&
        body.remainingBitsCount() % 8 == 0 &&
        body.preloadUint(32) == 0
    ) throw SlhWalletErrors.Encoding;
    return p;
}

// Fixed-width header followed by the complete comment bytes.
fun SlhPayment.canonicalMessage(self): cell {
    val (wc, wh) = self.wallet.getWorkchainAndHash();
    val (rc, rh) = self.recipient.getWorkchainAndHash();
    return beginCell()
        .storeUint(0x50515331, 32)
        .storeInt(self.network, 32)
        .storeInt(wc, 8)
        .storeUint(wh, 256)
        .storeInt(rc, 8)
        .storeUint(rh, 256)
        .storeUint(self.amount, 64)
        .storeUint(self.expires, 32)
        .storeUint(self.sequence, 64)
        .storeUint(self.epoch, 32)
        .storeUint(self.message.beginParse().remainingBitsCount() / 8, 16)
        .storeRef(self.message)
        .endCell();
}

// SAFETY: reads trusted execution context with no stack inputs.
fun slhWalletGlobalId(): int
    asm "GLOBALID"

// Native gas cap plus two conservatively bounded forwarding fees.
fun slhSubmissionMinimum(): coins {
    return calculateGasFee(0, 1000000) + 2 * calculateForwardFee(0, 2048, 4);
}
