import "@acton/boc"
import "@acton/fmt"
import "@acton/fs"
import "@acton/io"
import "@acton/emulation/config"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/tlb/maybe"
import "@acton/types/big_array"
import "@acton/types/transaction"
import "@contracts/slh_common"
import "@contracts/slh_wallet"
import "@wrappers/SlhWallet.gen"
import "architecture_environment"
import "relay_trace"

fun slhFixtureRequest(sequence: int): cell {
    return boc.decode(fs.readBytes(format("tests/fixtures/slh-wallet/seq{}.boc", sequence))!)!;
}

fun slhFixturePayment(): SlhPayment {
    var s = slhFixtureRequest(0).beginParse();
    s.loadUint(32);
    return parseSlhPayment(s.loadRef());
}

fun freshSlh(name: string): (Treasury, SlhWallet, address) {
    architectureEnvironment();
    val payer = testing.treasury(name);
    val recipient = deployTestV5(payer.address, "recipient");
    val state = SlhWalletState.fromCell(
        boc.decode(fs.readBytes("tests/fixtures/slh-wallet/storage.boc")!)!,
    );
    val wallet = SlhWallet.fromStorage(state);
    testing.setShardAccount(wallet.address, null);
    expect(
        wallet.deploy(payer.address, { value: grams("0.3") }),
    ).toHaveSuccessfulDeploy({ to: wallet.address });
    return (payer, wallet, recipient);
}

fun slhChangedRequest(p: SlhPayment, signature: cell): cell {
    val payload = beginCell()
        .storeUint(0x50515331, 32)
        .storeSlice(p.toCell().beginParse())
        .endCell();
    return beginCell().storeUint(0x534c4857, 32).storeRef(payload).storeRef(signature).endCell();
}

get fun `test SLH complete wallet withdrawal trace and exact principal conservation`() {
    val (payer, wallet, recipient) = freshSlh("slh-full-trace");
    val relayer = deployTestV5(payer.address, "relayer");
    val walletBefore = testing.getAccountBalance(wallet.address);
    val before = walletBefore + testing.getAccountBalance(relayer) +
        testing.getAccountBalance(recipient);
    val trace = relayThroughV5(relayer, wallet.address, grams("0.08"), slhFixtureRequest(0));
    expect(trace).toHaveSuccessfulTx({ from: relayer, to: wallet.address });
    expect(trace).toHaveSuccessfulTx({
        from: wallet.address,
        to: recipient,
        value: grams("0.01"),
        body: slhFixturePayment().message,
    });
    expect(trace).toHaveSuccessfulTx({ from: wallet.address, to: relayer });
    expect(wallet.sequence()).toEqual(1);
    expect(testing.getAccountBalance(wallet.address)).toEqual(walletBefore - grams("0.01"));
    val fee = traceFees(trace, "SLH_WALLET");
    expect(
        before - testing.getAccountBalance(wallet.address) - testing.getAccountBalance(relayer) -
            testing.getAccountBalance(recipient),
    ).toEqual(fee);
    println(
        "SLH_WITHDRAWAL fee_nano={} transactions={} minimum_funding={}",
        fee,
        trace.size(),
        slhSubmissionMinimum(),
    );
}

get fun `test SLH matched standard V5 payment under identical configuration`() {
    architectureEnvironment();
    val payer = testing.treasury("slh-standard-baseline");
    val relayer = deployTestV5(payer.address, "relayer");
    val recipient = deployTestV5(payer.address, "recipient");
    val before = testing.getAccountBalance(relayer) + testing.getAccountBalance(recipient);
    val trace = relayThroughV5(
        relayer,
        recipient,
        grams("0.01"),
        slhFixturePayment().message,
    );
    expect(trace).toHaveSuccessfulTx({ from: relayer, to: recipient, value: grams("0.01") });
    val fee = traceFees(trace, "SLH_V5_BASELINE");
    expect(
        before - testing.getAccountBalance(relayer) - testing.getAccountBalance(recipient),
    ).toEqual(fee);
    println("SLH_BASELINE fee_nano={} transactions={}", fee, trace.size());
}

get fun `test SLH genuine reordered authorizations competing relayers and ambiguous retry`() {
    val (payer, wallet, recipient) = freshSlh("slh-order");
    val competitor = testing.treasury("slh-other-relayer");
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(1), { value: grams("0.08") }),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Sequence });
    expect(wallet.sequence()).toEqual(0);
    expect(
        wallet.sendAny(competitor.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient });
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Sequence });
    expect(wallet.sequence()).toEqual(1);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(1), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient });
    expect(wallet.sequence()).toEqual(2);
}

get fun `test SLH exact raw message binding and forged verifier claims cannot authorize`() {
    val (payer, wallet, _recipient) = freshSlh("slh-binding");
    var s = slhFixtureRequest(0).beginParse();
    s.loadUint(32);
    val payload = s.loadRef();
    val signature = s.loadRef();
    val p = parseSlhPayment(payload);
    val expected = boc
        .decode(fs.readBytes("tests/fixtures/slh-wallet/canonical-sha256.boc")!)!
        .beginParse()
        .loadUint(256);
    expect(slhHashMany(slhMessageParts(beginCell(), p.canonicalMessage()))).toEqual(expected);
    var changed = p;
    changed.amount += 1;
    expect(
        wallet.sendAny(
            payer.address,
            slhChangedRequest(changed, signature),
            { value: grams("0.08") },
        ),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Signature });
    changed = p;
    changed.message = beginCell().storeUint(0, 32).storeUint(1, 8).endCell();
    expect(
        wallet.sendAny(
            payer.address,
            slhChangedRequest(changed, signature),
            { value: grams("0.08") },
        ),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Signature });
    var sig = signature.beginParse();
    val r = sig.loadUint(128);
    val secret = sig.loadUint(128);
    val path = sig.loadUint(128);
    val forged = beginCell()
        .storeUint(r, 128)
        .storeUint(secret, 128)
        .storeUint(path ^ 1, 128)
        .storeSlice(sig)
        .endCell();
    expect(
        wallet.sendAny(payer.address, slhChangedRequest(p, forged), { value: grams("0.08") }),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Signature });
    val claim = beginCell()
        .storeUint(0x534c4431, 32)
        .storeRef(payload)
        .storeRef(signature)
        .endCell();
    expect(
        wallet.sendAny(payer.address, claim, { value: grams("0.08") }),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Encoding });
    var wrongFields = [0, 1, 2, 3];
    repeat (4) {
        changed = p;
        val which = wrongFields.pop();
        if (which == 0) {
            changed.network = -239;
        }
        if (which == 1) {
            changed.wallet = payer.address;
        }
        if (which == 2) {
            changed.epoch = 1;
        }
        if (which == 3) {
            changed.recipient = payer.address;
        }
        expect(
            wallet.sendAny(
                payer.address,
                slhChangedRequest(changed, signature),
                { value: grams("0.08") },
            ),
        ).toHaveTx({ to: wallet.address, success: false });
    }
    expect(wallet.sequence()).toEqual(0);
}

get fun `test SLH inadequate gas and changed fee schedule preserve principal and permit retry`() {
    val (payer, wallet, recipient) = freshSlh("slh-funding");
    var values: array<coins> = [0, grams("0.0001"), grams("0.01")];
    repeat (3) {
        val before = testing.getAccountBalance(wallet.address);
        val trace = wallet.sendAny(payer.address, slhFixtureRequest(0), { value: values.pop() });
        expect(trace).toHaveTx({ to: wallet.address, success: false });
        expect(testing.getAccountBalance(wallet.address)).toBeGreaterOrEqual(before);
        expect(wallet.sequence()).toEqual(0);
    }
    val original = testing.getConfig();
    var expensive = original;
    var prices = expensive.getMsgForwardPrices(BASECHAIN);
    prices.lumpPrice = 1000000000;
    expensive.setMsgForwardPrices(prices, BASECHAIN);
    expect(testing.setConfig(expensive)).toEqual(true);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Funding });
    expect(wallet.sequence()).toEqual(0);
    expect(testing.setConfig(original)).toEqual(true);
    // Force a genuine action-phase failure after valid verification. The raw
    // config keeps its archived schema; only max_msg_cells is set to zero.
    var limited = original;
    var limits = original.get(43).loadValue().beginParse();
    val tag = limits.loadUint(8);
    val maxBits = limits.loadUint(32);
    limits.loadUint(32);
    limited.setParamRaw(
        43,
        beginCell()
            .storeUint(tag, 8)
            .storeUint(maxBits, 32)
            .storeUint(0, 32)
            .storeSlice(limits)
            .endCell(),
    );
    expect(testing.setConfig(limited)).toEqual(true);
    val principal = testing.getAccountBalance(wallet.address);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveTx({ to: wallet.address, success: false, actionExitCode: 40 });
    expect(wallet.sequence()).toEqual(0);
    expect(testing.getAccountBalance(wallet.address)).toBeGreaterOrEqual(principal);
    expect(testing.setConfig(original)).toEqual(true);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient });
    expect(wallet.sequence()).toEqual(1);
}

get fun `test SLH expiry boundary and expired authorization cannot spend`() {
    val (payer, wallet, recipient) = freshSlh("slh-expiry-boundary");
    testing.setNow(1793044500);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient });
    val (otherPayer, otherWallet, _otherRecipient) = freshSlh("slh-expired");
    testing.setNow(1793044501);
    expect(
        otherWallet.sendAny(otherPayer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveFailedTx({ to: otherWallet.address, exitCode: SlhWalletErrors.Expired });
    expect(otherWallet.sequence()).toEqual(0);
}

// These resets are injected models. The following test separately reaches
// freeze/deletion through TON's real storage phase under changed rent prices.
get fun `test SLH redeployment resets sequence but expiry still binds`() {
    val (payer, wallet, recipient) = freshSlh("slh-reset-model");
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient });
    expect(wallet.sequence()).toEqual(1);
    testing.setShardAccount(wallet.address, null);
    expect(
        wallet.deploy(payer.address, { value: grams("0.3") }),
    ).toHaveSuccessfulDeploy({ to: wallet.address });
    expect(wallet.sequence()).toEqual(0);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient });
    println("LIFECYCLE injected_reset=1 identical_authorization_paid_twice=1");
    testing.setShardAccount(wallet.address, null);
    expect(
        wallet.deploy(payer.address, { value: grams("0.3") }),
    ).toHaveSuccessfulDeploy({ to: wallet.address });
    testing.setNow(1793044501);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Expired });
    expect(wallet.sequence()).toEqual(0);
}

get fun `test SLH actual storage deletion under changed prices permits unexpired replay`() {
    val (payer, wallet, recipient) = freshSlh("slh-rent-lifecycle");
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient });
    val original = testing.getConfig();
    val account = testing.getAccountState(wallet.address)!;
    // Fixed archived prices cannot delete this state before the uint32 expiry
    // horizon. This does NOT assume that governance will preserve those prices.
    val currentPrices = original.getStoragePrices().get(1777471189).loadValue();
    expect(currentPrices.bitPrice).toEqual(0);
    expect(currentPrices.cellPrice).toEqual(135);
    val horizonRent = ((0xffffffff - 1793044400) *
        (account.storageStat.used.bits * currentPrices.bitPrice +
            account.storageStat.used.cells * currentPrices.cellPrice) +
        65535) /
        65536;
    expect(horizonRent + grams("0.1") + 2).toBeLess(grams("1"));
    println(
        "LIFECYCLE cells={} bits={} rent_to_uint32_horizon_nano={}",
        account.storageStat.used.cells,
        account.storageStat.used.bits,
        horizonRent,
    );
    // Controlled governance counterexample: raise rent to 1 TON/cell/second.
    // No account data or status is injected for either storage transition.
    var accelerated = original;
    var prices: StoragePricesDict = [];
    prices.set(
        0,
        StoragePrices {
            initialUnixTime: 0,
            bitPrice: 0,
            cellPrice: 65536000000000,
            masterchainBitPrice: 0,
            masterchainCellPrice: 65536000000000,
        },
    );
    accelerated.setStoragePrices(prices);
    expect(testing.setConfig(accelerated)).toEqual(true);
    testing.setNow(1793044401);
    val _first = wallet.sendAny(payer.address, beginCell().endCell(), { value: 0 });
    val frozen = testing.getAccountState(wallet.address)!;
    expect(frozen.storage.state is TlbAccountStateFrozen).toEqual(true);
    val frozenState = frozen.storage.state;
    if (frozenState is TlbAccountStateFrozen) {
        val (_wc, initialHash) = wallet.address.getWorkchainAndHash();
        expect(frozenState.stateHash == initialHash).toEqual(false);
    }
    val _second = wallet.sendAny(payer.address, beginCell().endCell(), { value: 0 });
    val deleted = testing.getAccountState(wallet.address);
    expect(deleted == null).toEqual(true);
    println("LIFECYCLE protocol_freeze=1 protocol_delete=1 before_expiry=1");
    expect(testing.setConfig(original)).toEqual(true);
    expect(
        wallet.deploy(payer.address, { value: grams("0.3") }),
    ).toHaveSuccessfulDeploy({ to: wallet.address });
    expect(wallet.sequence()).toEqual(0);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient, value: grams("0.01") });
    expect(wallet.sequence()).toEqual(1);
    println("LIFECYCLE identical_signature_replayed_after_protocol_deletion=1");
}

fun slhMalformedSignatureTail(signature: cell): cell {
    var s = signature.beginParse();
    val bits = s.loadBits(s.remainingBitsCount());
    if (s.remainingRefsCount() == 0) {
        return beginCell().storeSlice(bits).storeUint(1, 1).endCell();
    }
    return beginCell().storeSlice(bits).storeRef(slhMalformedSignatureTail(s.loadRef())).endCell();
}

get fun `test SLH late malformed signature and malformed payment cannot advance state`() {
    val (payer, wallet, _recipient) = freshSlh("slh-late-invalid");
    var s = slhFixtureRequest(0).beginParse();
    s.loadUint(32);
    val payload = s.loadRef();
    val signature = s.loadRef();
    val principal = testing.getAccountBalance(wallet.address);
    val late = wallet.sendAny(
        payer.address,
        slhChangedRequest(parseSlhPayment(payload), slhMalformedSignatureTail(signature)),
        { value: grams("0.08") },
    );
    expect(late).toHaveFailedTx({ to: wallet.address, exitCode: SlhErrors.Encoding });
    val malformed = beginCell()
        .storeUint(0x534c4857, 32)
        .storeRef(beginCell().storeSlice(payload.beginParse()).storeUint(0, 1).endCell())
        .storeRef(signature)
        .endCell();
    expect(
        wallet.sendAny(payer.address, malformed, { value: grams("0.08") }),
    ).toHaveFailedTx({ to: wallet.address, exitCode: SlhWalletErrors.Encoding });
    expect(wallet.sequence()).toEqual(0);
    expect(testing.getAccountBalance(wallet.address)).toBeGreaterOrEqual(principal);
    println("LATE_INVALID gas={} principal_preserved=1", late.at(0).gasUsed);
}

get fun `test SLH charged action failure and late rollback preserve principal`() {
    val (payer, wallet, recipient) = freshSlh("slh-staged-rollback");
    val original = testing.getConfig();
    val finePerCell = (original.getMsgForwardPrices(BASECHAIN).cellPrice >> 16) / 4;
    // Fail a message-size check after the payment body cell was inspected.
    // Unlike max_msg_cells=0, this exercises a positive action fine.
    var zeroBits = original;
    var limits = original.get(43).loadValue().beginParse();
    val tag = limits.loadUint(8);
    limits.loadUint(32);
    zeroBits.setParamRaw(
        43,
        beginCell().storeUint(tag, 8).storeUint(0, 32).storeSlice(limits).endCell(),
    );
    expect(testing.setConfig(zeroBits)).toEqual(true);
    val beforeFine = testing.getAccountBalance(wallet.address);
    val taxed = wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") });
    expect(taxed).toHaveTx({ to: wallet.address, success: false, actionExitCode: 40 });
    val paidFine = taxed.at(0).tx.load().getActionFee()!;
    expect(paidFine).toEqual(finePerCell);
    expect(paidFine).toBeGreater(0);
    expect(testing.getAccountBalance(wallet.address)).toBeGreaterOrEqual(beforeFine);
    expect(testing.getAccountBalance(wallet.address)).toEqual(
        beforeFine + grams("0.08") - taxed.at(0).tx.load().totalFees.grams,
    );
    expect(wallet.sequence()).toEqual(0);
    println("ACTION_FINE exit=40 fine_nano={} old_principal_preserved=1", paidFine);
    var limited = original;
    var raw = original.get(43).loadValue().beginParse();
    // Config 43 v2: skip tag and message/library/depth limits; replace only
    // max_acc_state_cells. The account is already active; no StateInit is sent.
    expect(raw.preloadUint(8)).toEqual(2);
    val prefix = raw.loadBits(168);
    raw.loadUint(32);
    limited.setParamRaw(
        43,
        beginCell().storeSlice(prefix).storeUint(1, 32).storeSlice(raw).endCell(),
    );
    expect(testing.setConfig(limited)).toEqual(true);
    val principal = testing.getAccountBalance(wallet.address);
    val recipientBefore = testing.getAccountBalance(recipient);
    val failed = wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") });
    expect(failed).toHaveTx({ to: wallet.address, success: false, actionExitCode: 50 });
    val tx = failed.at(0).tx.load();
    // The embedded native revision does not fine already-staged messages on
    // this late failure. The newer reference processor does; see the proof.
    expect(tx.getActionFee()).toEqual(null);
    val description = tx.description.load();
    if (description is TlbTransOrd) {
        expect(description.action.unwrap().load().msgsCreated).toEqual(2);
    }
    expect(testing.getAccountBalance(wallet.address)).toEqual(
        principal + grams("0.08") - tx.totalFees.grams,
    );
    expect(wallet.sequence()).toEqual(0);
    expect(testing.getAccountBalance(recipient)).toEqual(recipientBefore);
    expect(testing.getAccountBalance(wallet.address)).toBeGreaterOrEqual(principal);
    println(
        "LATE_ACTION_FAILURE exit=50 fine_nano=0 old_principal_preserved=1 staged_messages=2 committed_messages=0",
    );
    expect(testing.setConfig(original)).toEqual(true);
    expect(
        wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") }),
    ).toHaveSuccessfulTx({ from: wallet.address, to: recipient, value: grams("0.01") });
    expect(wallet.sequence()).toEqual(1);
}
