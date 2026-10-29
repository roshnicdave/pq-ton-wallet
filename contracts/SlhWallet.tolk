import "slh_common"
import "slh_sha2_128_24"
import "slh_wallet"

contract SlhWallet {
    version: "0.1.0"
    storage: SlhWalletState
}

fun onInternalMessage(in: InMessage) {
    if (in.body.isEmpty()) {
        return;
    }
    assert (in.valueCoins >= slhSubmissionMinimum()) throw SlhWalletErrors.Funding;
    var s = in.body;
    assert (
        s.remainingBitsCount() == 32 && s.remainingRefsCount() == 2 && s.loadUint(32) == 0x534c4857
    ) throw SlhWalletErrors.Encoding;
    val p = parseSlhPayment(s.loadRef());
    val signature = s.loadRef();
    val state = SlhWalletState.fromCell(contract.getData());
    assert (p.network == -3 && p.network == slhWalletGlobalId()) throw SlhWalletErrors.Network;
    assert (p.wallet == contract.getAddress()) throw SlhWalletErrors.Wallet;
    val (wc, _wh) = p.wallet.getWorkchainAndHash();
    val (rc, _rh) = p.recipient.getWorkchainAndHash();
    val (sc, _sh) = in.senderAddress.getWorkchainAndHash();
    assert (wc == 0 && rc == 0 && sc == 0) throw SlhWalletErrors.Network;
    assert (
        p.sequence == state.sequence && p.sequence < 0xffffffffffffffff
    ) throw SlhWalletErrors.Sequence;
    assert (p.epoch == state.epoch) throw SlhWalletErrors.Epoch;
    assert (blockchain.now() <= p.expires) throw SlhWalletErrors.Expired;
    assert (p.amount > 0) throw SlhWalletErrors.Encoding;
    // Post-storage principal excludes the remaining credited submission value.
    val principal = contract.getOriginalBalance() - in.valueCoins;
    assert (principal >= p.amount) throw SlhWalletErrors.Funding;
    val prime = slhEncodePure(p.canonicalMessage(), beginCell().endCell());
    assert (
        slhDraftRecover(state.seed, state.root, signature, prime) == state.root
    ) throw SlhWalletErrors.Signature;
    contract.setData(
        SlhWalletState {
            seed: state.seed,
            root: state.root,
            sequence: state.sequence + 1,
            epoch: state.epoch,
        }.toCell(),
    );
    // Reserve first; non-ignored action failures roll back state and messages.
    reserveGramsOnBalance(principal - p.amount, RESERVE_MODE_EXACT_AMOUNT);
    val payment = createMessage({
        bounce: BounceMode.NoBounce,
        value: p.amount as coins,
        dest: p.recipient,
        body: p.message.beginParse(),
    });
    payment.send(SEND_MODE_PAY_FEES_SEPARATELY);
    val refund = createMessage({ bounce: BounceMode.NoBounce, value: 0, dest: in.senderAddress });
    // SAFETY: RAWRESERVE protects p-a before payment and refund.
    refund.send(SEND_MODE_CARRY_ALL_BALANCE);
}

get fun sequence(): int {
    return SlhWalletState.fromCell(contract.getData()).sequence;
}
