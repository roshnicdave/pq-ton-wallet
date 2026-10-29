import "@stdlib/gas-payments"
import "@contracts/slh_common"
// Verification feasibility only. No payment authority or owner funds.
import "@contracts/slh_sha2_128_24"

struct SlhDraftProbeState {
    seed: uint128
    root: uint128
    refund: address
    accepted: uint8
}

contract SlhDraftProbe {
    version: "0.0.1"
    storage: SlhDraftProbeState
}

fun onInternalMessage(in: InMessage) {
    var state = SlhDraftProbeState.fromCell(contract.getData());
    assert (state.accepted == 0) throw SlhErrors.Encoding;
    var body = in.body;
    assert (body.loadUint(32) == 0x534c4431) throw SlhErrors.Encoding;
    val message = body.loadRef();
    val signature = body.loadRef();
    body.assertEnd();
    // Fixed empty external context; this is not an internal/prehash API.
    val prime = slhEncodePure(message, beginCell().endCell());
    assert (
        slhDraftRecover(state.seed, state.root, signature, prime) == state.root
    ) throw SlhErrors.Signature;
    state.accepted = 1;
    contract.setData(state.toCell());
    reserveGramsOnBalance(grams("0.005"), RESERVE_MODE_EXACT_AMOUNT);
    val refund = createMessage({ bounce: BounceMode.NoBounce, value: 0, dest: state.refund });
    // SAFETY: disposable job funding only, fixed refund address, exact reserve.
    refund.send(SEND_MODE_CARRY_ALL_BALANCE);
}

get fun accepted(): int {
    return SlhDraftProbeState.fromCell(contract.getData()).accepted;
}
