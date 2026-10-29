import "@acton/boc"
import "@acton/build"
import "@acton/fmt"
import "@acton/fs"
import "@acton/io"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/bench"
import "@acton/testing/expect"
import "@acton/types/big_array"
import "@contracts/slh_common"
import "@contracts/slh_sha2_128_24"
import "@tests/architecture_environment"
import "@tests/relay_trace"

fun draftFixture(name: string): (uint128, uint128, cell, cell) {
    var s = boc
        .decode(fs.readBytes(format("tests/fixtures/slh-draft/{}.boc", name))!)!
        .beginParse();
    assert (s.loadUint(32) == 0x534c4431) throw 999;
    return (s.loadUint(128), s.loadUint(128), s.loadRef(), s.loadRef());
}

get fun `test draft real signatures match committed root and native one transaction gas limit`() {
    var names = ["gpu", "cpu"];
    repeat (2) {
        val name = names.pop();
        val (seed, root, message, signature) = draftFixture(name);
        val prime = slhEncodePure(message, beginCell().endCell());
        val measured = bench.measure(
            "draft complete verification",
            fun() {
                return slhDraftRecover(seed, root, signature, prime);
            },
        );
        expect(measured.result).toEqual(root);
        println("DRAFT_CORE name={} gas={}", name, measured.gasUsed);
        expect(measured.gasUsed).toBeLess(500000);
    }
}

get fun `test draft rejects changed message root context Merkle path and extra transport reference`() {
    val (seed, root, message, signature) = draftFixture("gpu");
    val empty = beginCell().endCell();
    val prime = slhEncodePure(message, empty);
    val wrongMessage = beginCell().storeUint(1, 8).storeRef(message).endCell();
    expect(slhDraftRecover(seed, root, signature, slhEncodePure(wrongMessage, empty))).toNotEqual(
        root,
    );
    expect(slhDraftRecover(seed, root ^ 1, signature, prime)).toNotEqual(root ^ 1);
    expect(slhDraftRecover(seed, root, signature, slhEncodePure(message, wrongMessage))).toNotEqual(
        root,
    );
    // Change the first FORS authentication node, retaining canonical transport.
    var first = signature.beginParse();
    val r = first.loadUint(128);
    val secret = first.loadUint(128);
    val path = first.loadUint(128);
    val forged = beginCell()
        .storeUint(r, 128)
        .storeUint(secret, 128)
        .storeUint(path ^ 1, 128)
        .storeSlice(first)
        .endCell();
    expect(slhDraftRecover(seed, root, forged, prime)).toNotEqual(root);
    val extended = beginCell().storeSlice(signature.beginParse()).storeRef(empty).endCell();
    var code = 0;
    try {
        val _ignored = slhDraftRecover(seed, root, extended, prime);
    } catch (e) {
        code = e;
    }
    expect(code).toEqual(SlhErrors.Encoding as int);
}

get fun `test draft complete internal verification deployment and refund fee trace`() {
    architectureEnvironment();
    val funder = testing.treasury("slh-draft-trace");
    val relayer = deployTestV5(funder.address, "relayer");
    val (seed, root, message, signature) = draftFixture("gpu");
    // Exact probe storage layout, avoiding a second entrypoint in this test module.
    val data = beginCell()
        .storeUint(seed, 128)
        .storeUint(root, 128)
        .storeAddress(relayer)
        .storeUint(0, 8)
        .endCell();
    val code = build("SlhDraftProbe", "research/SlhDraftProbe.tolk");
    val target = AutoDeployAddress {
        workchain: 0,
        stateInit: ContractState { code, data },
    };
    val job = target.calculateAddress();
    testing.setShardAccount(job, null);
    val before = testing.getAccountBalance(relayer);
    val body = beginCell()
        .storeUint(0x534c4431, 32)
        .storeRef(message)
        .storeRef(signature)
        .endCell();
    val trace = submitProbe(
        relayer,
        createMessage({
            bounce: BounceMode.NoBounce,
            value: grams("0.1"),
            dest: target,
            body: body.beginParse(),
        }),
    );
    expect(trace).toHaveSuccessfulDeploy({ to: job });
    expect(trace).toHaveSuccessfulTx({ from: job, to: relayer });
    expect(net.runGetMethod<int>(job, "accepted")).toEqual(1);
    val fee = traceFees(trace, "SLH_DRAFT_ONE_PASS");
    expect(before - testing.getAccountBalance(relayer) - testing.getAccountBalance(job)).toEqual(
        fee,
    );
    println(
        "DRAFT_TRACE verification_only fee_nano={} transactions={} code_hash={}",
        fee,
        trace.size(),
        code.hash(),
    );
    // Exercise the actual on-chain comparison, not only root recovery in a callback.
    val wrongMessage = beginCell().storeUint(1, 8).storeRef(message).endCell();
    val invalidData = beginCell()
        .storeUint(seed, 128)
        .storeUint(root, 128)
        .storeAddress(funder.address)
        .storeUint(0, 8)
        .endCell();
    val invalidTarget = AutoDeployAddress {
        workchain: 0,
        stateInit: ContractState {
            code,
            data: invalidData,
        },
    };
    val invalidJob = invalidTarget.calculateAddress();
    testing.setShardAccount(invalidJob, null);
    val rejected = net.send(
        funder.address,
        createMessage({
            bounce: BounceMode.NoBounce,
            value: grams("0.1"),
            dest: invalidTarget,
            body: beginCell()
                .storeUint(0x534c4431, 32)
                .storeRef(wrongMessage)
                .storeRef(signature)
                .endCell()
                .beginParse(),
        }),
    );
    expect(rejected).toHaveFailedTx({ to: invalidJob, exitCode: SlhErrors.Signature as int });
    expect(net.runGetMethod<int>(invalidJob, "accepted")).toEqual(0);
}
