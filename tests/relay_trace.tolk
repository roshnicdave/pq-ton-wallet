// Real Wallet V5 code and signatures, executed only in the local emulator.
// PUBLIC TEST KEY: seed 07 repeated. Never fund these deterministic accounts.
import "@acton/boc"
import "@acton/crypto"
import "@acton/fmt"
import "@acton/fs"
import "@acton/io"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@acton/testing/expect"
import "@acton/types/big_array"
import "@acton/types/message"
import "@acton/types/transaction"

fun testV5Data(name: string): cell {
    // Only two fixed public fixtures exist; no user wallet configuration is read.
    val path = format("tests/fixtures/v5/{}-data.boc", name);
    return boc.decode(fs.readBytes(path)!)!;
}

fun deployTestV5(funder: address, name: string): address {
    val state: ContractState = {
        code: boc.decode(fs.readBytes("tests/fixtures/v5/code.boc")!)!,
        data: testV5Data(name),
    };
    val target = AutoDeployAddress {
        workchain: 0,
        stateInit: state,
    };
    val addr = target.calculateAddress();
    testing.setShardAccount(addr, null);
    expect(
        net.send(
            funder,
            createMessage({ bounce: BounceMode.NoBounce, value: grams("1"), dest: target }),
        ),
    ).toHaveSuccessfulDeploy({ to: addr });
    return addr;
}

fun relayThroughV5(relayer: address, to: address, value: coins, body: cell): SendResultList {
    return submitProbe(
        relayer,
        createMessage({ bounce: BounceMode.NoBounce, value, dest: to, body: body.beginParse() }),
    );
}

fun submitProbe(relayer: address, message: OutMessage): SendResultList {
    val actions = beginCell()
        .storeRef(beginCell().endCell())
        .storeUint(0x0ec3c86d, 32)
        .storeUint(3, 8)
        .storeRef(message.messageCell)
        .endCell();
    val signing = beginCell()
        .storeUint(0x7369676e, 32)
        .storeUint(2026, 32)
        .storeUint(1793044500, 32)
        .storeUint(0, 32)
        .storeUint(1, 1)
        .storeRef(actions)
        .storeUint(0, 1)
        .endCell();
    val signature = crypto.sign(
        0x0707070707070707070707070707070707070707070707070707070707070707,
        signing,
    );
    val request = beginCell().storeSlice(signing.beginParse()).storeSlice(signature).endCell();
    val external = net.createExternalMessage(relayer, request);
    val (cells, bits, _refs) = external.messageCell.calculateSizeStrict(8192);
    var encoded = boc.encode(external.messageCell, { crc32: true });
    var bytes = 0;
    while (true) {
        bytes += encoded.remainingBitsCount() / 8;
        if (encoded.remainingRefsCount() == 0) {
            break;
        }
        encoded = encoded.loadRef().beginParse();
    }
    println("PROBE external bytes={} bits={} cells={}", bytes, bits, cells);
    return net.sendExternal(external).unwrap();
}

fun traceFees(results: SendResultList, label: string): coins {
    var fee: coins = 0;
    var i = 0;
    while (i < results.size()) {
        val result = results.at(i);
        val tx = result.tx.load();
        fee += tx.totalFees.grams;
        var remainingForward: coins = 0;
        var computeFee: coins = 0;
        val description = tx.description.load();
        if (description is TlbTransOrd) {
            val compute = description.computePh;
            if (compute is TlbTrComputeVm) {
                computeFee = compute.gasFees;
            }
        }
        var j = 0;
        while (j < result.outMessages.size()) {
            remainingForward += TlbMessageRelaxedGeneric
                .fromCell(result.outMessages.atCell(j))
                .info
                .fwdFee;
            j += 1;
        }
        fee += remainingForward;
        println(
            "TRACE_TX {} gas={} compute_nano={} total_nano={} outgoing_remaining_fwd_nano={}",
            format("label={} index={}", label, i),
            result.gasUsed,
            computeFee,
            tx.totalFees.grams,
            remainingForward,
        );
        i += 1;
    }
    return fee;
}
