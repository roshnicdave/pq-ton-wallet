import "@acton/boc"
import "@acton/fs"
import "@acton/emulation/network"
import "@acton/emulation/testing"
import "@wrappers/SlhWallet.gen"
import "slh_wallet.test"

fun main() {
    val (payer, wallet, _recipient) = freshSlh("receipt-fixture");
    val before = testing.getShardAccount(wallet.address)!.account;
    val trace = wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") });
    val after = testing.getShardAccount(wallet.address)!.account;
    val receipt = beginCell().storeRef(trace.at(0).tx).storeRef(before).storeRef(after).endCell();
    assert (
        fs.writeBytes("tests/fixtures/slh-wallet/receipt.boc", boc.encode(receipt, { crc32: true }))
    ) throw 990;
    val failed = wallet.sendAny(payer.address, slhFixtureRequest(0), { value: grams("0.08") });
    val failedAfter = testing.getShardAccount(wallet.address)!.account;
    val rejection = beginCell()
        .storeRef(failed.at(0).tx)
        .storeRef(after)
        .storeRef(failedAfter)
        .endCell();
    assert (
        fs.writeBytes(
            "tests/fixtures/slh-wallet/receipt-failed.boc",
            boc.encode(rejection, { crc32: true }),
        )
    ) throw 991;
}
