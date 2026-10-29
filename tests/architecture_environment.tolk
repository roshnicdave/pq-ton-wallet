import "@acton/boc"
import "@acton/fs"
import "@acton/emulation/config"
import "@acton/emulation/testing"
import "@acton/testing/expect"

// Archived public testnet configuration: offline, deterministic comparisons.
fun architectureEnvironment() {
    testing.setNow(1793044400);
    val config = BlockchainConfigMap.fromCell(
        boc.decode(fs.readBytes("tests/fixtures/architecture-config.boc")!)!,
    );
    expect(testing.setConfig(config)).toEqual(true);
}
