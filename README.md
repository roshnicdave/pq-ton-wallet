# PQ TON Wallet

A post-quantum TON wallet with offline signing and on-chain verification.
Built for infrequent withdrawals: the wallet sends one authorized payment and
refunds unused submission funding to the relayer.

## Construction

Draft **SHA2-128-24**: `n=16, h=22, d=1, a=24, k=6, w=4, len=68`.
State is `(PK.seed, PK.root, sequence:u64, epoch:u32)`. Signed bytes, big-endian:

```text
00 00 || "PQS1" || network:i32 || wallet:(i8,bytes32) || recipient:(i8,bytes32)
      || amount:u64 || expiry:u32 || sequence:u64 || epoch:u32 || length:u16 || body
```

Pure signing, empty context; testnet `-3`, basechain addresses, 4–123 byte comment
body starting with four zero bytes. No fallback key or caller-supplied actions.
See [FIPS 205](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf) and
[draft SP 800-230](https://csrc.nist.gov/pubs/sp/800/230/ipd).

## Proof baseline

Source-level arguments for the current construction:

1. **Encoding:** fixed widths and explicit length give a decoding left inverse.
   Distinct payment fields produce distinct signed messages.
2. **Verification:** after `t` reads, exactly `t` signature blocks are consumed
   and `241-t` remain. Chunk boundaries are validated. At path level `l`,
   `index=floor(initial_index/2^l)` and `value` is the candidate ancestor after
   `l` ordered sibling hashes. This proves FORS/XMSS reconstruction by induction.
   Each WOTS chain applies steps `a_i..2`; address domains separate operations.
3. **Work:** with message-digit sum `s`, checksum `c=192-s`, chain hashes total
   `204-s-digit_sum_4(c)`. The subtracted sum is positive and divisible by three,
   so at most 201 chain hashes and **377 core SHA-256 invocations** are required.
4. **Authorization:** the sole payment path requires the recovered persistent
   root. Given correct verification and scheme unforgeability, emitting a payment
   on never-signed bytes yields a forgery. Encoding binds its exact fields.
5. **Replay:** successful action commitment increments sequence once; failure
   commits neither sequence nor payment. Each sequence emits at most once within
   a preserved account incarnation. Deletion/redeployment can reset it; safety
   across resets requires every erasure after the authorization expires.
6. **Principal:** let `p=BALANCE-remaining_INMSG_VALUE`. Require `v>=G+2F`, reserve
   `p-a`, pay `a` with separate fees, then refund the remainder. Success leaves
   `p-a`. Native capped compute gives `g<=G`; failure fines satisfy `A<=4c_f`,
   where `c_f` is the per-cell fine. Since `F>=16c_f`, `p+v-g-A>=p` on failure.
   Here `G` prices 1M gas and `F` bounds forwarding 2,048 bits/four cells.
   This depends on pinned processor semantics and excludes storage rent.

The checker pins bytecode, source, disassembly and native versions. Its
**945,804 gas** bound still requires compiled-variable correspondence and complete
native/continuation cost accounting. The hash count alone does not prove it.

## Build and benchmarks

| Measurement | Result |
| --- | ---: |
| Signature | 3,856 bytes |
| Live wallet compute | 370,972 gas |
| Full testnet withdrawal fees | 0.030280328 TON |
| Matched Wallet V5 fees | 0.000643146 TON |

Fees include relayer, wallet, recipient and refund transactions. Fixtures and
traces are public; never fund their keys.

Acton **1.2.1**, Python **3.13**, from this directory:

```sh
pip install -r requirements.txt
acton build
acton test tests/slh_wallet.test.tolk research/slh_draft.test.tolk --no-studio-reporting
python3 -m unittest discover -s tests -p test_slh_journal.py -v
python3 research/check_slh_wallet_gas.py --acton /path/to/acton
```

Tests need no seed, faucet or network. `research/reproduce_draft_interop.py`
checks pinned upstream sources and optionally builds the disposable C signer.

## Payments and recovery

The signer commits each pending payment to a local journal before export.
Retries reuse identical signed bytes. Conflicting pending authorizations reject;
`export` recovers the request without reading a seed or signing again.

`confirm` checks a receipt containing the transaction and its before/after account
cells: code, key, sequence transition, successful computation/actions, exact
payment and relayer refund. It records **emission**, not recipient execution.

```sh
python3 scripts/slh_wallet_signer.py confirm --journal build/payment-journal.sqlite \
  --receipt build/receipt.boc --trusted-hash '<validated-testnet-transaction-hash>'
```

The hash must be authenticated through validated testnet history, independently
of the receipt provider. The receipt checker does not verify consensus finality.
`acton script tests/make_receipts.tolk` regenerates the public emulator receipts.

## Current limits

Testnet only; no independent audit yet. Compiled/native proof obligations remain
open. Seed recovery restores authority, not payment history; account resets and
cloned journals require authenticated history. Journal durability assumes working
local locks/flushes. The plaintext-seed signer needs protected key storage.
Draft SHA2-128-24 requires **fewer than 2^24 generated signatures per key**, including
unpublished outputs across devices; that aggregate limit is not enforced.
