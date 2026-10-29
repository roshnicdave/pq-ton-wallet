# PQ TON Wallet

A hash-based TON wallet for infrequent withdrawals. Testnet research, unaudited;
not ready for real funds. The wallet verifies locally, sends one authorized
payment and refunds unused relayer funding. The signing seed stays offline.

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

Conditional source-level arguments; not machine-checked or independently reviewed.

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

## Evidence and reproduction

| Measurement | Result |
| --- | ---: |
| Signature | 3,856 bytes |
| Live wallet compute | 370,972 gas |
| Full testnet withdrawal fees | 0.030280328 TON |
| Matched Wallet V5 fees | 0.000643146 TON |

Fees include relayer, wallet, recipient and refund transactions. Fixtures and
traces are public; never fund their keys. Earlier experiments are archived locally
and excluded from this repository.

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

## Recovery assumptions

The CLI requires one intact SQLite journal: commit before export, reuse identical
bytes on retry, reject conflicting pending payments. `export` recovers derived
files without signing. The wallet address is checked against the key and code.
Reconciliation requires authenticated finality, incarnation and a successful
wallet-emission trace; sequence alone is not a receipt. This authentication is
not implemented, so the CLI remains a single-pending-payment research tool.

Seed recovery restores authority, not payment history. Journal durability assumes
working local locks/flushes; restored or cloned journals are not rollback-resistant.
The draft requires **fewer than 2^24 generated signatures per key**, including
unpublished outputs across all devices; this is not enforced. The plaintext-seed
signer is unhardened. Compiler/native proofs, authenticated recovery, lifecycle
assumptions and independent cryptographic/contract review remain open.
