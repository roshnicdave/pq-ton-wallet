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

## Verification

Fixed field widths and the body length make the signed message unambiguous.
The contract reconstructs these bytes and checks the signature against the stored
public key. With a correct verifier and an unforgeable signature scheme, an
unsigned payment cannot pass this check.

After reading `t` signature blocks, the reader has exactly `241-t` left.
At Merkle path level `l`, `index=floor(initial_index/2^l)` and `value` is the
ancestor computed from the first `l` siblings. Induction gives the FORS and
XMSS roots. Each WOTS chain applies steps `a_i..2`; separate address domains
keep the hash operations distinct.

For message-digit sum `s` and checksum `c=192-s`, the number of chain hashes is
`204-s-digit_sum_4(c)`. The subtracted sum is positive and divisible by three,
so verification needs at most 201 chain hashes, or **377 SHA-256 calls** overall.

A successful payment increments the sequence once. Failed transactions commit
neither the sequence nor the payment. A sequence can therefore pay at most once
while the account state persists. Deletion and redeployment can reset it;
old authorizations must expire before that reset to prevent replay.

For balance protection, let `p=BALANCE-remaining_INMSG_VALUE`. The relayer supplies
`v>=G+2F`: `G` pays for 1M gas and `F` bounds forwarding 2,048 bits/four cells.
The wallet reserves `p-a`, sends `a` with fees separate, and refunds the remainder.
Success leaves `p-a`. On failure, compute costs `g<=G` and fines `A<=4c_f`, where
`c_f` is the per-cell fine. Since `F>=16c_f`, `p+v-g-A>=p`. This uses the pinned
transaction processor's rules and excludes storage rent.

The gas checker calculates **945,804 gas** for the pinned bytecode. Its loop-to-
bytecode mapping and native cost accounting still need verification.

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
payment and relayer refund. It confirms that the wallet sent the payment. Recipient execution happens later.

```sh
python3 scripts/slh_wallet_signer.py confirm --journal build/payment-journal.sqlite \
  --receipt build/receipt.boc --trusted-hash '<validated-testnet-transaction-hash>'
```

The hash must be authenticated through validated testnet history, independently
of the receipt provider. The receipt checker does not verify consensus finality.
`acton script tests/make_receipts.tolk` regenerates the public emulator receipts.

## Current limits

Testnet only; not independently audited. Seed recovery restores the key, but
payment history must be recovered separately. Account resets and cloned journals
need authenticated history checks. Journal durability depends on filesystem locks
and flushes. Signing keys are currently stored in plaintext.
Draft SHA2-128-24 requires **fewer than 2^24 generated signatures per key**, including
unpublished outputs across devices; that aggregate limit is not enforced.
