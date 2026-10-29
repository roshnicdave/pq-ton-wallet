"""Offline SHA2-128-24 signer and pending-payment management for TON testnet."""
import argparse
import json
import os
import struct
import subprocess
import time
from pathlib import Path
from pytoniq_core import Address, Cell, StateInit, begin_cell
from slh_sha2_128_24_reference import verify
from slh_wallet_journal import PaymentJournal, sync_directory

FIELDS = {"network", "wallet", "recipient", "amount", "expires", "sequence", "epoch", "body_hex"}
CODE_HASH = "71d67e17e8af4de8c843482f091ead58cf9f0acdd0210eb1cff5401ee04ced08"


def frozen_wallet(public):
    if len(public) != 32:
        raise ValueError("public key must be 32 bytes")
    code = Cell.one_from_boc((Path(__file__).resolve().parents[1] /
                              "benchmarks/slh-wallet-security/code.boc").read_bytes())
    if code.hash.hex() != CODE_HASH:
        raise ValueError("wallet code identity changed")
    return wallet_address(code, public).to_str(False)


def normalize(p):
    if set(p) != FIELDS:
        raise ValueError("unknown or missing payment fields")
    for name, maximum in [("network", 0), ("amount", 2**64), ("expires", 2**32),
                          ("sequence", 2**64-1), ("epoch", 2**32)]:
        if type(p[name]) is not int:
            raise ValueError(name + " must be an integer")
        if name != "network" and not 0 <= p[name] < maximum:
            raise ValueError(name + " outside range")
    if p["network"] != -3 or p["amount"] == 0:
        raise ValueError("testnet only, positive amount required")
    body = bytes.fromhex(p["body_hex"])
    if not 4 <= len(body) <= 123 or body[:4] != bytes(4):
        raise ValueError("only complete bounded comment bodies are supported")
    p = dict(p, body_hex=body.hex())
    for name in ("wallet", "recipient"):
        address = Address(p[name])
        if address.wc != 0:
            raise ValueError("basechain addresses only")
        p[name] = address.to_str(False)
    return p


def canonical(p):
    p = normalize(p)
    def addr(value):
        a = Address(value)
        return a.wc.to_bytes(1, "big", signed=True) + a.hash_part
    body = bytes.fromhex(p["body_hex"])
    return (b"PQS1" + (-3).to_bytes(4, "big", signed=True) + addr(p["wallet"]) +
            addr(p["recipient"]) + struct.pack(">QIQIH", p["amount"], p["expires"],
            p["sequence"], p["epoch"], len(body)) + body)


def snake(data):
    tail = None
    for i in reversed(range(0, len(data), 112)):
        b = begin_cell().store_bytes(data[i:i+112])
        if tail is not None:
            b.store_ref(tail)
        tail = b.end_cell()
    return tail or begin_cell().end_cell()


def storage(public):
    if len(public) != 32:
        raise ValueError("public key must be 32 bytes")
    return begin_cell().store_bytes(public).store_uint(0, 64).store_uint(0, 32).end_cell()


def wallet_address(code, public):
    return Address((0, StateInit(code=code, data=storage(public)).serialize().hash))


def payload(p):
    p = normalize(p)
    body = begin_cell().store_bytes(bytes.fromhex(p["body_hex"])).end_cell()
    return (begin_cell().store_uint(0x50515331, 32).store_int(-3, 32)
            .store_address(Address(p["wallet"])).store_address(Address(p["recipient"]))
            .store_uint(p["amount"], 64).store_uint(p["expires"], 32)
            .store_uint(p["sequence"], 64).store_uint(p["epoch"], 32).store_ref(body).end_cell())


def sign_payment(binary, seed, public, p):
    if len(seed) != 48 or seed[32:] != public[:16]:
        raise ValueError("seed/public key mismatch")
    p = normalize(p)
    if p["wallet"] != frozen_wallet(public) or p["epoch"] != 0:
        raise ValueError("payment does not bind the frozen wallet for this public key")
    start = time.monotonic()
    result = subprocess.run([str(binary.resolve()), "sign"], input=seed+public[16:]+os.urandom(16)+
                            b"\x00\x00"+canonical(p), capture_output=True, check=True)
    sig = result.stdout
    if not verify(public, sig, canonical(p)):
        raise ValueError("signature self-verification failed")
    request = (begin_cell().store_uint(0x534c4857, 32).store_ref(payload(p))
               .store_ref(snake(sig)).end_cell())
    return request, sig, time.monotonic()-start


def exclusive(path, data, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    sync_directory(path.parent)


def validate_record(record):
    """Check public journal contents before exporting them to a relayer."""
    public = bytes.fromhex(record["public_key"])
    p = normalize(record["payment"])
    sig = bytes.fromhex(record["signature"])
    if (p["wallet"] != frozen_wallet(public) or p["epoch"] != 0 or
            record["canonical_hex"] != canonical(p).hex() or not verify(public, sig, canonical(p))):
        raise ValueError("invalid journal authorization")
    request = (begin_cell().store_uint(0x534c4857, 32).store_ref(payload(p))
               .store_ref(snake(sig)).end_cell())
    blob = bytes.fromhex(record["request_boc_hex"])
    if (Cell.one_from_boc(blob).hash != request.hash or
            request.hash.hex() != record["request_hash"] or len(blob) != record["request_boc_bytes"]):
        raise ValueError("journal request differs from authorized payment")
    return blob


def export_record(record, request, manifest):
    blob = validate_record(record)
    meta = {k: v for k, v in record.items() if k != "request_boc_hex"}
    for path, data in ((request, blob), (manifest, (json.dumps(meta, indent=2)+"\n").encode())):
        if path.exists():
            if path.read_bytes() != data:
                raise FileExistsError("conflicting/partial export; use fresh paths to recover journal bytes")
        else:
            exclusive(path, data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("build/slh-testnet-io"))
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--secret", type=Path, required=True)
    init.add_argument("--public", type=Path, required=True)
    recover = sub.add_parser("recover")
    recover.add_argument("--secret", type=Path, required=True)
    recover.add_argument("--public", type=Path, required=True)
    journal_init = sub.add_parser("journal-init", help="new-wallet journal only; not seed/history recovery")
    journal_init.add_argument("--public", type=Path, required=True)
    journal_init.add_argument("--journal", type=Path, required=True)
    sign = sub.add_parser("sign")
    for name in ("secret", "public", "payment", "request", "manifest", "journal"):
        sign.add_argument("--"+name, type=Path, required=True)
    export = sub.add_parser("export", help="recover the committed request without signing or reading a seed")
    for name in ("journal", "request", "manifest"):
        export.add_argument("--"+name, type=Path, required=True)
    confirm = sub.add_parser("confirm", help="verify a wallet-emission receipt and advance its journal")
    for name in ("journal", "receipt"):
        confirm.add_argument("--"+name, type=Path, required=True)
    confirm.add_argument("--trusted-hash", required=True,
                         help="finalized testnet transaction hash authenticated independently of the receipt provider")
    args = parser.parse_args()
    if args.command == "confirm":
        from slh_wallet_receipt import verify_receipt
        journal = PaymentJournal(args.journal)
        record = journal.pending()
        validate_record(record)
        result = verify_receipt(record, args.receipt.read_bytes(), args.trusted_hash, CODE_HASH)
        journal.reconcile_trusted_observation(result["next_sequence"], result["chain_time"],
            "transaction:" + result["transaction_hash"], result["request_hash"])
        print(json.dumps(result))
    elif args.command == "journal-init":
        public = bytes.fromhex(json.loads(args.public.read_text())["public_key"])
        wallet = frozen_wallet(public)
        PaymentJournal.create(args.journal, public, wallet)
        print(json.dumps({"wallet": wallet, "next_sequence": 0, "network": "testnet"}))
    elif args.command == "export":
        export_record(PaymentJournal(args.journal).pending(), args.request, args.manifest)
    elif args.command in {"init", "recover"}:
        if args.public.exists():
            raise FileExistsError(args.public)
        if args.command == "init":
            seed = os.urandom(48)
            exclusive(args.secret, seed, private=True)
        else:
            seed = args.secret.read_bytes()
            if len(seed) != 48:
                raise ValueError("recovery requires the complete 48-byte seed")
        start = time.monotonic()
        result = subprocess.run([str(args.binary.resolve()), "keygen"], input=seed,
                                capture_output=True, check=True)
        if len(result.stdout) != 32:
            raise ValueError("bad C key generation output")
        data = {"public_key": result.stdout.hex(), "keygen_seconds": time.monotonic()-start,
                "network": "testnet", "disposable": True}
        exclusive(args.public, (json.dumps(data, indent=2)+"\n").encode())
        print(json.dumps(data))
    else:
        public = bytes.fromhex(json.loads(args.public.read_text())["public_key"])
        p = normalize(json.loads(args.payment.read_text()))
        if p["wallet"] != frozen_wallet(public) or p["epoch"] != 0:
            raise ValueError("payment does not bind the frozen wallet for this public key")
        def produce():
            request, sig, elapsed = sign_payment(args.binary, args.secret.read_bytes(), public, p)
            blob = request.to_boc(hash_crc32=True)
            return {"payment": p, "public_key": public.hex(), "signature": sig.hex(),
                "canonical_hex": canonical(p).hex(), "sign_seconds": elapsed,
                "request_hash": request.hash.hex(), "request_boc_bytes": len(blob),
                "request_boc_hex": blob.hex()}
        record = PaymentJournal(args.journal).issue(public, p, produce)
        export_record(record, args.request, args.manifest)
        print(json.dumps({k: v for k, v in record.items()
                          if k not in {"signature", "canonical_hex", "request_boc_hex"}}))


if __name__ == "__main__":
    main()
