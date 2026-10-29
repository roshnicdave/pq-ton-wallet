"""Payment failure/recovery checks using existing public signatures, never new keys."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import json
import multiprocessing
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from slh_wallet_journal import PaymentJournal
from slh_wallet_signer import (export_record, frozen_wallet, payload, snake,
                               validate_record, canonical, sign_payment, CODE_HASH)
from slh_wallet_receipt import verify_receipt
from pytoniq_core import Cell, begin_cell


def public_record(sequence=0):
    record = json.loads((ROOT / f"tests/fixtures/slh-wallet/seq{sequence}.json").read_text())
    request = (begin_cell().store_uint(0x534c4857, 32).store_ref(payload(record["payment"]))
               .store_ref(snake(bytes.fromhex(record["signature"]))).end_cell())
    blob = request.to_boc(hash_crc32=True)
    record.update(request_boc_hex=blob.hex(), request_boc_bytes=len(blob), request_hash=request.hash.hex())
    return record


def crash_worker(path, stage, connection):
    record = public_record()
    journal = PaymentJournal(path)
    def produce():
        connection.send("before-commit")
        connection.recv()
        return record
    if stage == "before":
        journal.issue(bytes.fromhex(record["public_key"]), record["payment"], produce)
    else:
        journal.issue(bytes.fromhex(record["public_key"]), record["payment"], lambda: record)
        connection.send("after-commit")
        connection.recv()


class SlhJournalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.path = self.directory / "pending.sqlite"
        self.record = public_record()
        self.public = bytes.fromhex(self.record["public_key"])
        self.payment = self.record["payment"]
        self.journal = PaymentJournal.create(self.path, self.public, frozen_wallet(self.public))

    def issue(self):
        return self.journal.issue(self.public, self.payment, lambda: self.record)

    def test_retry_and_competing_callers_use_one_committed_signature(self):
        produce = Mock(return_value=self.record)
        with ThreadPoolExecutor(2) as pool:
            records = list(pool.map(lambda _: PaymentJournal(self.path).issue(
                self.public, self.payment, produce), range(2)))
        self.assertEqual(records[0], records[1])
        produce.assert_called_once()
        no_signing = Mock(side_effect=AssertionError("retry signed again"))
        self.assertEqual(PaymentJournal(self.path).issue(self.public, self.payment, no_signing), self.record)
        with self.assertRaisesRegex(ValueError, "pending"):
            self.journal.issue(self.public, self.payment | {"amount": 2}, no_signing)
        with self.assertRaisesRegex(ValueError, "reconciliation"):
            self.journal.issue(self.public, self.payment | {"sequence": 1}, no_signing)
        no_signing.assert_not_called()
        public_file, payment_file = self.directory / "public.json", self.directory / "payment.json"
        public_file.write_text(json.dumps({"public_key": self.public.hex()}))
        payment_file.write_text(json.dumps(self.payment))
        subprocess.run([sys.executable, str(ROOT / "scripts/slh_wallet_signer.py"),
            "--binary", str(self.directory / "absent-binary"), "sign",
            "--journal", str(self.path), "--public", str(public_file),
            "--payment", str(payment_file), "--secret", str(self.directory / "absent-secret"),
            "--request", str(self.directory / "retry.boc"),
            "--manifest", str(self.directory / "retry.json")], check=True, capture_output=True)

    def test_partial_export_recovers_without_signer_or_seed(self):
        self.issue()
        request, manifest = self.directory / "request.boc", self.directory / "manifest.json"
        request.write_bytes(b"interrupted export")
        with self.assertRaises(FileExistsError):
            export_record(self.journal.pending(), request, manifest)
        fresh = self.directory / "recovered.boc"
        # Exercise the real CLI: no secret, public-key file, or signing executable.
        command = [sys.executable, str(ROOT / "scripts/slh_wallet_signer.py"), "export",
                   "--journal", str(self.path), "--request", str(fresh), "--manifest", str(manifest)]
        subprocess.run(command, check=True, capture_output=True)
        subprocess.run(command, check=True, capture_output=True)
        self.assertEqual(fresh.read_bytes(), bytes.fromhex(self.record["request_boc_hex"]))
        self.assertEqual(json.loads(manifest.read_text())["payment"], self.payment)

    def test_public_bundle_tampering_and_wrong_wallet_are_rejected(self):
        self.assertEqual(self.payment["wallet"], frozen_wallet(self.public))
        validate_record(self.record)
        for field, value in (("request_hash", "00"*32), ("canonical_hex", "00")):
            with self.assertRaises(ValueError): validate_record(self.record | {field: value})
        altered = copy.deepcopy(self.record)
        altered["payment"]["amount"] += 1
        altered["canonical_hex"] = canonical(altered["payment"]).hex()
        with self.assertRaisesRegex(ValueError, "authorization"): validate_record(altered)
        produce = Mock(side_effect=AssertionError("wrong wallet reached signer"))
        with self.assertRaises(ValueError):
            self.journal.issue(self.public, self.payment | {"wallet": "0:"+"ff"*32}, produce)
        produce.assert_not_called()
        with self.assertRaisesRegex(ValueError, "frozen wallet"):
            sign_payment(self.directory / "absent-binary", bytes(32)+self.public[:16], self.public,
                         self.payment | {"wallet": "0:"+"ff"*32})

    def test_expiry_is_inclusive_and_requires_unchanged_trusted_sequence(self):
        self.issue()
        expires = self.payment["expires"]
        self.journal.reconcile_trusted_observation(0, expires, "trusted-block-at-expiry")
        self.assertEqual(self.journal.pending(), self.record)
        with self.assertRaisesRegex(ValueError, "stale"):
            self.journal.reconcile_trusted_observation(0, expires-1, "stale-block")
        self.journal.reconcile_trusted_observation(0, expires+1, "trusted-block-after-expiry")
        with self.assertRaisesRegex(ValueError, "no pending"): self.journal.pending()
        with closing(self.journal.connect()) as db:
            self.assertEqual(db.execute("SELECT status FROM requests").fetchone()[0], "expired")

    def test_known_emission_advances_but_unknown_consumption_blocks(self):
        self.issue()
        self.journal.reconcile_trusted_observation(1, 100, "trusted-successful-wallet-trace",
                                                  self.record["request_hash"])
        next_record = public_record(1)
        self.journal.issue(self.public, next_record["payment"], lambda: next_record)
        self.journal.reconcile_trusted_observation(2, 101, "trusted-unknown-consumption", "00"*32)
        with self.assertRaisesRegex(ValueError, "reconciliation"):
            self.journal.issue(self.public, next_record["payment"], lambda: next_record)
        with closing(self.journal.connect()) as db:
            self.assertEqual(db.execute("SELECT status FROM requests ORDER BY rowid").fetchall(),
                             [("emitted",), ("pending",)])
            self.assertEqual(db.execute("SELECT blocked FROM wallet").fetchone()[0], 1)

    def kill_at(self, stage):
        context = multiprocessing.get_context("spawn")
        parent, child = context.Pipe()
        process = context.Process(target=crash_worker, args=(self.path, stage, child))
        process.start()
        try:
            self.assertTrue(parent.poll(10), "worker did not reach the crash point")
            marker = parent.recv()
            process.kill()
            process.join(5)
            self.assertFalse(process.is_alive())
            return marker
        finally:
            if process.is_alive(): process.kill(); process.join(5)
            parent.close(); child.close(); process.close()

    def test_process_kill_before_commit_leaves_no_publishable_request(self):
        self.assertEqual(self.kill_at("before"), "before-commit")
        with self.assertRaisesRegex(ValueError, "no pending"): PaymentJournal(self.path).pending()
        self.assertEqual(self.issue(), self.record)

    def test_process_kill_after_commit_recovers_exact_request(self):
        self.assertEqual(self.kill_at("after"), "after-commit")
        self.assertEqual(PaymentJournal(self.path).pending(), self.record)

    def test_missing_journal_fails_closed_instead_of_recreating_database(self):
        self.path.unlink()
        with self.assertRaises(FileNotFoundError): PaymentJournal(self.path)
        with self.assertRaises(sqlite3.OperationalError): self.journal.pending()
        self.assertFalse(self.path.exists())

    def test_verified_emission_unlocks_next_payment_through_cli(self):
        self.issue()
        receipt = ROOT / "tests/fixtures/slh-wallet/receipt.boc"
        trusted = Cell.one_from_boc(receipt.read_bytes()).refs[0].hash.hex()
        result = subprocess.run([sys.executable, str(ROOT / "scripts/slh_wallet_signer.py"),
            "confirm", "--journal", str(self.path), "--receipt", str(receipt),
            "--trusted-hash", trusted], check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)["status"], "emitted")
        with self.assertRaisesRegex(ValueError, "no pending"): self.journal.pending()
        next_record = public_record(1)
        self.assertEqual(self.journal.issue(self.public, next_record["payment"], lambda: next_record), next_record)

    def test_failed_wallet_transaction_never_confirms_pending_payment(self):
        self.issue()
        receipt = ROOT / "tests/fixtures/slh-wallet/receipt-failed.boc"
        trusted = Cell.one_from_boc(receipt.read_bytes()).refs[0].hash.hex()
        result = subprocess.run([sys.executable, str(ROOT / "scripts/slh_wallet_signer.py"),
            "confirm", "--journal", str(self.path), "--receipt", str(receipt),
            "--trusted-hash", trusted], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.journal.pending(), self.record)

    def test_receipt_hash_and_account_cells_must_match_checkpoint(self):
        receipt = (ROOT / "tests/fixtures/slh-wallet/receipt.boc").read_bytes()
        root = Cell.one_from_boc(receipt)
        trusted = root.refs[0].hash.hex()
        with self.assertRaisesRegex(ValueError, "transaction hash"):
            verify_receipt(self.record, receipt, "00"*32, CODE_HASH)
        swapped = (begin_cell().store_ref(root.refs[0]).store_ref(root.refs[2])
                   .store_ref(root.refs[2]).end_cell().to_boc())
        with self.assertRaisesRegex(ValueError, "state update"):
            verify_receipt(self.record, swapped, trusted, CODE_HASH)
        with self.assertRaisesRegex(ValueError, "code mismatch"):
            verify_receipt(self.record, receipt, trusted, "00"*32)

    def test_receipt_cannot_substitute_payment_fields_or_signing_key(self):
        receipt = (ROOT / "tests/fixtures/slh-wallet/receipt.boc").read_bytes()
        trusted = Cell.one_from_boc(receipt).refs[0].hash.hex()
        for field, value in [("recipient", "0:"+"ff"*32), ("amount", self.payment["amount"]+1),
                             ("body_hex", (bytes(4)+b"different").hex())]:
            record = copy.deepcopy(self.record)
            record["payment"][field] = value
            with self.assertRaisesRegex(ValueError, "differs from authorization"):
                verify_receipt(record, receipt, trusted, CODE_HASH)
        with self.assertRaisesRegex(ValueError, "key, sequence or epoch"):
            verify_receipt(self.record | {"public_key": "00"*32}, receipt, trusted, CODE_HASH)


if __name__ == "__main__":
    unittest.main()
