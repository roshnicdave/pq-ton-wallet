"""One-wallet pending-payment journal. See README for recovery assumptions."""
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3

from pytoniq_core import Cell


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class PaymentJournal:
    def __init__(self, path):
        self.path = Path(path).absolute()
        if not self.path.is_file():
            raise FileNotFoundError("missing journal; payment history cannot be inferred from the seed")

    def connect(self):
        # mode=rw prevents silent recreation if the file disappears after open.
        db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True,
                             timeout=30, isolation_level=None)
        db.execute("PRAGMA synchronous=EXTRA")
        db.execute("PRAGMA fullfsync=ON")  # F_FULLFSYNC where the native VFS supports it.
        if (db.execute("PRAGMA synchronous").fetchone()[0] != 3 or
                db.execute("PRAGMA journal_mode").fetchone()[0] != "delete"):
            db.close()
            raise RuntimeError("journal requires EXTRA synchronization and rollback DELETE mode")
        return db

    @classmethod
    def create(cls, path, public, wallet):
        path = Path(path)
        if not path.parent.is_dir():
            raise FileNotFoundError("create the journal in an existing durable local directory")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        journal = cls(path)
        with closing(journal.connect()) as db:
            db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE wallet(public TEXT NOT NULL, address TEXT NOT NULL,
                    next_seq TEXT NOT NULL, blocked INTEGER NOT NULL, last_time INTEGER NOT NULL);
                CREATE TABLE requests(seq TEXT NOT NULL, fields TEXT NOT NULL,
                    record TEXT NOT NULL, status TEXT NOT NULL);
                CREATE UNIQUE INDEX one_pending ON requests((1)) WHERE status='pending';
            """)
            db.execute("INSERT INTO wallet VALUES(?,?, '0',0,0)", (public.hex(), wallet))
            db.commit()
        sync_directory(path.parent)
        return journal

    def issue(self, public, payment, produce):
        """Return the pending bundle or commit a new one before export."""
        fields = json.dumps(payment, sort_keys=True, separators=(",", ":"))
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            key, wallet, sequence, blocked, _ = db.execute("SELECT * FROM wallet").fetchone()
            if (blocked or key != public.hex() or payment["wallet"] != wallet or
                    payment["epoch"] != 0 or payment["sequence"] != int(sequence)):
                raise ValueError("journal key, wallet or sequence mismatch; authenticated reconciliation required")
            row = db.execute("SELECT fields,record FROM requests WHERE status='pending'").fetchone()
            if row:
                if row[0] != fields:
                    raise ValueError("unresolved pending payment; cannot replace its authorization")
                return json.loads(row[1])
            record = produce()
            if record["payment"] != payment or record["public_key"] != key:
                raise ValueError("signer output differs from journal authorization")
            request = Cell.one_from_boc(bytes.fromhex(record["request_boc_hex"]))
            if request.hash.hex() != record["request_hash"]:
                raise ValueError("request hash mismatch")
            db.execute("INSERT INTO requests VALUES(?,?,?,'pending')",
                       (sequence, fields, json.dumps(record, sort_keys=True)))
            db.commit()
            return record

    def pending(self):
        with closing(self.connect()) as db:
            row = db.execute("SELECT record FROM requests WHERE status='pending'").fetchone()
            if not row:
                raise ValueError("no pending request")
            return json.loads(row[0])

    def reconcile_trusted_observation(self, next_sequence, chain_time, checkpoint,
                                      committed_request_hash=None):
        """Requires authenticated finality/incarnation and a successful wallet trace.

        request_hash identifies committed payment emission, not mere submission.
        This method does not authenticate the observation; the CLI checks receipt contents against a trusted hash.
        """
        if (type(next_sequence) is not int or not 0 <= next_sequence < 2**64 or
                type(chain_time) is not int or not 0 <= chain_time < 2**32 or
                not isinstance(checkpoint, str) or not checkpoint):
            raise ValueError("invalid trusted observation")
        with closing(self.connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            sequence, blocked, last_time = db.execute(
                "SELECT next_seq,blocked,last_time FROM wallet").fetchone()
            sequence = int(sequence)
            if blocked or next_sequence < sequence or chain_time < last_time:
                raise ValueError("blocked journal or stale observation")
            row = db.execute("SELECT rowid,record FROM requests WHERE status='pending'").fetchone()
            if not row:
                raise ValueError("no pending request to reconcile")
            ident, encoded = row
            record = json.loads(encoded)
            if next_sequence == sequence + 1 and committed_request_hash == record["request_hash"]:
                record["observation"] = dict(checkpoint=checkpoint, chain_time=chain_time,
                                              next_sequence=next_sequence, request_hash=committed_request_hash)
                db.execute("UPDATE requests SET status='emitted',record=? WHERE rowid=?",
                           (json.dumps(record, sort_keys=True), ident))
                db.execute("UPDATE wallet SET next_seq=?", (str(next_sequence),))
            elif next_sequence == sequence and committed_request_hash is None:
                if chain_time > record["payment"]["expires"]:
                    record["observation"] = dict(checkpoint=checkpoint, chain_time=chain_time,
                                                  next_sequence=next_sequence)
                    db.execute("UPDATE requests SET status='expired',record=? WHERE rowid=?",
                               (json.dumps(record, sort_keys=True), ident))
            elif next_sequence > sequence:
                # Unknown consumption is not evidence of this payment's emission.
                db.execute("UPDATE wallet SET blocked=1")
                record["unresolved_observation"] = dict(checkpoint=checkpoint, chain_time=chain_time,
                    next_sequence=next_sequence, request_hash=committed_request_hash)
                db.execute("UPDATE requests SET record=? WHERE rowid=?",
                           (json.dumps(record, sort_keys=True), ident))
            else:
                raise ValueError("observation does not match pending request")
            db.execute("UPDATE wallet SET last_time=?", (chain_time,))
            db.commit()
