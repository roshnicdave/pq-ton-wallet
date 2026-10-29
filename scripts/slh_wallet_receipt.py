"""Check payment emission against an independently authenticated transaction hash."""
from pytoniq_core import Account, Address, Cell, InternalMsgInfo, Transaction, begin_cell


def require(condition, message):
    if not condition:
        raise ValueError(message)


def account_state(cell, expected_hash, payment, public, sequence, code_hash):
    require(cell.hash == expected_hash, "account cell does not match transaction state update")
    account = Account.deserialize(cell.begin_parse())
    require(account is not None and account.addr == Address(payment["wallet"]), "wrong wallet account")
    require(account.storage.state.type_ == "account_active", "wallet is not active")
    state = account.storage.state.state_init
    require(state.code is not None and state.code.hash.hex() == code_hash, "wallet code mismatch")
    require(state.library is None and state.special is None and state.split_depth is None,
            "unexpected wallet state initialization")
    require(not account.storage.balance.other.dict, "extra currencies are unsupported")
    require(state.data is not None, "missing wallet data")
    data = state.data.begin_parse()
    require(len(data.bits) == 352 and len(data.refs) == 0, "wrong wallet data layout")
    require(data.load_bytes(32) == public and data.load_uint(64) == sequence and
            data.load_uint(32) == payment["epoch"], "wallet key, sequence or epoch mismatch")


def verify_receipt(record, receipt, trusted_hash, code_hash):
    """record/code_hash are locally validated; trusted_hash must anchor finalized testnet history."""
    require(isinstance(trusted_hash, str) and len(trusted_hash) == 64, "expected a hex transaction hash")
    expected = bytes.fromhex(trusted_hash)
    bundle = Cell.one_from_boc(receipt)
    require(bundle.type_ == -1 and not bundle.bits and len(bundle.refs) == 3, "wrong receipt layout")
    tx_cell, before, after = bundle.refs
    require(tx_cell.type_ == -1 and tx_cell.hash == expected, "transaction hash mismatch")
    tx = Transaction.deserialize(tx_cell.begin_parse())
    p, public = record["payment"], bytes.fromhex(record["public_key"])
    wallet, recipient = Address(p["wallet"]), Address(p["recipient"])
    require(tx.account_addr == wallet.hash_part and wallet.wc == 0, "transaction belongs to another wallet")
    require(tx.orig_status.type_ == "active" and tx.end_status.type_ == "active", "wallet was not active before and after this transaction")
    require(tx.now <= p["expires"], "payment executed after its signed expiry")
    description = tx.description
    require(description.type_ == "ordinary" and not description.aborted and not description.destroyed,
            "wallet transaction did not commit")
    compute, action = description.compute_ph, description.action
    require(compute.type_ == "vm" and compute.success and compute.exit_code == 0 and
            not compute.account_activated, "wallet computation failed or activated an account")
    require(action is not None and action.success and action.valid and not action.no_funds and
            action.result_code == 0 and action.skipped_actions == 0 and
            action.tot_actions == 3 and action.spec_actions == 1 and action.msgs_created == 2,
            "wallet actions did not commit exactly")
    account_state(before, tx.state_update.old_hash,
                  p, public, p["sequence"], code_hash)
    account_state(after, tx.state_update.new_hash,
                  p, public, p["sequence"] + 1, code_hash)
    incoming = tx.in_msg
    require(incoming is not None and isinstance(incoming.info, InternalMsgInfo) and
            incoming.info.dest == wallet and not incoming.info.bounced and
            incoming.info.src.wc == 0 and incoming.body.hash.hex() == record["request_hash"],
            "transaction does not execute the pending request")
    require(tx.outmsg_cnt == 2 and len(tx.out_msgs) == 2, "wrong outgoing message count")
    payment, refund = tx.out_msgs
    for message in (payment, refund):
        require(isinstance(message.info, InternalMsgInfo) and message.info.src == wallet and
                not message.info.bounce and not message.info.bounced and message.init is None and
                not message.info.value.other.dict, "unexpected outgoing message")
    body = begin_cell().store_bytes(bytes.fromhex(p["body_hex"])).end_cell()
    require(payment.info.dest == recipient and payment.info.value.grams == p["amount"] and
            payment.body.hash == body.hash, "emitted payment differs from authorization")
    require(refund.info.dest == incoming.info.src and not refund.body.bits and not refund.body.refs,
            "unexpected submission refund")
    return dict(status="emitted", transaction_hash=tx_cell.hash.hex(),
                request_hash=record["request_hash"], next_sequence=p["sequence"] + 1,
                chain_time=tx.now)
