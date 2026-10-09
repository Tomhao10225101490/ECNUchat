"""双棘轮内存单测：往返明文、MK 变化、DH 代数、乱序、重放、GCM、跳过上限。"""

import pytest

from src.double_ratchet import (
    GCMError,
    Header,
    RatchetMessage,
    ReplayError,
    SkipLimitError,
    decrypt,
    encrypt,
    init_receiver,
    init_sender,
)
from src.prekeys import generate_identity, generate_x25519
from src.x3dh import initiator_secret, responder_secret


def _bootstrap():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, ek_pub = generate_x25519()
    opk = bob.opks[0]
    sk = initiator_secret(alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk.pub)
    assert sk == responder_secret(
        bob.spk.priv, bob.ik_dh_priv, alice.ik_dh_pub, ek_pub, opk.priv
    )
    a = init_sender(sk, bob.spk.pub, "alice", "bob")
    first, _ = encrypt(a, b"hello-0")
    b = init_receiver(sk, bob.spk.priv, first.header.dh_pub, "bob", "alice")
    pt, _ = decrypt(b, first)
    assert pt == b"hello-0"
    return a, b


def test_roundtrip_three_each_way() -> None:
    a, b = _bootstrap()
    # bootstrap 已消耗 alice 的第 0 条。再各发满 3 条往返。
    sent_ab = []
    for i in range(3):
        msg, _ = encrypt(a, f"alice-{i}".encode())
        sent_ab.append(msg)
    for i, msg in enumerate(sent_ab):
        pt, _ = decrypt(b, msg)
        assert pt == f"alice-{i}".encode()

    sent_ba = []
    for i in range(3):
        msg, _ = encrypt(b, f"bob-{i}".encode())
        sent_ba.append(msg)
    for i, msg in enumerate(sent_ba):
        pt, _ = decrypt(a, msg)
        assert pt == f"bob-{i}".encode()


def test_same_dh_pub_two_messages_different_mk() -> None:
    a, b = _bootstrap()
    m1, mk1 = encrypt(a, b"one")
    m2, mk2 = encrypt(a, b"two")
    assert m1.header.dh_pub == m2.header.dh_pub
    assert mk1 != mk2
    assert decrypt(b, m1)[0] == b"one"
    assert decrypt(b, m2)[0] == b"two"


def test_dh_ratchet_increments_after_reply_and_mk_changes() -> None:
    a, b = _bootstrap()
    assert a.dh_ratchet_count == 1
    assert b.dh_ratchet_count == 1
    before_pub = a.dhs_pub
    msg_before, mk_before = encrypt(a, b"before-reply")
    decrypt(b, msg_before)

    gen_b_before_reply = b.dh_ratchet_count
    reply, mk_reply = encrypt(b, b"first-reply")
    assert b.dh_ratchet_count == gen_b_before_reply + 1
    assert b.dh_ratchet_count == 2
    assert reply.header.dh_pub != before_pub
    assert mk_reply != mk_before

    gen_a_before = a.dh_ratchet_count
    pt, _ = decrypt(a, reply)
    assert pt == b"first-reply"
    assert a.dh_ratchet_count == gen_a_before + 1

    after, mk_after = encrypt(a, b"after-reply")
    assert after.header.dh_pub != before_pub
    assert mk_after != mk_before
    assert decrypt(b, after)[0] == b"after-reply"


def test_out_of_order_still_decrypts() -> None:
    a, b = _bootstrap()
    messages = []
    plains = [b"m0", b"m1", b"m2"]
    for p in plains:
        messages.append(encrypt(a, p)[0])
    # 先到最后一条，再补前面
    assert decrypt(b, messages[2])[0] == b"m2"
    assert decrypt(b, messages[0])[0] == b"m0"
    assert decrypt(b, messages[1])[0] == b"m1"


def test_late_old_chain_message_uses_pn_cache_after_dh_ratchet() -> None:
    a, b = _bootstrap()
    old_late, _ = encrypt(a, b"old-chain-late")

    reply, _ = encrypt(b, b"reply-starts-new-chain")
    assert decrypt(a, reply)[0] == b"reply-starts-new-chain"

    new_chain, _ = encrypt(a, b"new-chain-first")
    assert decrypt(b, new_chain)[0] == b"new-chain-first"
    assert old_late.header.dh_pub in b.retired_dh
    assert decrypt(b, old_late)[0] == b"old-chain-late"


def test_replay_rejected() -> None:
    a, b = _bootstrap()
    msg, _ = encrypt(a, b"once")
    assert decrypt(b, msg)[0] == b"once"
    with pytest.raises(ReplayError):
        decrypt(b, msg)


def test_gcm_fails_on_flipped_byte() -> None:
    a, b = _bootstrap()
    msg, _ = encrypt(a, b"tamper")
    before = b.to_record()
    flipped = bytearray(msg.ciphertext)
    flipped[0] ^= 0x01
    bad = RatchetMessage(
        header=msg.header, nonce=msg.nonce, ciphertext=bytes(flipped)
    )
    with pytest.raises(GCMError):
        decrypt(b, bad)
    assert b.to_record() == before
    assert decrypt(b, msg)[0] == b"tamper"


def test_forged_new_dh_header_does_not_advance_state() -> None:
    a, b = _bootstrap()
    reply, _ = encrypt(b, b"reply")
    assert decrypt(a, reply)[0] == b"reply"
    legitimate, _ = encrypt(a, b"after-ratchet")
    before = b.to_record()
    forged = RatchetMessage(
        header=Header(
            dh_pub=legitimate.header.dh_pub,
            n=legitimate.header.n,
            pn=legitimate.header.pn,
        ),
        nonce=legitimate.nonce,
        ciphertext=legitimate.ciphertext[:-1] + bytes([legitimate.ciphertext[-1] ^ 1]),
    )
    with pytest.raises(GCMError):
        decrypt(b, forged)
    assert b.to_record() == before
    assert decrypt(b, legitimate)[0] == b"after-ratchet"


def test_skip_more_than_40_rejected() -> None:
    a, b = _bootstrap()
    # bootstrap 已消费 n=0，nr=1。再发到 n=42 时中间要跳过 41 把 MK。
    last = None
    for i in range(42):
        last, _ = encrypt(a, f"x{i}".encode())
    assert last is not None
    assert last.header.n == 42
    with pytest.raises(SkipLimitError):
        decrypt(b, last)


def test_skip_exactly_40_then_decrypt() -> None:
    a, b = _bootstrap()
    kept = None
    for i in range(41):
        kept, _ = encrypt(a, f"y{i}".encode())
    assert kept is not None
    assert kept.header.n == 41
    assert decrypt(b, kept)[0] == b"y40"
