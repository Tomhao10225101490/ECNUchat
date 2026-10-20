"""混合棘轮：每条新链混入 PQ 封装、降级拒绝、旧会话自动迁移。"""

import pytest

from src.double_ratchet import (
    GCMError,
    Header,
    RatchetError,
    RatchetMessage,
    decrypt,
    encrypt,
    init_receiver,
    init_sender,
)
from src.prekeys import generate_identity, generate_x25519
from src.x3dh import (
    initiator_hybrid_secret,
    initiator_secret,
    responder_hybrid_secret,
)


def _hybrid_bootstrap():
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, ek_pub = generate_x25519()
    opk = bob.opks[0]
    sk, handshake_ct = initiator_hybrid_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk.pub, bob.pq_pub
    )
    assert sk == responder_hybrid_secret(
        bob.spk.priv,
        bob.ik_dh_priv,
        alice.ik_dh_pub,
        ek_pub,
        opk.priv,
        bob.pq_priv,
        handshake_ct,
    )
    a = init_sender(sk, bob.spk.pub, "alice", "bob", remote_pq_pk=bob.pq_pub)
    first, _ = encrypt(a, b"hello-0")
    assert first.pq_ct is not None  # 第一条链就混入 PQ
    b = init_receiver(
        sk,
        bob.spk.priv,
        first.header.dh_pub,
        "bob",
        "alice",
        remote_pq_pk=alice.pq_pub,
        pq_ct=first.pq_ct,
        local_pq_priv=bob.pq_priv,
    )
    assert decrypt(b, first, pq_priv=bob.pq_priv)[0] == b"hello-0"
    return a, b, alice, bob


def test_hybrid_roundtrip_both_directions() -> None:
    a, b, alice, bob = _hybrid_bootstrap()
    m1, _ = encrypt(a, b"alice-1")
    assert m1.pq_ct is not None
    assert decrypt(b, m1, pq_priv=bob.pq_priv)[0] == b"alice-1"

    reply, _ = encrypt(b, b"bob-1")
    assert reply.pq_ct is not None
    assert b.dh_ratchet_count == 2
    assert decrypt(a, reply, pq_priv=alice.pq_priv)[0] == b"bob-1"

    again, _ = encrypt(a, b"alice-2")
    assert decrypt(b, again, pq_priv=bob.pq_priv)[0] == b"alice-2"


def test_missing_pq_on_new_chain_rejected() -> None:
    a, b, alice, bob = _hybrid_bootstrap()
    reply, _ = encrypt(b, b"bob-1")
    stripped = RatchetMessage(
        header=reply.header,
        nonce=reply.nonce,
        ciphertext=reply.ciphertext,
        pq_ct=None,
    )
    with pytest.raises(RatchetError, match="PQ"):
        decrypt(a, stripped, pq_priv=alice.pq_priv)


def test_tampered_pq_ct_fails_cleanly() -> None:
    a, b, alice, bob = _hybrid_bootstrap()
    reply, _ = encrypt(b, b"bob-1")
    bad = RatchetMessage(
        header=reply.header,
        nonce=reply.nonce,
        ciphertext=reply.ciphertext,
        pq_ct=bytes(reply.pq_ct[0] ^ 0x01) + reply.pq_ct[1:],
    )
    with pytest.raises((GCMError, RatchetError)):
        decrypt(a, bad, pq_priv=alice.pq_priv)


def test_legacy_session_migrates_to_hybrid_on_reply() -> None:
    """旧库会话：先把 remote_pq_pk 补上（等价于 _upgrade_pq_key），
    下一次换链起混入 PQ；升级前的消息仍是经典链，不受影响。"""
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, ek_pub = generate_x25519()
    opk = bob.opks[0]
    sk = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk.pub
    )
    a = init_sender(sk, bob.spk.pub, "alice", "bob")
    first, _ = encrypt(a, b"legacy-0")
    assert first.pq_ct is None
    b = init_receiver(sk, bob.spk.priv, first.header.dh_pub, "bob", "alice")
    assert decrypt(b, first)[0] == b"legacy-0"

    # 迁移：双方补上对端 PQK 公钥
    a.remote_pq_pk = bob.pq_pub
    b.remote_pq_pk = alice.pq_pub

    legacy_tail, _ = encrypt(a, b"legacy-1")
    assert legacy_tail.pq_ct is None  # 旧链照旧
    assert decrypt(b, legacy_tail)[0] == b"legacy-1"

    reply, _ = encrypt(b, b"post-migration")
    assert reply.pq_ct is not None  # 迁移后的第一条回复已混入 PQ
    assert decrypt(a, reply, pq_priv=alice.pq_priv)[0] == b"post-migration"


def test_pq_state_survives_store_roundtrip(tmp_path) -> None:
    from src.store import ClientStore

    a, b, alice, bob = _hybrid_bootstrap()
    m1, _ = encrypt(a, b"persist-me")
    store = ClientStore(tmp_path / "bob.db")
    store.create("password123", bob)
    store.save_session("alice", b)
    store.close()

    reopened = ClientStore(tmp_path / "bob.db")
    reopened.unlock("password123")
    loaded = reopened.load_session("alice")
    assert loaded is not None
    assert loaded.remote_pq_pk == alice.pq_pub
    assert decrypt(loaded, m1, pq_priv=bob.pq_priv)[0] == b"persist-me"
    reopened.close()


def test_engine_upgrades_legacy_session_before_send(tmp_path) -> None:
    """旧库里的经典会话在下次发送前自动补拉 PQK 并升级为混合棘轮。"""
    import asyncio

    from src.client import ChatEngine
    from src.protocol import b64e
    from src.store import ClientStore

    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, _ = generate_x25519()
    sk = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, None
    )
    state = init_sender(sk, bob.spk.pub, "alice", "bob")
    assert state.remote_pq_pk is None

    store = ClientStore(tmp_path / "alice.db")
    store.create("password123", alice)
    store.save_session("bob", state)
    engine = ChatEngine(
        username="alice",
        password="password123",
        store=store,
        identity=alice,
        connected=True,
    )
    engine.sessions["bob"] = state

    async def fake_request(obj, *_expect):
        assert obj["type"] == "fetch_bundle"
        return {
            "type": "bundle",
            "username": "bob",
            "ik_sign_pub": b64e(bob.ik_sign_pub),
            "ik_dh_pub": b64e(bob.ik_dh_pub),
            "spk_pub": b64e(bob.spk.pub),
            "spk_sig": b64e(bob.spk.signature),
            "opk": None,
            "pq_pub": b64e(bob.pq_pub),
            "pq_sig": b64e(bob.pq_sig),
        }

    engine.request = fake_request  # type: ignore[method-assign]
    upgraded = asyncio.run(engine._ensure_session_for_send("bob"))
    assert upgraded.remote_pq_pk == bob.pq_pub
    # 当前发送链是升级前就派生的经典链，这条链上的消息照旧不带 PQ。
    first, _ = encrypt(upgraded, b"first-after-migration")
    assert first.pq_ct is None

    bstate = init_receiver(
        sk,
        bob.spk.priv,
        first.header.dh_pub,
        "bob",
        "alice",
        remote_pq_pk=alice.pq_pub,
    )
    assert decrypt(bstate, first, pq_priv=bob.pq_priv)[0] == b"first-after-migration"
    # 升级后的第一次回复换链，必须混入 PQ 封装。
    reply, _ = encrypt(bstate, b"reply")
    assert reply.pq_ct is not None
    assert decrypt(upgraded, reply, pq_priv=alice.pq_priv)[0] == b"reply"
    store.close()
