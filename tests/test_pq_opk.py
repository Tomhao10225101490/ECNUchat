"""一次性 PQ 预密钥：发放、不误消耗、签名、降级拒绝、旧库补池。"""

from __future__ import annotations

import asyncio
import json

import pytest

from src.client import ChatEngine
from src.double_ratchet import encrypt, init_sender
from src.prekeys import (
    MLKEM768_PUB_LEN,
    PQ_OPK_POOL_SIZE,
    generate_identity,
    generate_x25519,
    verify_pq_opk,
)
from src.protocol import (
    MAX_WS_MESSAGE,
    b64e,
    check_size,
    dumps,
    encode_ratchet_payload,
)
from src.store import ClientStore, ServerStore, _identity_from_json, _identity_to_json
from src.x3dh import X3DHError, build_initial_message, initiator_secret


def test_identity_roundtrip_keeps_pq_opks(tmp_path) -> None:
    alice = generate_identity("alice")
    assert len(alice.pq_opks) == PQ_OPK_POOL_SIZE
    raw = _identity_to_json(alice)
    loaded = _identity_from_json(raw)
    assert [item.pub for item in loaded.pq_opks] == [item.pub for item in alice.pq_opks]
    assert loaded.pq_opks[0].signature == alice.pq_opks[0].signature
    # 旧保险库没有这个字段时按空池加载，登录后再补。
    obj = json.loads(raw.decode())
    del obj["pq_opks"]
    legacy = _identity_from_json(json.dumps(obj).encode())
    assert legacy.pq_opks == []
    assert legacy.pq_priv == alice.pq_priv


def test_fetch_bundle_pops_pq_opk_only_when_asked(tmp_path) -> None:
    bob = generate_identity("bob")
    store = ServerStore(tmp_path / "server.db")
    store.create_user(
        "bob",
        bob.ik_sign_pub,
        bob.ik_dh_pub,
        bob.spk.pub,
        bob.spk.signature,
        bob.spk.created,
        bob.pq_pub,
        bob.pq_sig,
        [item.pub for item in bob.opks],
        [(item.pub, item.signature) for item in bob.pq_opks],
    )
    assert store.count_pq_opks("bob") == PQ_OPK_POOL_SIZE
    first = store.fetch_bundle("bob")
    assert first is not None
    assert first["pq_opk_pub"] is None
    assert store.count_pq_opks("bob") == PQ_OPK_POOL_SIZE
    used = store.fetch_bundle("bob", consume_pq_opk=True)
    assert used is not None and used["pq_opk_pub"] is not None
    verify_pq_opk(bob.ik_sign_pub, used["pq_opk_pub"], "bob", used["pq_opk_sig"])
    assert store.count_pq_opks("bob") == PQ_OPK_POOL_SIZE - 1
    again = store.fetch_bundle("bob", consume_pq_opk=True)
    assert again is not None
    assert again["pq_opk_pub"] != used["pq_opk_pub"]
    store.close()


def test_register_payload_stays_under_frame_limit() -> None:
    alice = generate_identity("alice")
    payload = {
        "type": "register",
        "username": alice.username,
        "ik_sign_pub": b64e(alice.ik_sign_pub),
        "ik_dh_pub": b64e(alice.ik_dh_pub),
        "spk_pub": b64e(alice.spk.pub),
        "spk_sig": b64e(alice.spk.signature),
        "opks": [b64e(item.pub) for item in alice.opks],
        "pq_pub": b64e(alice.pq_pub),
        "pq_sig": b64e(alice.pq_sig),
        "pq_opks": [
            {"pub": b64e(item.pub), "sig": b64e(item.signature)}
            for item in alice.pq_opks
        ],
    }
    raw = dumps(payload)
    check_size(raw)
    assert len(raw.encode("utf-8")) < MAX_WS_MESSAGE
    assert len(alice.pq_opks[0].pub) == MLKEM768_PUB_LEN


def test_server_rejects_bad_pq_opk_signature(tmp_path) -> None:
    from src.server import _decode_pq_opks

    alice = generate_identity("alice")
    bob = generate_identity("bob")
    items, err = _decode_pq_opks(
        [{"pub": b64e(bob.pq_opks[0].pub), "sig": b64e(bob.pq_opks[0].signature)}],
        alice.ik_sign_pub,
        "alice",
    )
    assert items is None
    assert err and "签名" in err


def test_old_vault_refills_pq_opks(tmp_path) -> None:
    alice = generate_identity("alice")
    alice.pq_opks.clear()
    path = tmp_path / "alice.db"
    store = ClientStore(path)
    store.create("password123", alice)
    store.close()
    engine = ChatEngine.open("alice", "password123", str(path))
    assert engine.identity.pq_opks == []
    seen: dict[str, object] = {}

    async def fake_request(obj, *_expect):
        seen["type"] = obj["type"]
        seen["count"] = len(obj.get("pq_opks") or [])
        return {"type": "upload_prekeys_ok"}

    engine.request = fake_request  # type: ignore[method-assign]
    engine.connected = True
    asyncio.run(engine._ensure_local_prekey_pools())
    assert seen["count"] == PQ_OPK_POOL_SIZE
    assert len(engine.identity.pq_opks) == PQ_OPK_POOL_SIZE
    assert engine.store.load_pending_pq_opks() == []
    engine.store.close()


def test_classic_handshake_refused_when_pq_present(tmp_path) -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, ek_pub = generate_x25519()
    opk = bob.opks[0]
    sk = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk.pub
    )
    state = init_sender(sk, bob.spk.pub, "alice", "bob")
    msg, _mk = encrypt(
        state,
        b'{"v":1,"text":"downgrade","group":null,"kind":"chat","gstate":null}',
    )
    init = build_initial_message(
        alice.ik_sign_priv, alice.ik_dh_pub, ek_pub, opk.pub
    )
    payload = encode_ratchet_payload(msg, x3dh=init)
    store = ClientStore(tmp_path / "bob.db")
    store.create("password123", bob)
    engine = ChatEngine(
        username="bob",
        password="password123",
        store=store,
        identity=bob,
        connected=True,
    )
    engine.peer_keys["alice"] = (alice.ik_sign_pub, alice.ik_dh_pub, alice.pq_pub)
    with pytest.raises(X3DHError, match="缺少 PQ"):
        asyncio.run(engine._decrypt_envelope("alice", payload))
    assert len(bob.pq_opks) == PQ_OPK_POOL_SIZE
    assert len(bob.opks) == 20
    store.close()


def test_upgrade_fetch_does_not_ask_to_consume_pq_opk(tmp_path) -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    store = ClientStore(tmp_path / "alice.db")
    store.create("password123", alice)
    engine = ChatEngine(
        username="alice",
        password="password123",
        store=store,
        identity=alice,
        connected=True,
    )
    seen: dict[str, object] = {}

    async def fake_request(obj, *_expect):
        seen.update(obj)
        return {
            "type": "bundle",
            "ik_sign_pub": b64e(bob.ik_sign_pub),
            "ik_dh_pub": b64e(bob.ik_dh_pub),
            "pq_pub": b64e(bob.pq_pub),
            "pq_sig": b64e(bob.pq_sig),
        }

    engine.request = fake_request  # type: ignore[method-assign]
    got = asyncio.run(engine._upgrade_pq_key("bob"))
    assert got == bob.pq_pub
    assert seen.get("consume_pq_opk") is not True
    store.close()
