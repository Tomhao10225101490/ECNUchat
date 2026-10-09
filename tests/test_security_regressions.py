"""安全回归：身份固定、畸形网络字段和可靠离线队列。"""

import asyncio

import pytest

from src.client import ChatEngine
from src.prekeys import generate_identity
from src.protocol import ProtocolError, b64e, decode_ratchet_payload
from src.store import ClientStore, ServerStore
from src.x3dh import X3DHError


def test_pinned_identity_cannot_be_silently_replaced(tmp_path) -> None:
    alice = generate_identity("alice")
    honest_bob = generate_identity("bob")
    impostor = generate_identity("bob")
    store = ClientStore(tmp_path / "alice.db")
    store.create("password123", alice)
    store.save_peer("bob", honest_bob.ik_sign_pub, honest_bob.ik_dh_pub)
    engine = ChatEngine(
        username="alice",
        password="password123",
        store=store,
        identity=alice,
        connected=True,
    )

    async def fake_request(_obj, *_expect):
        return {
            "type": "bundle",
            "username": "bob",
            "ik_sign_pub": b64e(impostor.ik_sign_pub),
            "ik_dh_pub": b64e(impostor.ik_dh_pub),
            "spk_pub": b64e(impostor.spk.pub),
            "spk_sig": b64e(impostor.spk.signature),
            "opk": b64e(impostor.opks[0].pub),
        }

    engine.request = fake_request  # type: ignore[method-assign]
    with pytest.raises(X3DHError, match="身份密钥发生变化"):
        asyncio.run(engine.start_session("bob"))
    assert store.load_peer("bob") == (
        honest_bob.ik_sign_pub,
        honest_bob.ik_dh_pub,
    )
    store.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("dh_pub", b64e(b"short")),
        ("nonce", b64e(b"short")),
        ("ciphertext", b64e(b"too short")),
        ("n", -1),
        ("pn", 2**32),
    ],
)
def test_malformed_ratchet_payload_rejected(field, value) -> None:
    payload = {
        "dh_pub": b64e(b"d" * 32),
        "n": 0,
        "pn": 0,
        "nonce": b64e(b"n" * 12),
        "ciphertext": b64e(b"c" * 16),
    }
    payload[field] = value
    with pytest.raises(ProtocolError):
        decode_ratchet_payload(payload)


def test_offline_queue_can_delete_only_delivered_prefix(tmp_path) -> None:
    store = ServerStore(tmp_path / "server.db")
    store.enqueue_offline("bob", "one")
    store.enqueue_offline("bob", "two")
    rows = store.list_offline("bob")
    assert [payload for _, payload in rows] == ["one", "two"]
    store.delete_offline(rows[0][0])
    assert [payload for _, payload in store.list_offline("bob")] == ["two"]
    store.close()
