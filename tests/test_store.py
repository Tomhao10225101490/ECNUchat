"""口令解开本地加密 blob 后，棘轮状态可以接着用。"""

from src.double_ratchet import decrypt, encrypt, init_receiver, init_sender
from src.prekeys import generate_identity, generate_x25519
from src.store import ClientStore
from src.x3dh import initiator_secret, responder_secret


def test_password_unlocks_ratchet_and_continues(tmp_path) -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, ek_pub = generate_x25519()
    opk = bob.opks[0]
    sk = initiator_secret(alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk.pub)
    assert sk == responder_secret(
        bob.spk.priv, bob.ik_dh_priv, alice.ik_dh_pub, ek_pub, opk.priv
    )
    a = init_sender(sk, bob.spk.pub, "alice", "bob")
    first, _ = encrypt(a, "重启前".encode())
    bstate = init_receiver(sk, bob.spk.priv, first.header.dh_pub, "bob", "alice")
    assert decrypt(bstate, first)[0] == "重启前".encode()

    path = tmp_path / "bob.db"
    store = ClientStore(path)
    store.create("password123", bob)
    store.save_session("alice", bstate)
    store.close()

    store2 = ClientStore(path)
    again = store2.unlock("password123")
    assert again.ik_sign_pub == bob.ik_sign_pub
    loaded = store2.load_session("alice")
    assert loaded is not None
    second, _ = encrypt(a, "重启后继续".encode())
    assert decrypt(loaded, second)[0] == "重启后继续".encode()
    store2.close()


def test_session_and_outbox_commit_together(tmp_path) -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, _ = generate_x25519()
    sk = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, None
    )
    state = init_sender(sk, bob.spk.pub, "alice", "bob")
    path = tmp_path / "alice.db"
    store = ClientStore(path)
    store.create("password123", alice)
    payload = {"ciphertext": "same-envelope", "x3dh": {"signature": "kept"}}
    store.save_session_with_outbox("bob", state, payload)
    store.close()

    reopened = ClientStore(path)
    reopened.unlock("password123")
    assert reopened.load_session("bob") is not None
    assert reopened.load_outbox("bob") == payload
    reopened.delete_outbox("bob")
    assert reopened.load_outbox("bob") is None
    reopened.save_unread({"dm:bob": 3, "group:test": 120})
    assert reopened.load_unread() == {"dm:bob": 3, "group:test": 120}
    reopened.save_pending_prekeys([b"a" * 32, b"b" * 32])
    assert reopened.load_pending_prekeys() == [b"a" * 32, b"b" * 32]
    reopened.clear_pending_prekeys()
    assert reopened.load_pending_prekeys() == []
    reopened.close()
