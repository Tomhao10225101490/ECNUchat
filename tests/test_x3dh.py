"""X3DH 内存单测：双方 SK 必须完全一致，覆盖有 OPK / 无 OPK。"""

from cryptography.exceptions import InvalidSignature

from src.prekeys import generate_ed25519, generate_identity, generate_x25519, verify_spk
from src.x3dh import (
    X3DHError,
    build_initial_message,
    initiator_secret,
    responder_secret,
    verify_initial,
)


def _sk_pair(with_opk: bool) -> tuple[bytes, bytes]:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, ek_pub = generate_x25519()
    opk_pub = bob.opks[0].pub if with_opk else None
    opk_priv = bob.opks[0].priv if with_opk else None
    sk_a = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk_pub
    )
    sk_b = responder_secret(
        bob.spk.priv, bob.ik_dh_priv, alice.ik_dh_pub, ek_pub, opk_priv
    )
    return sk_a, sk_b


def test_both_sides_sk_equal_with_opk() -> None:
    sk_a, sk_b = _sk_pair(with_opk=True)
    assert len(sk_a) == 32
    assert sk_a == sk_b


def test_both_sides_sk_equal_without_opk() -> None:
    sk_a, sk_b = _sk_pair(with_opk=False)
    assert len(sk_a) == 32
    assert sk_a == sk_b


def test_with_and_without_opk_produce_different_sk() -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, _ = generate_x25519()
    sk_no = initiator_secret(alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, None)
    sk_yes = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, bob.opks[0].pub
    )
    assert sk_no != sk_yes


def test_spk_signature_binds_username() -> None:
    bob = generate_identity("bob")
    verify_spk(bob.ik_sign_pub, bob.spk.pub, "bob", bob.spk.signature)
    try:
        verify_spk(bob.ik_sign_pub, bob.spk.pub, "mallory", bob.spk.signature)
    except InvalidSignature:
        return
    raise AssertionError("错误用户名的 SPK 签名应当失败")


def test_initial_message_signature() -> None:
    alice = generate_identity("alice")
    _, ek_pub = generate_x25519()
    opk_pub = generate_x25519()[1]
    msg = build_initial_message(alice.ik_sign_priv, alice.ik_dh_pub, ek_pub, opk_pub)
    verify_initial(alice.ik_sign_pub, msg.ik_dh_pub, msg.ek_pub, msg.opk_pub, msg.signature)
    other = generate_ed25519()[1]
    try:
        verify_initial(other, msg.ik_dh_pub, msg.ek_pub, msg.opk_pub, msg.signature)
    except X3DHError:
        return
    raise AssertionError("错误身份公钥应当验签失败")
