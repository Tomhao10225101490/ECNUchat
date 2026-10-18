"""混合 PQXDH 单元测试：SK 一致、KEM 绑定进签名、经典回退。"""

import pytest

from src.prekeys import generate_identity, generate_x25519
from src.x3dh import (
    X3DHError,
    build_initial_message,
    hkdf_pq_sk,
    hkdf_sk,
    initiator_hybrid_secret,
    initiator_secret,
    responder_hybrid_secret,
    responder_secret,
    verify_initial,
)


def _hybrid_sk_pair(with_opk: bool):
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    assert alice.pq_pub is not None and bob.pq_priv is not None
    ek_priv, ek_pub = generate_x25519()
    opk_pub = bob.opks[0].pub if with_opk else None
    opk_priv = bob.opks[0].priv if with_opk else None
    sk_a, pq_ct = initiator_hybrid_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk_pub, bob.pq_pub
    )
    sk_b = responder_hybrid_secret(
        bob.spk.priv,
        bob.ik_dh_priv,
        alice.ik_dh_pub,
        ek_pub,
        opk_priv,
        bob.pq_priv,
        pq_ct,
    )
    return sk_a, sk_b, alice, bob, ek_pub, opk_pub, pq_ct


def test_hybrid_sk_equal_with_opk() -> None:
    sk_a, sk_b, *_ = _hybrid_sk_pair(with_opk=True)
    assert len(sk_a) == 32
    assert sk_a == sk_b


def test_hybrid_sk_equal_without_opk() -> None:
    sk_a, sk_b, *_ = _hybrid_sk_pair(with_opk=False)
    assert sk_a == sk_b


def test_hybrid_sk_differs_from_classic() -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, _ = generate_x25519()
    classic = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, None
    )
    hybrid, _ = initiator_hybrid_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, None, bob.pq_pub
    )
    assert classic != hybrid
    # 域分离：相同材料经过不同 info 的输出也不撞
    assert hkdf_sk(b"\x00" * 96) != hkdf_pq_sk(b"\x00" * 96, b"\x00" * 32)


def test_initial_signature_binds_pq_ct_and_pq_pub() -> None:
    alice = generate_identity("alice")
    ek_pub = generate_x25519()[1]
    msg = build_initial_message(
        alice.ik_sign_priv,
        alice.ik_dh_pub,
        ek_pub,
        None,
        ik_pq_pub_a=alice.pq_pub,
        pq_ct=b"c" * 1088,
    )
    verify_initial(
        alice.ik_sign_pub,
        msg.ik_dh_pub,
        msg.ek_pub,
        msg.opk_pub,
        msg.signature,
        msg.ik_pq_pub,
        msg.pq_ct,
    )
    # 换一个 KEM 密文，签名必须失败：KEM 密文被身份签名绑定
    with pytest.raises(X3DHError):
        verify_initial(
            alice.ik_sign_pub,
            msg.ik_dh_pub,
            msg.ek_pub,
            msg.opk_pub,
            msg.signature,
            msg.ik_pq_pub,
            b"d" * 1088,
        )
    # 换一把 PQ 公钥同样失败：KEM 公钥被身份签名绑定
    other = generate_identity("other")
    with pytest.raises(X3DHError):
        verify_initial(
            alice.ik_sign_pub,
            msg.ik_dh_pub,
            msg.ek_pub,
            msg.opk_pub,
            msg.signature,
            other.pq_pub,
            msg.pq_ct,
        )


def test_classic_path_still_works() -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    ek_priv, ek_pub = generate_x25519()
    sk_a = initiator_secret(alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, None)
    sk_b = responder_secret(bob.spk.priv, bob.ik_dh_priv, alice.ik_dh_pub, ek_pub, None)
    assert sk_a == sk_b
