"""答辩演示：三篇论文各自对上哪段代码，以及仍然不能说满的边界。

不需要联网。打印的每一行都能在源码里指出来。

1. Fiedler、Günther，PKC 2025：握手优先用一次性 ML-KEM 预密钥。
   用过的私钥删掉之后，长期 PQK 解不开这次握手。
2. 同一篇：服务器可以扣留下一次性钥，迫使封装落到签过名的长期 PQK；
   但不能把 KEM 整个拿掉。拿掉之后接收方拒绝。
3. Bienstock 等，CRYPTO 2022：乱序消息仍能立即解密；发送棘轮私钥
   dhs_priv 还留在窗口里，这不是 Triple Ratchet。
4. Rösler、Mainka、Schwenk，EuroS&P 2018：非成员签的群状态进不了链。
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mlkem

from src.double_ratchet import (
    GCMError,
    decrypt,
    encrypt,
    init_receiver,
    init_sender,
)
from src.groups import (
    GroupStateError,
    build_add_state,
    build_genesis_state,
    verify_group_state_sig,
    verify_state_transition,
)
from src.prekeys import (
    clear_mlkem_cache,
    decapsulate_mlkem,
    encapsulate_mlkem,
    generate_identity,
    generate_x25519,
    verify_pq,
)
from src.x3dh import (
    initiator_hybrid_secret,
    initiator_secret,
    responder_hybrid_secret,
)


def section(title: str) -> None:
    print()
    print(f"== {title}")


def main() -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    assert alice.pq_pub and bob.pq_pub and bob.pq_priv
    pqopk = bob.pq_opks[0]
    ek_priv, ek_pub = generate_x25519()

    section("PKC 2025：一次性封装公钥，用完即删")
    sk_a, pq_ct = initiator_hybrid_secret(
        alice.ik_dh_priv,
        ek_priv,
        bob.spk.pub,
        bob.ik_dh_pub,
        None,
        pqopk.pub,
    )
    sk_b = responder_hybrid_secret(
        bob.spk.priv,
        bob.ik_dh_priv,
        alice.ik_dh_pub,
        ek_pub,
        None,
        pqopk.priv,
        pq_ct,
        pqopk.pub,
    )
    print(f"一次性 PQOPK 握手，双方 SK 一致：{sk_a == sk_b}，SK 前 8 字节 {sk_a[:8].hex()}")
    try:
        verify_pq(bob.ik_sign_pub, pqopk.pub, "bob", pqopk.signature)
    except InvalidSignature:
        print("一次性公钥的签名带前缀 pq-opk-v1，不能拿去冒充长期 PQK。")
    bob.take_pq_opk(pqopk.pub)
    print(f"首条认证成功后删除该私钥，池中剩余 {len(bob.pq_opks)} 把。")
    sk_later = responder_hybrid_secret(
        bob.spk.priv,
        bob.ik_dh_priv,
        alice.ik_dh_pub,
        ek_pub,
        None,
        bob.pq_priv,
        pq_ct,
        pqopk.pub,
    )
    print(f"事后只剩长期 PQK 时，SK 已经对不上：{sk_later != sk_a}")
    sender = init_sender(
        sk_a, bob.spk.pub, "alice", "bob", remote_pq_pk=bob.pq_pub, handshake_pq="pqopk"
    )
    message, mk = encrypt(sender, "这条握手不靠长期封装私钥".encode())
    del mk
    wrong = init_receiver(
        sk_later,
        bob.spk.priv,
        message.header.dh_pub,
        "bob",
        "alice",
        remote_pq_pk=alice.pq_pub,
        pq_ct=message.pq_ct,
        local_pq_priv=bob.pq_priv,
    )
    try:
        decrypt(wrong, message, pq_priv=bob.pq_priv)
    except GCMError:
        print("用长期私钥解出来的共享秘密进不了 GCM。密文保持关闭。")
    else:
        raise SystemExit("长期私钥不应解开一次性握手")

    section("PKC 2025：扣留一次性钥只能落到最后手段，不能拿掉 KEM")
    ek2_priv, ek2_pub = generate_x25519()
    last_a, last_ct = initiator_hybrid_secret(
        alice.ik_dh_priv,
        ek2_priv,
        bob.spk.pub,
        bob.ik_dh_pub,
        None,
        bob.pq_pub,
    )
    last_b = responder_hybrid_secret(
        bob.spk.priv,
        bob.ik_dh_priv,
        alice.ik_dh_pub,
        ek2_pub,
        None,
        bob.pq_priv,
        last_ct,
        bob.pq_pub,
    )
    print(f"没有 PQOPK 时，双方用签过名的长期 PQK，SK 一致：{last_a == last_b}")
    classic = initiator_secret(
        alice.ik_dh_priv, ek2_priv, bob.spk.pub, bob.ik_dh_pub, None
    )
    print(f"拿掉 KEM 之后的经典 SK 与混合 SK 不同：{classic != last_a}")
    print("接收方本机持有 PQK 时，没有 PQ 的初始消息会在客户端被拒绝，不会静默降级。")

    section("CRYPTO 2022：立即解密还在；dhs_priv 窗口也还在")
    chain_a = init_sender(sk_a, bob.spk.pub, "alice", "bob")
    first, _ = encrypt(chain_a, b"n0")
    chain_b = init_receiver(
        sk_a, bob.spk.priv, first.header.dh_pub, "bob", "alice"
    )
    assert decrypt(chain_b, first)[0] == b"n0"
    pending = [encrypt(chain_a, f"n{i}".encode())[0] for i in range(1, 4)]
    assert decrypt(chain_b, pending[2])[0] == b"n3"
    assert decrypt(chain_b, pending[0])[0] == b"n1"
    print("先收到 n=3，再补 n=1，两条都解开。这是 _skip_message_keys 的立即解密。")
    print(
        f"发送棘轮私钥仍在状态里：dhs_priv 长度 {len(sender.dhs_priv or b'')} 字节。"
        "这不是 Triple Ratchet，窗口要主动说出来。"
    )

    section("EuroS&P 2018：逐人棘轮之外，幽灵成员签不进群状态")
    mallory = generate_identity("mallory")
    genesis = build_genesis_state(
        alice.ik_sign_priv, "课程组", "alice", ["alice", "bob", "carol"]
    )
    verify_state_transition(None, genesis)
    verify_group_state_sig(genesis, alice.ik_sign_pub)
    print("创建者签名的创世状态通过。群正文仍是每人一封双棘轮，不是 Sender Keys。")
    forged = build_add_state(mallory.ik_sign_priv, genesis, "mallory", "mallory")
    try:
        verify_state_transition(genesis, forged)
        verify_group_state_sig(forged, mallory.ik_sign_pub)
    except GroupStateError as exc:
        print(f"非成员 mallory 签名拉自己进群：拒绝（{exc}）")
    else:
        raise SystemExit("伪造群状态不应通过")

    section("速度：同一把长期 PQK 不再每次重建私钥对象")
    assert bob.pq_pub is not None and bob.pq_priv is not None
    _ss, ct = encapsulate_mlkem(bob.pq_pub)
    rounds = 40
    clear_mlkem_cache()
    started = time.perf_counter()
    for _ in range(rounds):
        mlkem.MLKEM768PrivateKey.from_seed_bytes(bob.pq_priv).decapsulate(ct)
    cold = time.perf_counter() - started
    decapsulate_mlkem(bob.pq_priv, ct)
    started = time.perf_counter()
    for _ in range(rounds):
        decapsulate_mlkem(bob.pq_priv, ct)
    warm = time.perf_counter() - started
    print(
        f"解封 {rounds} 次：每次重建 {cold / rounds * 1e6:.0f} 微秒，"
        f"缓存对象后 {warm / rounds * 1e6:.0f} 微秒。"
    )
    print("缓存只省对象重建。它不改变 ss，也不把长期 PQK 变成一次性钥。")

    section("答辩时仍要主动说的边界")
    print("没有在本仓库上重跑 UC 证明或 PKC 2025 的安全界。")
    print("没有 Kyber，用的是 ML-KEM-768。没有 XEdDSA。指纹仍只覆盖 IK_sign。")
    print("混合棘轮每次换链封装的是长期 PQK。这把长期私钥泄露后，棘轮退回经典 DH。")
    print("服务器扣留 PQOPK 时，握手会落到这把长期钥，客户端把会话标成 pqk。")
    print("没有头加密，没有密封发送者，没有群签名，也不是 MLS。")


if __name__ == "__main__":
    main()
