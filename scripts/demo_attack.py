"""演示：不核对指纹时，服务器可以在发 bundle 时换掉公钥做中间人。

核对指纹之后，服务器只能转发——它没有私钥，解不开 AES-256-GCM。
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import PROJECT_NAME
from src.prekeys import generate_identity, generate_x25519, verify_spk
from src.protocol import fingerprint
from src.x3dh import initiator_secret, responder_secret


def main() -> None:
    print(PROJECT_NAME)
    print("中间人演示（只在内存里换公钥，不连网）")
    print()

    alice = generate_identity("alice")
    bob = generate_identity("bob")
    mallory = generate_identity("mallory")

    print("Bob 真实 IK_sign 指纹：")
    print(" ", fingerprint(bob.ik_sign_pub))
    print("Mallory 的 IK_sign 指纹：")
    print(" ", fingerprint(mallory.ik_sign_pub))
    print()
    if fingerprint(bob.ik_sign_pub) == fingerprint(mallory.ik_sign_pub):
        raise SystemExit("指纹不应相同")
    print("不核对指纹时，Alice 不会发现 bundle 里的公钥已被替换。")
    print()

    # 诚实路径
    ek_priv, ek_pub = generate_x25519()
    opk = bob.opks[0]
    sk_honest_a = initiator_secret(
        alice.ik_dh_priv, ek_priv, bob.spk.pub, bob.ik_dh_pub, opk.pub
    )
    sk_honest_b = responder_secret(
        bob.spk.priv, bob.ik_dh_priv, alice.ik_dh_pub, ek_pub, opk.priv
    )
    print("诚实 bundle：Alice 与 Bob 的 SK 是否相同:", sk_honest_a == sk_honest_b)

    # 服务器把 Bob 的 IK_dh / SPK / OPK 换成 Mallory 的，但对外仍声称是 Bob
    verify_spk(mallory.ik_sign_pub, mallory.spk.pub, "mallory", mallory.spk.signature)
    poisoned_ek_priv, poisoned_ek_pub = generate_x25519()
    mopk = mallory.opks[0]
    sk_alice_mitm = initiator_secret(
        alice.ik_dh_priv,
        poisoned_ek_priv,
        mallory.spk.pub,
        mallory.ik_dh_pub,
        mopk.pub,
    )
    sk_bob_real = responder_secret(
        bob.spk.priv,
        bob.ik_dh_priv,
        alice.ik_dh_pub,
        poisoned_ek_pub,
        opk.priv,
    )
    print("被掉包后：Alice 算出的 SK 与真实 Bob 是否相同:", sk_alice_mitm == sk_bob_real)
    print("被掉包后：Alice 的 SK 是否等于 Mallory 重算的 SK:", sk_alice_mitm == responder_secret(
        mallory.spk.priv,
        mallory.ik_dh_priv,
        alice.ik_dh_pub,
        poisoned_ek_pub,
        mopk.priv,
    ))
    print()
    print("结论：")
    print("1. 不核对手动比对的 IK_sign 指纹时，服务器可以在 fetch_bundle 时换公钥，")
    print("   与 Alice 完成 X3DH，再与 Bob 另建一条，成为中间人。")
    print("2. 双方用安全渠道核对指纹后，服务器再换公钥会被发现；此后它只能转发")
    print("   base64 信封，没有 MK，AES-256-GCM 解不开，改一个字节也会校验失败。")


if __name__ == "__main__":
    main()
