"""演示：恶意服务器伪造群成员表会被端到端验证拒绝。

不需要联网。展示三种攻击的结局：
1. 服务器往群状态里塞幽灵成员，用非成员密钥签名 → 授权检查拒绝。
2. 服务器让两名成员看到两份不同的名单 → 哈希链断开，拒绝。
3. 合法成员签署的真实拉人状态 → 通过验证。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.groups import (
    GroupStateError,
    build_add_state,
    build_genesis_state,
    verify_group_state_sig,
    verify_state_transition,
)
from src.prekeys import generate_identity


def try_verify(label: str, previous, state, signer_pub) -> None:
    try:
        verify_state_transition(previous, state)
        verify_group_state_sig(state, signer_pub)
    except GroupStateError as exc:
        print(f"[拒绝] {label}：{exc}")
    else:
        print(f"[通过] {label}")


def main() -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    carol = generate_identity("carol")
    mallory = generate_identity("mallory")

    genesis = build_genesis_state(
        alice.ik_sign_priv, "三人组", "alice", ["alice", "bob", "carol"]
    )
    try_verify("alice 创建的创世状态", None, genesis, alice.ik_sign_pub)

    # 攻击 1：服务器想悄悄把 mallory 拉进群。它没有 alice/bob/carol 的
    # 私钥，只能用 mallory 自己的密钥签名。授权规则要求签署者是上一状态
    # 的成员，因此被拒。
    forged_add = build_add_state(mallory.ik_sign_priv, genesis, "mallory", "mallory")
    try_verify(
        "服务器伪造：非成员 mallory 签名把 mallory 拉进群",
        genesis,
        forged_add,
        mallory.ik_sign_pub,
    )

    # 攻击 2：服务器给 bob 看一份「去掉 carol」的名单。签名伪造不了，
    # 但即使签名是 alice 的真签名（例如重放旧状态），成员只增不减的规则
    # 或前驱哈希也会让链断开。
    from src.groups import sign_group_state

    shrink = sign_group_state(
        alice.ik_sign_priv,
        name="三人组",
        epoch=2,
        members=["alice", "bob"],
        prev_hash=genesis.state_hash(),
        signer="alice",
    )
    try_verify("服务器伪造：用 alice 真签名删掉 carol", genesis, shrink, alice.ik_sign_pub)

    # 合法路径：bob 真实地拉 dave，签名链连续，通过。
    dave = generate_identity("dave")
    legit = build_add_state(bob.ik_sign_priv, genesis, "dave", "bob")
    try_verify("bob 合法地把 dave 拉进群", genesis, legit, bob.ik_sign_pub)

    print(
        "\n结论：服务器只能转发合法成员签署的状态，伪造的成员表在客户端"
        "验证层被拒绝；它能做到的只剩漏投（DoS），而这会通过 group_sync "
        "补链暴露。"
    )


if __name__ == "__main__":
    main()
