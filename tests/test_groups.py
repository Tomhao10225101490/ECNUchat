"""带签名群状态的单元测试：创世、加人、伪造与重放拒绝。"""

import pytest

from src.groups import (
    GENESIS_PREV_HASH,
    GroupStateError,
    build_add_state,
    build_genesis_state,
    verify_group_state_sig,
    verify_state_transition,
)
from src.prekeys import generate_identity


def _genesis(creator):
    return build_genesis_state(
        creator.ik_sign_priv, "三人组", creator.username, ["alice", "bob", "carol"]
    )


def test_genesis_state_self_consistent() -> None:
    alice = generate_identity("alice")
    state = _genesis(alice)
    assert state.epoch == 1
    assert state.prev_hash == GENESIS_PREV_HASH
    assert state.signer == "alice"
    verify_state_transition(None, state)
    verify_group_state_sig(state, alice.ik_sign_pub)


def test_genesis_signature_binds_members() -> None:
    alice = generate_identity("alice")
    state = _genesis(alice)
    # 改成加了幽灵成员的名单，签名必须对不上
    forged = build_genesis_state(
        generate_identity("mallory").ik_sign_priv,
        "三人组",
        "mallory",
        ["alice", "bob", "carol", "mallory"],
    )
    with pytest.raises(GroupStateError):
        verify_group_state_sig(forged, alice.ik_sign_pub)
    # 用错误密钥验合法状态也必须失败
    with pytest.raises(GroupStateError):
        verify_group_state_sig(state, generate_identity("mallory").ik_sign_pub)


def test_add_links_epoch_and_prev_hash() -> None:
    alice = generate_identity("alice")
    bob = generate_identity("bob")
    genesis = _genesis(alice)
    added = build_add_state(bob.ik_sign_priv, genesis, "dave", "bob")
    assert added.epoch == 2
    assert added.prev_hash == genesis.state_hash()
    assert set(added.members) == {"alice", "bob", "carol", "dave"}
    verify_state_transition(genesis, added)
    verify_group_state_sig(added, bob.ik_sign_pub)


def test_add_by_non_member_rejected() -> None:
    alice = generate_identity("alice")
    mallory = generate_identity("mallory")
    genesis = _genesis(alice)
    forged = build_add_state(mallory.ik_sign_priv, genesis, "mallory", "mallory")
    with pytest.raises(GroupStateError, match="上一状态的成员"):
        verify_state_transition(genesis, forged)


def test_epoch_gap_rejected() -> None:
    alice = generate_identity("alice")
    genesis = _genesis(alice)
    from src.groups import sign_group_state

    jumped = sign_group_state(
        alice.ik_sign_priv,
        name="三人组",
        epoch=3,
        members=["alice", "bob", "carol"],
        prev_hash=genesis.state_hash(),
        signer="alice",
    )
    with pytest.raises(GroupStateError, match="连续递增"):
        verify_state_transition(genesis, jumped)


def test_prev_hash_tamper_rejected() -> None:
    alice = generate_identity("alice")
    genesis = _genesis(alice)
    from src.groups import sign_group_state

    wrong_link = sign_group_state(
        alice.ik_sign_priv,
        name="三人组",
        epoch=2,
        members=["alice", "bob", "carol"],
        prev_hash=b"\x00" * 32,
        signer="alice",
    )
    with pytest.raises(GroupStateError, match="前驱哈希"):
        verify_state_transition(genesis, wrong_link)


def test_member_removal_rejected() -> None:
    alice = generate_identity("alice")
    genesis = _genesis(alice)
    from src.groups import sign_group_state

    shrink = sign_group_state(
        alice.ik_sign_priv,
        name="三人组",
        epoch=2,
        members=["alice", "bob"],
        prev_hash=genesis.state_hash(),
        signer="alice",
    )
    with pytest.raises(GroupStateError, match="只增不减"):
        verify_state_transition(genesis, shrink)
