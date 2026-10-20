"""带签名、哈希链接的群状态：端到端的群成员一致性。

背景：EuroS&P 2018（Rösler、Mainka、Schwenk，*More is Less*）指出
Signal / WhatsApp 当年的群管理没有端到端保护。本仓库此前的实现把成员表
记在服务器上（`group_create` / `group_add` 直接改服务器状态），一个恶意
服务器可以往群里塞幽灵成员，或让两个成员看到不同的名单。

本模块把成员名单改成「群状态」：每条状态是一份由合法成员签署的完整名单，
并通过 prev_hash 链接成链。服务器只能追加转发，不能伪造：

- 创世状态（epoch=1）必须由创建者签署，签名绑定群名、创建者、成员表和
  空的前驱哈希。
- 后续状态（epoch=k+1）必须由上一状态的一名成员签署，成员表相对上一
  状态最多新增一人，前驱哈希必须指向上一状态。
- 消息绑定：群消息的密文里带 gstate = 当前群状态的 SHA-256，接收方只
  接受「该状态在已验证链上、且发送者在该状态成员表里」的消息。

这样恶意服务器能做到的只剩拒绝转发（DoS）或漏投状态（客户端通过
group_sync 补链发现）；它无法凭空加入成员，也无法让成员之间对名单产生
分歧而不被察觉。未覆盖的部分照旧：成员没有「同意入群」的端到端协商，
这是邀请式成员制，不是 MLS。

本模块只做字节进、字节出，不 import 网络或数据库。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

GROUP_STATE_DOMAIN = b"group-state-v1\x00"
GENESIS_PREV_HASH = b""


class GroupStateError(Exception):
    """群状态验签、链接或成员规则失败。"""


def canonical_group_state(
    name: str,
    epoch: int,
    members: list[str],
    prev_hash: bytes,
    signer: str,
) -> bytes:
    """规范字节：域名 || 群名 || epoch(4B BE) || 签署者 || 成员… || prev_hash。

    成员先排序去重，因此同一状态只有一种字节表示。签名覆盖这些字节，
    前驱哈希也由这些字节的 SHA-256 定义，天然形成哈希链。
    """
    ordered = sorted(dict.fromkeys(members))
    parts = [
        GROUP_STATE_DOMAIN,
        name.encode("utf-8") + b"\x00",
        epoch.to_bytes(4, "big"),
        signer.encode("utf-8") + b"\x00",
    ]
    for member in ordered:
        parts.append(member.encode("utf-8") + b"\x00")
    parts.append(prev_hash)
    return b"".join(parts)


def group_state_hash(
    name: str,
    epoch: int,
    members: list[str],
    prev_hash: bytes,
    signer: str,
) -> bytes:
    return hashlib.sha256(
        canonical_group_state(name, epoch, members, prev_hash, signer)
    ).digest()


@dataclass(frozen=True)
class GroupState:
    name: str
    epoch: int
    members: tuple[str, ...]
    prev_hash: bytes
    signer: str
    signature: bytes

    def canonical(self) -> bytes:
        return canonical_group_state(
            self.name, self.epoch, list(self.members), self.prev_hash, self.signer
        )

    def state_hash(self) -> bytes:
        return hashlib.sha256(self.canonical()).digest()


def sign_group_state(
    ik_sign_priv: bytes,
    *,
    name: str,
    epoch: int,
    members: list[str],
    prev_hash: bytes,
    signer: str,
) -> GroupState:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    state = GroupState(
        name=name,
        epoch=epoch,
        members=tuple(sorted(dict.fromkeys(members))),
        prev_hash=prev_hash,
        signer=signer,
        signature=b"",
    )
    signature = Ed25519PrivateKey.from_private_bytes(ik_sign_priv).sign(
        state.canonical()
    )
    return GroupState(
        name=state.name,
        epoch=state.epoch,
        members=state.members,
        prev_hash=state.prev_hash,
        signer=state.signer,
        signature=signature,
    )


def verify_group_state_sig(state: GroupState, ik_sign_pub: bytes) -> None:
    """只验签名本身；链接和授权规则在 verify_state_transition 里。"""
    if state.epoch < 1:
        raise GroupStateError("群状态纪元必须从 1 开始")
    try:
        Ed25519PublicKey.from_public_bytes(ik_sign_pub).verify(
            state.signature, state.canonical()
        )
    except InvalidSignature as exc:
        raise GroupStateError("群状态签名无效") from exc


def verify_state_transition(
    previous: GroupState | None, state: GroupState
) -> None:
    """不碰公钥，只检查哈希链、纪元与成员演变规则。

    - 创世：epoch=1、前驱为空、签署者即创建者且必须在成员表里。
    - 后续：epoch 连续、prev_hash 指向前一状态、签署者是上一状态成员、
      成员表只能新增至多一人（邀请式成员制，没有群签名协商）。
    """
    if state.epoch < 1:
        raise GroupStateError("群状态纪元必须从 1 开始")
    if previous is None:
        if state.epoch != 1:
            raise GroupStateError("群状态缺少前驱")
        if state.prev_hash != GENESIS_PREV_HASH:
            raise GroupStateError("创世状态的前驱哈希必须为空")
        if state.signer not in state.members:
            raise GroupStateError("群创建者必须在成员表里")
        return
    if previous.name != state.name:
        raise GroupStateError("群状态群名不一致")
    if state.epoch != previous.epoch + 1:
        raise GroupStateError("群状态纪元必须连续递增")
    if state.prev_hash != previous.state_hash():
        raise GroupStateError("群状态前驱哈希不匹配")
    if state.signer not in previous.members:
        raise GroupStateError("只有上一状态的成员能签署新状态")
    if not set(previous.members) <= set(state.members):
        raise GroupStateError("成员只增不减")
    if len(state.members) > len(previous.members) + 1:
        raise GroupStateError("每次最多新增一名成员")


def build_genesis_state(
    ik_sign_priv: bytes, name: str, creator: str, members: list[str]
) -> GroupState:
    return sign_group_state(
        ik_sign_priv,
        name=name,
        epoch=1,
        members=members,
        prev_hash=GENESIS_PREV_HASH,
        signer=creator,
    )


def build_add_state(
    ik_sign_priv: bytes, previous: GroupState, new_member: str, signer: str
) -> GroupState:
    if new_member in previous.members:
        raise GroupStateError("新成员已在群内")
    members = list(previous.members) + [new_member]
    return sign_group_state(
        ik_sign_priv,
        name=previous.name,
        epoch=previous.epoch + 1,
        members=members,
        prev_hash=previous.state_hash(),
        signer=signer,
    )
