"""双棘轮：对称棘轮、DH 棘轮、乱序缓存，消息钥匙用后即弃。

对照 Bienstock、Fairoze、Garg、Mukherjee、Raghuraman，CRYPTO 2022
（ePrint 2022/355）。会议正式题名是 *A More Complete Analysis of the
Signal Double Ratchet Algorithm*。对外介绍把这篇称作对双棘轮的通用可组合
分析：他们定义 UC 功能 F_DR，并证明 Signal 双棘轮实现它。本文件按那条
双棘轮的积木实现。没有实现文中更强的 Triple Ratchet / F_TR，也没有在
本仓库上重跑 UC 证明。

概念对应：

- 对称棘轮（文中的 inner symmetric-key ratchet）：`kdf_ck`。
  同一把棘轮公钥下，HMAC 推出一次性 MK，并换成下一把链钥匙。
  这一步给出前向安全，本身不给出破密恢复。
- DH 棘轮（文中的 public ratchet）：`kdf_rk`、`init_sender`、
  `_prepare_sending_chain`、`_dh_ratchet`。新的 X25519 输出混进根钥匙，
  开出新链。破密恢复发生在双方都换过棘轮公钥之后。
- 乱序与丢包（文中的 immediate decryption）：`_skip_message_keys`。
  空隙里的 MK 按 `dh_pub || n` 缓存，后到的包仍能解。永久丢失的一条
  不挡住后面的消息。上限 `MAX_SKIP` 是本实现的拒绝线；论文里的立即解密
  没有这道常数上限。
- 消息钥匙用后即弃：`encrypt` / `decrypt` 不把已经用于 GCM 的 MK 留在
  `RatchetState` 里。调用方拿到返回值后丢掉。跳过缓存里的 MK 要留到
  对应密文到来，解开时弹出。这避开他们列出的 T1：把已经不需要的上一
  发送世代对称秘密继续留在状态里，妥协之后的注入在 F_DR 下成立。

安全边界：发送棘轮私钥 `dhs_priv` 必须留到收到对方下一把棘轮公钥。
这个窗口里对同一方连续取走两次状态，可以拼出本轮已经发出的消息钥匙。
这是他们指出的双棘轮缺口。Triple Ratchet 会在算出本轮 DH 之后对私钥
材料再做一次本地单向更新。本文件保存的是完整 X25519 私钥，没有那一层。
证明假设（可编程理想密码、公钥棘轮 KDF 的随机预言机、强 Diffie-Hellman）
也没有在这段 Python 上重新建立。X3DH 如何得到初始 SK 不在他们的定理里。

SK 只用于初始化。每条聊天明文用独立的 MK 做 AES-256-GCM。
本模块只做字节进、字节出，不 import 网络或数据库。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.x3dh import x25519_dh

# 公钥棘轮 KDF 的 info。与 X3DH 的 x3dh-v1 分开，两次派生不会撞车。
DR_INFO = b"dr-v1"
# 对称棘轮的两个 HMAC 输入，对应 Signal 的 KDF_CK，也就是 CRYPTO 2022
# 文中的 inner symmetric-key ratchet：0x01 推出一次性消息钥匙，0x02 推出下一把链钥匙。
SYMMETRIC_RATCHET_MK_LABEL = b"\x01"
SYMMETRIC_RATCHET_CK_LABEL = b"\x02"
# 立即解密的实现上限。论文对多项式大小的空隙都成立；超过这个空隙就拒绝。
MAX_SKIP = 40
MAX_SEEN = 160
NONCE_LEN = 12


class RatchetError(Exception):
    kind: str

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


class ReplayError(RatchetError):
    def __init__(self, message: str = "重放拒绝") -> None:
        super().__init__("重放拒绝", message)


class SkipLimitError(RatchetError):
    def __init__(self, message: str = "跳过超过 40 条被拒绝") -> None:
        super().__init__("跳过超限", message)


class GCMError(RatchetError):
    def __init__(self, message: str = "GCM 失败") -> None:
        super().__init__("GCM 失败", message)


def kdf_ck(ck: bytes) -> tuple[bytes, bytes]:
    """对称棘轮：MK = HMAC(ck, 0x01)，新 CK = HMAC(ck, 0x02)。

    Bienstock 等把这一步称作 inner symmetric-key ratchet。链是确定的，
    所以它提供前向安全，不提供破密恢复。旧的 CK 不保留。
    """
    mk = _hmac_sha256(ck, SYMMETRIC_RATCHET_MK_LABEL)
    new_ck = _hmac_sha256(ck, SYMMETRIC_RATCHET_CK_LABEL)
    return new_ck, mk


def kdf_rk(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """DH 棘轮：HKDF(ikm=dh_out, salt=rk, info=dr-v1, 64) → RK||CK。

    对应 CRYPTO 2022 的 public ratchet：新世代的根钥匙和链钥匙一起从
    上一把根钥匙与这一次的 DH 输出派生。
    """
    out = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=rk,
        info=DR_INFO,
    ).derive(dh_out)
    return out[:32], out[32:]


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def generate_ratchet_keypair() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def skipped_key(dh_pub: bytes, n: int) -> bytes:
    return dh_pub + n.to_bytes(4, "big")


def build_aad(sender: str, receiver: str, n: int, pn: int, dh_pub: bytes) -> bytes:
    return (
        sender.encode("utf-8")
        + receiver.encode("utf-8")
        + n.to_bytes(4, "big")
        + pn.to_bytes(4, "big")
        + dh_pub
    )


@dataclass
class Header:
    dh_pub: bytes
    n: int
    pn: int


@dataclass
class RatchetMessage:
    header: Header
    nonce: bytes
    ciphertext: bytes


@dataclass
class RatchetState:
    rk: bytes
    local_user: str
    remote_user: str
    # 当前发送世代的 X25519 私钥。必须留到对方下一把棘轮公钥到来，
    # 否则算不出下一次 DH。Bienstock 等指出：这个窗口里的两次状态泄露
    # 可以恢复本轮 MK。Triple Ratchet 会在算出 DH 后对它做本地单向更新。
    dhs_priv: bytes | None = None
    dhs_pub: bytes | None = None
    dhr_pub: bytes | None = None
    cks: bytes | None = None
    ckr: bytes | None = None
    ns: int = 0
    nr: int = 0
    pns: int = 0
    # 立即解密缓存：还没送达的 MK，键是 dh_pub || n。解开后弹出，不长期保留。
    skipped: dict[bytes, bytes] = field(default_factory=dict)
    seen: set[bytes] = field(default_factory=set)
    retired_dh: set[bytes] = field(default_factory=set)
    dh_ratchet_count: int = 0

    def to_record(self) -> dict:
        return {
            "rk": self.rk,
            "local_user": self.local_user,
            "remote_user": self.remote_user,
            "dhs_priv": self.dhs_priv,
            "dhs_pub": self.dhs_pub,
            "dhr_pub": self.dhr_pub,
            "cks": self.cks,
            "ckr": self.ckr,
            "ns": self.ns,
            "nr": self.nr,
            "pns": self.pns,
            "skipped": dict(self.skipped),
            "seen": list(self.seen),
            "retired_dh": list(self.retired_dh),
            "dh_ratchet_count": self.dh_ratchet_count,
        }

    @classmethod
    def from_record(cls, rec: dict) -> RatchetState:
        return cls(
            rk=rec["rk"],
            local_user=rec["local_user"],
            remote_user=rec["remote_user"],
            dhs_priv=rec.get("dhs_priv"),
            dhs_pub=rec.get("dhs_pub"),
            dhr_pub=rec.get("dhr_pub"),
            cks=rec.get("cks"),
            ckr=rec.get("ckr"),
            ns=rec.get("ns", 0),
            nr=rec.get("nr", 0),
            pns=rec.get("pns", 0),
            skipped=dict(rec.get("skipped") or {}),
            seen=set(rec.get("seen") or []),
            retired_dh=set(rec.get("retired_dh") or []),
            dh_ratchet_count=rec.get("dh_ratchet_count", 0),
        )


def init_sender(sk: bytes, spk_pub_b: bytes, local_user: str, remote_user: str) -> RatchetState:
    """A 算完 SK 后生成 R_A，用 SPK_B 做第一次 DH 棘轮，只得到发送链。"""
    dhs_priv, dhs_pub = generate_ratchet_keypair()
    dh_out = x25519_dh(dhs_priv, spk_pub_b)
    rk, cks = kdf_rk(sk, dh_out)
    return RatchetState(
        rk=rk,
        local_user=local_user,
        remote_user=remote_user,
        dhs_priv=dhs_priv,
        dhs_pub=dhs_pub,
        cks=cks,
        dh_ratchet_count=1,
    )


def init_receiver(
    sk: bytes,
    spk_priv_b: bytes,
    remote_dh_pub: bytes,
    local_user: str,
    remote_user: str,
) -> RatchetState:
    """B 用 SPK 私钥和头里的 R_A 重算 DH / KDF_RK，得到接收链。"""
    dh_out = x25519_dh(spk_priv_b, remote_dh_pub)
    rk, ckr = kdf_rk(sk, dh_out)
    return RatchetState(
        rk=rk,
        local_user=local_user,
        remote_user=remote_user,
        dhr_pub=remote_dh_pub,
        ckr=ckr,
        dh_ratchet_count=1,
    )


def _prepare_sending_chain(state: RatchetState) -> None:
    """第一次回复前的公钥棘轮：生成新的棘轮私钥，把接收链长度记入 PNs，换发送链。

    新的 `dhs_priv` 从这里开始留在状态里，直到对方的下一把棘轮公钥触发
    `_dh_ratchet`。这就是 CRYPTO 2022 写出的那个双棘轮窗口。
    """
    if state.cks is not None and state.dhs_priv is not None:
        return
    if state.dhr_pub is None:
        raise RatchetError("协议错误", "没有对端棘轮公钥，无法建立发送链")
    state.pns = state.nr
    state.dhs_priv, state.dhs_pub = generate_ratchet_keypair()
    dh_out = x25519_dh(state.dhs_priv, state.dhr_pub)
    state.rk, state.cks = kdf_rk(state.rk, dh_out)
    state.ns = 0
    state.dh_ratchet_count += 1


def _dh_ratchet(state: RatchetState, remote_dh_pub: bytes) -> None:
    """收到新的 dh_pub：用仍留着的发送私钥做接收链，再换一把新的发送私钥。

    两次 `kdf_rk` 是公钥棘轮进入下一世代。调用前应先按 PN 把旧接收链上
    没到的 MK 放进跳过缓存，丢失的旧消息才仍能补解。
    """
    if state.dhs_priv is None:
        raise RatchetError("协议错误", "本地还没有发送棘轮密钥，无法完成 DH 棘轮")
    if state.dhr_pub is not None:
        state.retired_dh.add(state.dhr_pub)
    state.dhr_pub = remote_dh_pub
    dh_recv = x25519_dh(state.dhs_priv, remote_dh_pub)
    state.rk, state.ckr = kdf_rk(state.rk, dh_recv)
    state.nr = 0
    state.pns = state.ns
    state.dhs_priv, state.dhs_pub = generate_ratchet_keypair()
    dh_send = x25519_dh(state.dhs_priv, remote_dh_pub)
    state.rk, state.cks = kdf_rk(state.rk, dh_send)
    state.ns = 0
    state.dh_ratchet_count += 1


def encrypt(state: RatchetState, plaintext: bytes) -> tuple[RatchetMessage, bytes]:
    """用当前发送链做一次对称棘轮。

    返回报文和本次 MK。MK 不写入 `RatchetState`；调用方用完即弃，禁止写日志。
    状态里换成下一把链钥匙，推不回这把 MK。
    """
    _prepare_sending_chain(state)
    assert state.cks is not None and state.dhs_pub is not None
    new_ck, mk = kdf_ck(state.cks)
    state.cks = new_ck
    n = state.ns
    pn = state.pns
    state.ns = n + 1
    header = Header(dh_pub=state.dhs_pub, n=n, pn=pn)
    nonce = os.urandom(NONCE_LEN)
    aad = build_aad(state.local_user, state.remote_user, n, pn, state.dhs_pub)
    ciphertext = AESGCM(mk).encrypt(nonce, plaintext, aad)
    return RatchetMessage(header=header, nonce=nonce, ciphertext=ciphertext), mk


def _skip_message_keys(state: RatchetState, until: int, dh_pub: bytes) -> None:
    """为乱序或丢包预派生 MK，放进跳过缓存。这是立即解密，不是推迟删除。

    超过 `MAX_SKIP` 把未消费的缓存项就拒绝，避免一个巨大序号迫使客户端
    无界派生。论文里的立即解密没有这个常数上限。
    """
    if state.ckr is None:
        return
    if until < state.nr:
        return
    needed = until - state.nr
    if needed <= 0:
        return
    if len(state.skipped) + needed > MAX_SKIP:
        raise SkipLimitError()
    while state.nr < until:
        new_ck, mk = kdf_ck(state.ckr)
        state.ckr = new_ck
        key = skipped_key(dh_pub, state.nr)
        if key in state.seen:
            raise ReplayError()
        state.skipped[key] = mk
        state.nr += 1


def decrypt(state: RatchetState, message: RatchetMessage) -> tuple[bytes, bytes]:
    """原子解密：认证成功才提交棘轮状态，失败时原状态完全不变。"""
    candidate = RatchetState.from_record(state.to_record())
    plaintext, mk = _decrypt_mutating(candidate, message)
    _commit_state(state, candidate)
    return plaintext, mk


def _commit_state(target: RatchetState, source: RatchetState) -> None:
    for name in RatchetState.__dataclass_fields__:
        value = getattr(source, name)
        if isinstance(value, dict):
            value = dict(value)
        elif isinstance(value, set):
            value = set(value)
        setattr(target, name, value)


def _decrypt_mutating(
    state: RatchetState, message: RatchetMessage
) -> tuple[bytes, bytes]:
    header = message.header
    if len(header.dh_pub) != 32 or len(message.nonce) != NONCE_LEN:
        raise GCMError("GCM 失败：报文头或 nonce 长度无效")
    if not 0 <= header.n <= 0xFFFFFFFF or not 0 <= header.pn <= 0xFFFFFFFF:
        raise RatchetError("协议错误", "消息序号超出 uint32 范围")
    if len(message.ciphertext) < 16:
        raise GCMError("GCM 失败：密文缺少认证标签")
    key = skipped_key(header.dh_pub, header.n)
    if key in state.seen:
        raise ReplayError()
    if key in state.skipped:
        mk = state.skipped.pop(key)
        plaintext = _open(state, message, mk)
        _mark_seen(state, key)
        return plaintext, mk
    # 旧链只有在 PN 处理阶段明确缓存过的消息密钥仍可接收；除此之外，
    # 退休公钥下的报文都是过期或重放。
    if header.dh_pub in state.retired_dh:
        raise ReplayError()

    if state.dhr_pub is None or header.dh_pub != state.dhr_pub:
        if state.ckr is not None and state.dhr_pub is not None:
            _skip_message_keys(state, header.pn, state.dhr_pub)
        if state.dhs_priv is None:
            raise RatchetError("协议错误", "尚未建立发送棘轮，无法处理新的对端公钥")
        if state.dhr_pub is not None and header.dh_pub == state.dhr_pub:
            pass
        else:
            _dh_ratchet(state, header.dh_pub)

    if header.n < state.nr:
        raise ReplayError()

    assert state.dhr_pub is not None
    _skip_message_keys(state, header.n, state.dhr_pub)
    if state.ckr is None:
        raise RatchetError("协议错误", "接收链为空")
    new_ck, mk = kdf_ck(state.ckr)
    state.ckr = new_ck
    state.nr = header.n + 1
    plaintext = _open(state, message, mk)
    _mark_seen(state, key)
    return plaintext, mk


def _mark_seen(state: RatchetState, key: bytes) -> None:
    state.seen.add(key)
    while len(state.seen) > MAX_SEEN:
        state.seen.pop()


def _open(state: RatchetState, message: RatchetMessage, mk: bytes) -> bytes:
    aad = build_aad(
        state.remote_user,
        state.local_user,
        message.header.n,
        message.header.pn,
        message.header.dh_pub,
    )
    try:
        return AESGCM(mk).decrypt(message.nonce, message.ciphertext, aad)
    except InvalidTag as exc:
        raise GCMError() from exc


