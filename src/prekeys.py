"""长期身份密钥、Signed Prekey、一次性预密钥池与后量子密钥。

本模块只做密钥生成与签名，不接触网络或数据库。
三把长期密钥职责分离，禁止 XEdDSA：
- IK_sign：Ed25519，只签名，不做 DH
- IK_dh：X25519，只做 X3DH，不签名
- SPK：X25519，由 IK_sign 对 (SPK 公钥原始字节 || 用户名) 签名
- PQK：ML-KEM-768，只做后量子密钥封装，不签名；其公钥由 IK_sign 对
  (PQK 公钥原始字节 || 用户名) 签名后公布。这是 PQXDH（PKC 2025 的
  Fiedler、Günther 分析）需要的 KEM 公钥，也是混合棘轮的长期封装目标。

若运行时的 cryptography 不带 ML-KEM，MLKEM_SUPPORTED 为 False，身份里
PQK 字段为 None，握手自动回退经典 X3DH。
"""

from __future__ import annotations

import time
import os
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem

    MLKEM_SUPPORTED = True
except ImportError:  # pragma: no cover - 仅老版本 cryptography
    mlkem = None  # type: ignore[assignment]
    MLKEM_SUPPORTED = False

MLKEM768_PUB_LEN = 1184
MLKEM768_CT_LEN = 1088
MLKEM768_SS_LEN = 32

OPK_POOL_SIZE = 20
OPK_REFILL_THRESHOLD = 5


def generate_ed25519() -> tuple[bytes, bytes]:
    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def generate_x25519() -> tuple[bytes, bytes]:
    priv = X25519PrivateKey.generate()
    return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()


def sign_spk(ik_sign_priv: bytes, spk_pub: bytes, username: str) -> bytes:
    data = spk_pub + username.encode("utf-8")
    return Ed25519PrivateKey.from_private_bytes(ik_sign_priv).sign(data)


def verify_spk(ik_sign_pub: bytes, spk_pub: bytes, username: str, signature: bytes) -> None:
    data = spk_pub + username.encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(ik_sign_pub).verify(signature, data)
    except InvalidSignature as exc:
        raise InvalidSignature("对方预密钥签名无效") from exc


def sign_bytes(ik_sign_priv: bytes, data: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(ik_sign_priv).sign(data)


def verify_bytes(ik_sign_pub: bytes, data: bytes, signature: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(ik_sign_pub).verify(signature, data)
    except InvalidSignature as exc:
        raise InvalidSignature("验签失败") from exc


def generate_mlkem768() -> tuple[bytes, bytes] | None:
    """生成 ML-KEM-768 密钥对 (种子, 公钥)。不支持时返回 None。

    私钥以 64 字节种子保存，解密时用 from_seed_bytes 重建。
    """
    if not MLKEM_SUPPORTED:
        return None
    seed = os.urandom(64)
    priv = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    return seed, priv.public_key().public_bytes_raw()


def encapsulate_mlkem(pq_pub: bytes) -> tuple[bytes, bytes]:
    """对长期 PQK 公钥做一次新鲜封装，返回 (共享秘密, 密文)。"""
    if not MLKEM_SUPPORTED:
        raise RuntimeError("当前 cryptography 不支持 ML-KEM")
    pub = mlkem.MLKEM768PublicKey.from_public_bytes(pq_pub)
    return pub.encapsulate()


def decapsulate_mlkem(pq_priv: bytes, pq_ct: bytes) -> bytes:
    if not MLKEM_SUPPORTED:
        raise RuntimeError("当前 cryptography 不支持 ML-KEM")
    return mlkem.MLKEM768PrivateKey.from_seed_bytes(pq_priv).decapsulate(pq_ct)


def sign_pq(ik_sign_priv: bytes, pq_pub: bytes, username: str) -> bytes:
    """IK_sign 对 (PQK 公钥原始字节 || 用户名) 签名，把 KEM 公钥绑到身份。"""
    data = pq_pub + username.encode("utf-8")
    return Ed25519PrivateKey.from_private_bytes(ik_sign_priv).sign(data)


def verify_pq(ik_sign_pub: bytes, pq_pub: bytes, username: str, signature: bytes) -> None:
    data = pq_pub + username.encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(ik_sign_pub).verify(signature, data)
    except InvalidSignature as exc:
        raise InvalidSignature("对方 PQ 密钥签名无效") from exc


@dataclass
class SignedPrekey:
    priv: bytes
    pub: bytes
    signature: bytes
    created: float


@dataclass
class OneTimePrekey:
    priv: bytes
    pub: bytes


@dataclass
class IdentityKeys:
    username: str
    ik_sign_priv: bytes
    ik_sign_pub: bytes
    ik_dh_priv: bytes
    ik_dh_pub: bytes
    spk: SignedPrekey
    pq_priv: bytes | None = None
    pq_pub: bytes | None = None
    pq_sig: bytes | None = None
    opks: list[OneTimePrekey] = field(default_factory=list)

    def unused_opk_count(self) -> int:
        return len(self.opks)

    def take_opk(self, opk_pub: bytes) -> OneTimePrekey:
        for i, opk in enumerate(self.opks):
            if opk.pub == opk_pub:
                return self.opks.pop(i)
        raise KeyError("本地没有对应的一次性预密钥私钥")

    def needs_refill(self) -> bool:
        return len(self.opks) < OPK_REFILL_THRESHOLD

    def refill_opks(self) -> list[OneTimePrekey]:
        """补到 20 把，返回新生成的那些以便上传公钥。"""
        created: list[OneTimePrekey] = []
        while len(self.opks) < OPK_POOL_SIZE:
            priv, pub = generate_x25519()
            item = OneTimePrekey(priv=priv, pub=pub)
            self.opks.append(item)
            created.append(item)
        return created


def generate_identity(username: str) -> IdentityKeys:
    ik_sign_priv, ik_sign_pub = generate_ed25519()
    ik_dh_priv, ik_dh_pub = generate_x25519()
    pq = generate_mlkem768()
    spk_priv, spk_pub = generate_x25519()
    spk = SignedPrekey(
        priv=spk_priv,
        pub=spk_pub,
        signature=sign_spk(ik_sign_priv, spk_pub, username),
        created=time.time(),
    )
    identity = IdentityKeys(
        username=username,
        ik_sign_priv=ik_sign_priv,
        ik_sign_pub=ik_sign_pub,
        ik_dh_priv=ik_dh_priv,
        ik_dh_pub=ik_dh_pub,
        spk=spk,
        pq_priv=pq[0] if pq else None,
        pq_pub=pq[1] if pq else None,
        pq_sig=sign_pq(ik_sign_priv, pq[1], username) if pq else None,
    )
    identity.refill_opks()
    return identity
