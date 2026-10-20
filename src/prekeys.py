"""长期身份密钥、Signed Prekey、一次性预密钥池与后量子密钥。

本模块只做密钥生成与签名，不接触网络或数据库。
三把长期密钥职责分离，禁止 XEdDSA：
- IK_sign：Ed25519，只签名，不做 DH
- IK_dh：X25519，只做 X3DH，不签名
- SPK：X25519，由 IK_sign 对 (SPK 公钥原始字节 || 用户名) 签名
- PQK：ML-KEM-768，只做后量子密钥封装，不签名；其公钥由 IK_sign 对
  (PQK 公钥原始字节 || 用户名) 签名后公布。这是 PQXDH（PKC 2025 的
  Fiedler、Günther 分析）里的最后手段封装公钥，也是混合棘轮的长期封装目标。
- PQOPK：一次性 ML-KEM-768。握手优先封装到它，首条密文认证成功后删私钥。
  签名输入带独立前缀，不能拿去冒充长期 PQK。

若运行时的 cryptography 不带 ML-KEM，MLKEM_SUPPORTED 为 False，身份里
PQK 字段为 None，握手自动回退经典 X3DH。
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

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
# 一次性 KEM 公钥 1184 字节。池子 8 把，注册包仍远小于 64KB。
PQ_OPK_POOL_SIZE = 8
PQ_OPK_REFILL_THRESHOLD = 2
# 与长期 PQK 的签名输入分开，避免一次性公钥被服务器换进长期槽。
PQ_OPK_PREFIX = b"pq-opk-v1\x00"
_KEM_CACHE_MAX = 32
_pub_cache: OrderedDict[bytes, Any] = OrderedDict()
_priv_cache: OrderedDict[bytes, Any] = OrderedDict()
_cache_lock = threading.Lock()


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


def clear_mlkem_cache() -> None:
    """丢掉缓存的 ML-KEM 对象。测试和演示用来对比「每次重建」的耗时。"""
    with _cache_lock:
        _pub_cache.clear()
        _priv_cache.clear()


def _remember(cache: OrderedDict[bytes, Any], key: bytes, value: Any) -> Any:
    cache[key] = value
    cache.move_to_end(key)
    while len(cache) > _KEM_CACHE_MAX:
        cache.popitem(last=False)
    return value


def _cached_public(raw: bytes) -> Any:
    with _cache_lock:
        hit = _pub_cache.get(raw)
        if hit is not None:
            _pub_cache.move_to_end(raw)
            return hit
    pub = mlkem.MLKEM768PublicKey.from_public_bytes(raw)
    with _cache_lock:
        existing = _pub_cache.get(raw)
        if existing is not None:
            _pub_cache.move_to_end(raw)
            return existing
        return _remember(_pub_cache, raw, pub)


def _cached_private(seed: bytes) -> Any:
    with _cache_lock:
        hit = _priv_cache.get(seed)
        if hit is not None:
            _priv_cache.move_to_end(seed)
            return hit
    priv = mlkem.MLKEM768PrivateKey.from_seed_bytes(seed)
    with _cache_lock:
        existing = _priv_cache.get(seed)
        if existing is not None:
            _priv_cache.move_to_end(seed)
            return existing
        return _remember(_priv_cache, seed, priv)


def encapsulate_mlkem(pq_pub: bytes) -> tuple[bytes, bytes]:
    """对一把 ML-KEM 公钥做一次新鲜封装，返回 (共享秘密, 密文)。

    公钥对象按原始字节缓存。混合棘轮每次换链都会封装到同一把长期 PQK，
    不必每次 from_public_bytes。
    """
    if not MLKEM_SUPPORTED:
        raise RuntimeError("当前 cryptography 不支持 ML-KEM")
    return _cached_public(pq_pub).encapsulate()


def decapsulate_mlkem(pq_priv: bytes, pq_ct: bytes) -> bytes:
    """解封。私钥以种子保存，对象按种子缓存，避免每次 from_seed_bytes。"""
    if not MLKEM_SUPPORTED:
        raise RuntimeError("当前 cryptography 不支持 ML-KEM")
    return _cached_private(pq_priv).decapsulate(pq_ct)


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


def sign_pq_opk(ik_sign_priv: bytes, pq_opk_pub: bytes, username: str) -> bytes:
    """一次性封装公钥的签名。前缀 pq-opk-v1 与长期 PQK 的签名输入不同。"""
    data = PQ_OPK_PREFIX + pq_opk_pub + username.encode("utf-8")
    return Ed25519PrivateKey.from_private_bytes(ik_sign_priv).sign(data)


def verify_pq_opk(
    ik_sign_pub: bytes, pq_opk_pub: bytes, username: str, signature: bytes
) -> None:
    data = PQ_OPK_PREFIX + pq_opk_pub + username.encode("utf-8")
    try:
        Ed25519PublicKey.from_public_bytes(ik_sign_pub).verify(signature, data)
    except InvalidSignature as exc:
        raise InvalidSignature("对方一次性 PQ 预密钥签名无效") from exc


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
class PqOneTimePrekey:
    """一次性 ML-KEM 预密钥。priv 是 64 字节种子，用后删除。"""

    priv: bytes
    pub: bytes
    signature: bytes


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
    pq_opks: list[PqOneTimePrekey] = field(default_factory=list)

    def unused_opk_count(self) -> int:
        return len(self.opks)

    def take_opk(self, opk_pub: bytes) -> OneTimePrekey:
        for i, opk in enumerate(self.opks):
            if opk.pub == opk_pub:
                return self.opks.pop(i)
        raise KeyError("本地没有对应的一次性预密钥私钥")

    def take_pq_opk(self, pq_opk_pub: bytes) -> PqOneTimePrekey:
        for i, item in enumerate(self.pq_opks):
            if item.pub == pq_opk_pub:
                return self.pq_opks.pop(i)
        raise KeyError("本地没有对应的一次性 PQ 预密钥私钥")

    def needs_refill(self) -> bool:
        return len(self.opks) < OPK_REFILL_THRESHOLD

    def needs_pq_refill(self) -> bool:
        if self.pq_priv is None or not MLKEM_SUPPORTED:
            return False
        return len(self.pq_opks) < PQ_OPK_REFILL_THRESHOLD

    def refill_opks(self) -> list[OneTimePrekey]:
        """补到 20 把，返回新生成的那些以便上传公钥。"""
        created: list[OneTimePrekey] = []
        while len(self.opks) < OPK_POOL_SIZE:
            priv, pub = generate_x25519()
            item = OneTimePrekey(priv=priv, pub=pub)
            self.opks.append(item)
            created.append(item)
        return created

    def refill_pq_opks(self) -> list[PqOneTimePrekey]:
        """补到 8 把一次性 ML-KEM。返回新生成的那些以便上传公钥和签名。"""
        if self.pq_priv is None or not MLKEM_SUPPORTED:
            return []
        created: list[PqOneTimePrekey] = []
        while len(self.pq_opks) < PQ_OPK_POOL_SIZE:
            pair = generate_mlkem768()
            if pair is None:
                break
            item = PqOneTimePrekey(
                priv=pair[0],
                pub=pair[1],
                signature=sign_pq_opk(self.ik_sign_priv, pair[1], self.username),
            )
            self.pq_opks.append(item)
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
    identity.refill_pq_opks()
    return identity
