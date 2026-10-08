"""X3DH：四次 Diffie-Hellman 协商 32 字节 SK。

X25519 就是题目里的椭圆曲线 Diffie-Hellman。
SK 只用来初始化双棘轮，绝不直接加密聊天内容。
本模块只做字节进、字节出，不 import 网络或数据库。
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

X3DH_INFO = b"x3dh-v1"
X3DH_SALT = b"\x00" * 32
X3DH_SK_LEN = 32


class X3DHError(Exception):
    """X3DH 协商或验签失败。"""


def x25519_dh(priv: bytes, pub: bytes) -> bytes:
    """X25519 = 椭圆曲线 Diffie-Hellman。"""
    return X25519PrivateKey.from_private_bytes(priv).exchange(
        X25519PublicKey.from_public_bytes(pub)
    )


def hkdf_sk(ikm: bytes) -> bytes:
    if len(ikm) == 0 or len(ikm) % 32 != 0:
        raise X3DHError("共享材料长度必须是 32 的倍数")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=X3DH_SK_LEN,
        salt=X3DH_SALT,
        info=X3DH_INFO,
    ).derive(ikm)


def initiator_secret(
    ik_dh_priv_a: bytes,
    ek_priv_a: bytes,
    spk_pub_b: bytes,
    ik_dh_pub_b: bytes,
    opk_pub_b: bytes | None = None,
) -> bytes:
    """A 侧：DH1=IK_A×SPK_B，DH2=EK_A×IK_B，DH3=EK_A×SPK_B，可选 DH4=EK_A×OPK_B。"""
    dh1 = x25519_dh(ik_dh_priv_a, spk_pub_b)
    dh2 = x25519_dh(ek_priv_a, ik_dh_pub_b)
    dh3 = x25519_dh(ek_priv_a, spk_pub_b)
    material = dh1 + dh2 + dh3
    if opk_pub_b:
        material += x25519_dh(ek_priv_a, opk_pub_b)
    return hkdf_sk(material)


def responder_secret(
    spk_priv_b: bytes,
    ik_dh_priv_b: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_priv_b: bytes | None = None,
) -> bytes:
    """B 侧角色对调：SPK 私钥配 A 的 IK_dh，IK_dh 私钥配 EK_A，以此类推。"""
    dh1 = x25519_dh(spk_priv_b, ik_dh_pub_a)
    dh2 = x25519_dh(ik_dh_priv_b, ek_pub_a)
    dh3 = x25519_dh(spk_priv_b, ek_pub_a)
    material = dh1 + dh2 + dh3
    if opk_priv_b:
        material += x25519_dh(opk_priv_b, ek_pub_a)
    return hkdf_sk(material)


def initial_signed_payload(
    ik_dh_pub_a: bytes, ek_pub_a: bytes, opk_pub_b: bytes | None
) -> bytes:
    return ik_dh_pub_a + ek_pub_a + (opk_pub_b or b"")


def sign_initial(
    ik_sign_priv_a: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_pub_b: bytes | None,
) -> bytes:
    data = initial_signed_payload(ik_dh_pub_a, ek_pub_a, opk_pub_b)
    return Ed25519PrivateKey.from_private_bytes(ik_sign_priv_a).sign(data)


def verify_initial(
    ik_sign_pub_a: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_pub_b: bytes | None,
    signature: bytes,
) -> None:
    data = initial_signed_payload(ik_dh_pub_a, ek_pub_a, opk_pub_b)
    try:
        Ed25519PublicKey.from_public_bytes(ik_sign_pub_a).verify(signature, data)
    except InvalidSignature as exc:
        raise X3DHError("验签失败") from exc


@dataclass(frozen=True)
class InitialMessage:
    ik_dh_pub: bytes
    ek_pub: bytes
    opk_pub: bytes | None
    signature: bytes


def build_initial_message(
    ik_sign_priv_a: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_pub_b: bytes | None,
) -> InitialMessage:
    return InitialMessage(
        ik_dh_pub=ik_dh_pub_a,
        ek_pub=ek_pub_a,
        opk_pub=opk_pub_b,
        signature=sign_initial(ik_sign_priv_a, ik_dh_pub_a, ek_pub_a, opk_pub_b),
    )
