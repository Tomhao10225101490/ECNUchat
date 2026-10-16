"""经典 X3DH：最多四次 X25519，HKDF 收成 32 字节 SK。

本模块实现的是 Marlinspike、Perrin 的经典 X3DH，没有后量子密钥封装。
Fiedler、Günther，PKC 2025（ePrint 2024/702）分析的 PQXDH 是这条握手的
后量子扩展。论文正式题名是 *Security Analysis of Signal's PQXDH Handshake*；
对外介绍写成 *PQXDH: A Post-Quantum Extension of X3DH*。它在同样的 DH
组合上再并入一次 KEM。Signal 部署用 Kyber，论文也处理 ML-KEM，用来挡住
「现在记下握手、以后量子计算机打破 X25519」。

未实现边界：bundle、初始消息和 `hkdf_sk` 的输入里都没有 KEM 公钥、封装
密文或 KEM 共享秘密。材料只有 DH1||DH2||DH3，有一次性预密钥时再接 DH4。
这里不调用 Kyber 或 ML-KEM，也不把 X25519 的输出说成后量子安全。

后量子扩展路径（没有写进代码）：目录公布一把 KEM 公钥，发起方封装，双方
把 KEM 共享秘密按单独的 info 做域分离后并入 HKDF。Fiedler 和 Günther 说明
还需要 KEM 的绑定性质；缺少域分离会把具体安全界降下来。

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
    """把经典 X3DH 的 DH 拼接收成 SK。ikm 只能是 32 字节 DH 输出的整数倍。

    PQXDH 的 KEM 共享秘密长度不必是 32 的倍数，也不会进这个函数。
    """
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
    """A 侧经典 X3DH：DH1=IK_A×SPK_B，DH2=EK_A×IK_B，DH3=EK_A×SPK_B，可选 DH4。

    没有第五段 KEM 共享秘密。PQXDH 要加的就是那一段，本函数不接受。
    """
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
    """B 侧角色对调，仍是经典 X3DH：SPK 私钥配 A 的 IK_dh，IK_dh 私钥配 EK_A。

    与发起方一样，共享材料里没有 KEM 共享秘密。
    """
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
