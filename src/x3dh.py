"""X3DH 与 PQXDH：最多四次 X25519，可选并入一次 ML-KEM，HKDF 收成 32 字节 SK。

经典路径是 Marlinspike、Perrin 的 X3DH。混合路径是本仓库对 Fiedler、
Günther，PKC 2025（ePrint 2024/702，*Security Analysis of Signal's
PQXDH Handshake*）的实现：在同样的 DH 组合之外并入一次 ML-KEM-768
密钥封装，双方把 KEM 共享秘密与 DH 材料拼接后放进 HKDF，info 用独立的
`pqxdh-v1` 与经典 `x3dh-v1` 域分离。

他们指出的 KEM 绑定在这里用两层处理：
1. 目录里的 PQK 公钥由 IK_sign 对 (PQK 公钥 || 用户名) 签名（prekeys）。
2. 发起方把自己的 PQK 公钥与 KEM 密文放进初始消息，IK_sign 的签名覆盖
   IK_dh || EK || OPK || IK_PQ || PQ_CT，两端核对同一份握手转写。

边界照旧：X25519 就是题目里的椭圆曲线 Diffie-Hellman；SK 只用来初始化
双棘轮，绝不直接加密聊天内容；本模块只做字节进、字节出。
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

from src.prekeys import MLKEM_SUPPORTED, decapsulate_mlkem, encapsulate_mlkem

X3DH_INFO = b"x3dh-v1"
PQXDH_INFO = b"pqxdh-v1"
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


def hkdf_pq_sk(dh_material: bytes, kem_ss: bytes) -> bytes:
    """混合 X3DH：ikm = DH1||DH2||DH3[||DH4] || KEM 共享秘密，info=pqxdh-v1。

    KEM 共享秘密长度不必是 32 的倍数；域标签与经典 x3dh-v1 分开，
    两次派生不会撞车。
    """
    if len(dh_material) == 0 or len(dh_material) % 32 != 0:
        raise X3DHError("共享材料长度必须是 32 的倍数")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=X3DH_SK_LEN,
        salt=X3DH_SALT,
        info=PQXDH_INFO,
    ).derive(dh_material + kem_ss)


def _initiator_dh_material(
    ik_dh_priv_a: bytes,
    ek_priv_a: bytes,
    spk_pub_b: bytes,
    ik_dh_pub_b: bytes,
    opk_pub_b: bytes | None = None,
) -> bytes:
    dh1 = x25519_dh(ik_dh_priv_a, spk_pub_b)
    dh2 = x25519_dh(ek_priv_a, ik_dh_pub_b)
    dh3 = x25519_dh(ek_priv_a, spk_pub_b)
    material = dh1 + dh2 + dh3
    if opk_pub_b:
        material += x25519_dh(ek_priv_a, opk_pub_b)
    return material


def initiator_secret(
    ik_dh_priv_a: bytes,
    ek_priv_a: bytes,
    spk_pub_b: bytes,
    ik_dh_pub_b: bytes,
    opk_pub_b: bytes | None = None,
) -> bytes:
    """A 侧经典 X3DH：DH1=IK_A×SPK_B，DH2=EK_A×IK_B，DH3=EK_A×SPK_B，可选 DH4。

    没有 KEM 共享秘密，输出与 `hkdf_pq_sk` 域分离。
    """
    material = _initiator_dh_material(
        ik_dh_priv_a, ek_priv_a, spk_pub_b, ik_dh_pub_b, opk_pub_b
    )
    return hkdf_sk(material)


def initiator_hybrid_secret(
    ik_dh_priv_a: bytes,
    ek_priv_a: bytes,
    spk_pub_b: bytes,
    ik_dh_pub_b: bytes,
    opk_pub_b: bytes | None,
    pq_pk_b: bytes,
) -> tuple[bytes, bytes]:
    """A 侧 PQXDH：经典四次 DH + 一次对 B 的 PQK 的封装，返回 (SK, PQ_CT)。

    PQ_CT 必须随初始消息发出并进 IK_sign 签名（见 initial_signed_payload）。
    """
    material = _initiator_dh_material(
        ik_dh_priv_a, ek_priv_a, spk_pub_b, ik_dh_pub_b, opk_pub_b
    )
    if not MLKEM_SUPPORTED:
        raise X3DHError("当前环境不支持 ML-KEM")
    kem_ss, pq_ct = encapsulate_mlkem(pq_pk_b)
    return hkdf_pq_sk(material, kem_ss), pq_ct


def _responder_dh_material(
    spk_priv_b: bytes,
    ik_dh_priv_b: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_priv_b: bytes | None = None,
) -> bytes:
    dh1 = x25519_dh(spk_priv_b, ik_dh_pub_a)
    dh2 = x25519_dh(ik_dh_priv_b, ek_pub_a)
    dh3 = x25519_dh(spk_priv_b, ek_pub_a)
    material = dh1 + dh2 + dh3
    if opk_priv_b:
        material += x25519_dh(opk_priv_b, ek_pub_a)
    return material


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
    material = _responder_dh_material(
        spk_priv_b, ik_dh_priv_b, ik_dh_pub_a, ek_pub_a, opk_priv_b
    )
    return hkdf_sk(material)


def responder_hybrid_secret(
    spk_priv_b: bytes,
    ik_dh_priv_b: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_priv_b: bytes | None,
    pq_priv_b: bytes,
    pq_ct: bytes,
) -> bytes:
    """B 侧 PQXDH：解封 A 的 PQ_CT，把 KEM 共享秘密并入同一 HKDF。"""
    material = _responder_dh_material(
        spk_priv_b, ik_dh_priv_b, ik_dh_pub_a, ek_pub_a, opk_priv_b
    )
    if not MLKEM_SUPPORTED:
        raise X3DHError("当前环境不支持 ML-KEM")
    kem_ss = decapsulate_mlkem(pq_priv_b, pq_ct)
    return hkdf_pq_sk(material, kem_ss)


def initial_signed_payload(
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_pub_b: bytes | None,
    ik_pq_pub_a: bytes | None = None,
    pq_ct: bytes | None = None,
) -> bytes:
    return (
        ik_dh_pub_a
        + ek_pub_a
        + (opk_pub_b or b"")
        + (ik_pq_pub_a or b"")
        + (pq_ct or b"")
    )


def sign_initial(
    ik_sign_priv_a: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_pub_b: bytes | None,
    ik_pq_pub_a: bytes | None = None,
    pq_ct: bytes | None = None,
) -> bytes:
    data = initial_signed_payload(
        ik_dh_pub_a, ek_pub_a, opk_pub_b, ik_pq_pub_a, pq_ct
    )
    return Ed25519PrivateKey.from_private_bytes(ik_sign_priv_a).sign(data)


def verify_initial(
    ik_sign_pub_a: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_pub_b: bytes | None,
    signature: bytes,
    ik_pq_pub_a: bytes | None = None,
    pq_ct: bytes | None = None,
) -> None:
    data = initial_signed_payload(
        ik_dh_pub_a, ek_pub_a, opk_pub_b, ik_pq_pub_a, pq_ct
    )
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
    ik_pq_pub: bytes | None = None
    pq_ct: bytes | None = None


def build_initial_message(
    ik_sign_priv_a: bytes,
    ik_dh_pub_a: bytes,
    ek_pub_a: bytes,
    opk_pub_b: bytes | None,
    ik_pq_pub_a: bytes | None = None,
    pq_ct: bytes | None = None,
) -> InitialMessage:
    return InitialMessage(
        ik_dh_pub=ik_dh_pub_a,
        ek_pub=ek_pub_a,
        opk_pub=opk_pub_b,
        signature=sign_initial(
            ik_sign_priv_a,
            ik_dh_pub_a,
            ek_pub_a,
            opk_pub_b,
            ik_pq_pub_a,
            pq_ct,
        ),
        ik_pq_pub=ik_pq_pub_a,
        pq_ct=pq_ct,
    )
