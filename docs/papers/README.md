# 文献与实现的对应

对外介绍以下面三篇为主引用。三篇都可以再分发的 ePrint 全文放在本目录，书目在 [references.bib](references.bib)，许可见 [NOTICES.md](NOTICES.md)。根目录的 MIT 许可不覆盖这些 PDF。

口头介绍用的是「这篇在证明什么」。会议论文的正式题名更长。两套名字指向同一篇 PDF，引用时写正式题名。

| 对外介绍 | 正式题名 | 全文 | 落到本仓库的哪一段 |
| --- | --- | --- | --- |
| Bienstock 等，*A Universally Composable Analysis of the Double Ratchet*，CRYPTO 2022 | *A More Complete Analysis of the Signal Double Ratchet Algorithm*。Bienstock、Fairoze、Garg、Mukherjee、Raghuraman。CRYPTO 2022，LNCS 13507，pp. 782–811。DOI `10.1007/978-3-031-15802-5_27`。ePrint 2022/355 | [PDF](2022-355-bienstock-etal-double-ratchet.pdf) | `kdf_ck`、`kdf_rk`、`_skip_message_keys`、`encrypt` / `decrypt`。没有 Triple Ratchet |
| Fiedler、Günther，*PQXDH: A Post-Quantum Extension of X3DH*，PKC 2025 | *Security Analysis of Signal's PQXDH Handshake*。Fiedler、Günther。PKC 2025，LNCS 15675，pp. 137–169。DOI `10.1007/978-3-031-91823-0_5`。ePrint 2024/702 | [PDF](2024-702-fiedler-guenther-pqxdh.pdf) | `src/x3dh.py` 的混合四次 DH + ML-KEM-768（半静态 PQK），`src/double_ratchet.py` 的 `kdf_rk_pq`。没有 Kyber / 临时封装公钥 |
| Rösler、Mainka、Schwenk，*More is Less: On the Security of Instant Messaging Groups*，EuroS&P 2018 | *More is Less: On the End-to-End Security of Group Chats in Signal, WhatsApp, and Threema*。EuroS&P 2018，pp. 415–429。DOI `10.1109/EuroSP.2018.00036`。ePrint 2017/713 | [PDF](2017-713-rosler-etal-group-chats.pdf) | `ChatEngine.send_text` 对每个其他成员各发一封双棘轮信封；成员表是 `src/groups.py` 的签名哈希链 |

这三篇覆盖三件事：双棘轮在通用可组合定义下还挡住什么、经典 X3DH 的后量子扩展本仓库做了多少、群为什么不走 Sender Keys。曲线、签名、HKDF、GCM，以及 2016–2019 年的破密恢复定义和棘轮拆分，仍然对着正在调用的算法，写在下面的对照表里。

Curve25519 的设计论文可以引用，作者没有授予再分发许可，所以这里只留正式链接，不把 PDF 放进仓库。

## 对照

| 仓库里的东西 | 代码 | 文献 | 全文 |
| --- | --- | --- | --- |
| X25519，也就是题目里的椭圆曲线 Diffie-Hellman | `src/x3dh.py` 的 `x25519_dh`，`src/double_ratchet.py` 里每次换链的那一次 DH | Bernstein，PKC 2006 | [作者 PDF](https://cr.yp.to/ecdh/curve25519-20060209.pdf) |
| Ed25519 身份签名 | `src/prekeys.py`、`src/x3dh.py` 的 `sign_initial` | Bernstein、Duif、Lange、Schwabe、Yang，ePrint 2011/368 | [PDF](2011-368-bernstein-etal-ed25519.pdf) |
| 四次 DH 收成一把 `SK`，DH 棘轮收成新的根钥匙 | `hkdf_sk`、`kdf_rk` | Krawczyk，ePrint 2010/264 | [PDF](2010-264-krawczyk-hkdf.pdf) |
| 每条消息一把 `MK` 的 AES-256-GCM | `encrypt` / `decrypt` | McGrew、Viega，ePrint 2004/193；Bellare、Tackmann，ePrint 2016/564 | [GCM](2004-193-mcgrew-viega-gcm.pdf)、[多用户](2016-564-bellare-tackmann-aes-gcm.pdf) |
| 泄露之后还能不能恢复 | 回复触发的 DH 棘轮 | Cohn-Gordon、Cremers、Garratt，ePrint 2016/221 | [PDF](2016-221-cohn-gordon-etal-post-compromise.pdf) |
| X3DH 加双棘轮整条密钥调度 | `src/x3dh.py`、`src/double_ratchet.py` | Cohn-Gordon 等，ePrint 2016/1013 | [PDF](2016-1013-cohn-gordon-etal-signal.pdf) |
| 对称棘轮、DH 棘轮、乱序仍能解开 | `kdf_ck`、`kdf_rk`、`_skip_message_keys` | Alwen、Coretti、Dodis，EUROCRYPT 2019 | [PDF](2018-1037-alwen-etal-double-ratchet.pdf) |
| 主引用。双棘轮的通用可组合分析 `F_DR`，以及它还留着的窗口 | `kdf_ck`、`kdf_rk`、`encrypt` / `decrypt`、`dhs_priv`。没有 Triple Ratchet | Bienstock 等，CRYPTO 2022，ePrint 2022/355 | [PDF](2022-355-bienstock-etal-double-ratchet.pdf) |
| 主引用。群消息拆成每人一封双棘轮信封，回应 Sender Keys 的 future secrecy 缺口 | `ChatEngine.send_text`、`_send_one` | Rösler、Mainka、Schwenk，EuroS&P 2018，ePrint 2017/713 | [PDF](2017-713-rosler-etal-group-chats.pdf) |
| 主引用。同一条握手的后量子扩展。本仓库实现的是经典 X3DH | `initiator_secret`、`hkdf_sk`。无 KEM | Fiedler、Günther，PKC 2025，ePrint 2024/702 | [PDF](2024-702-fiedler-guenther-pqxdh.pdf) |

证明所依据的协议文本是两份规范，不是上面的会议论文：

- Moxie Marlinspike、Trevor Perrin。*The X3DH Key Agreement Protocol*，Revision 1，2016-11-04。<https://signal.org/docs/specifications/x3dh/>
- Trevor Perrin（编辑）、Moxie Marlinspike、Rolfe Schmidt（第 3 版起）。*The Double Ratchet Algorithm*，Revision 4，2025-11-04。<https://signal.org/docs/specifications/doubleratchet/>

字节级标准是 RFC 7748（X25519）、RFC 8032（Ed25519）、NIST SP 800-38D（GCM）和 RFC 5869（HKDF）。运算都走 Python `cryptography`，仓库里没有自写的曲线或分组密码。

## X25519

Bernstein 在 PKC 2006 给出的函数，定义在素域 `2^255-19` 上的 Montgomery 曲线 `y^2 = x^3 + 486662 x^2 + x`。Diffie-Hellman 只交换 x 坐标：32 字节标量乘 32 字节 u 坐标，输出仍是 32 字节。RFC 7748 把这个字节函数命名为 X25519，并规定标量夹紧：清掉最低 3 位，清掉最高位，置上次第高位。夹紧由 `cryptography` 完成，`x25519_dh` 只调用 `X25519PrivateKey.exchange`。

这条曲线对本仓库有三件具体的事。公钥只有 32 字节，所以预密钥、临时钥匙和棘轮公钥都能直接放进 JSON。只使用 x 坐标，双方不必再传一个 y 位。对端公钥是全零时，库会拒绝算出共享秘密；`x25519_dh` 不再包一层自己的判断。

X3DH 里最多四次调用，双棘轮每次更换发送链再调用一次。输出都是 32 字节，后面才进入 HKDF。论文给出的是这个函数的设计，不是「一把 ECDH 钥匙加密全部聊天」这种用法。会话钥匙的新鲜性来自后面的棘轮，不来自曲线本身。

## Ed25519

Bernstein、Duif、Lange、Schwabe 和 Yang 的签名用与 Curve25519 双有理等价的扭曲 Edwards 曲线。公钥 32 字节，签名 64 字节，哈希是 SHA-512。签名随机数由私钥和消息确定，签名时不必再抽一次临时随机数。这避开了 ECDSA 里同一随机数签两条消息就会泄露私钥的那类失败。论文把目标放在大约 128 比特安全、短钥匙，以及实现时秘密不进入数组下标和分支。本仓库没有实现那篇论文里的算术，调用的是 `cryptography` 的 RFC 8032。

身份钥匙从生成起就分成两把，写在 `src/prekeys.py`：

- `IK_sign` 是 Ed25519，只签名。它签三样东西：`SPK 公钥 || 用户名`、X3DH 初始消息里的 `IK_dh || EK || 用掉的 OPK`、登录挑战的 32 字节。
- `IK_dh` 是 X25519，只做 Diffie-Hellman。

Signal 用 XEdDSA，让同一把 Curve25519 身份钥匙既能签名又能做 DH。本仓库不实现 XEdDSA。因此 Ed25519 论文证明的是签名方案，X25519 论文证明的是 DH 函数。两把公钥之间的绑定是应用层的事，放在下面 X3DH 一节里说清楚。

界面上的指纹是 `IK_sign` 公钥的 SHA-256，16 组、每组 4 个大写十六进制，见 `fingerprint`。

## HKDF，以及链上的 HMAC

Krawczyk 把密钥派生拆成两步。Extract 用盐把未必均匀的输入材料收成一把伪随机钥匙。Expand 再用一个上下文字符串 `info` 把它展开成指定长度。两个不同的 `info` 得到的输出不能互相代替。RFC 5869 是同一构造的标准文本。SHA-256 的输出长度是 32 字节；调用方没有自己的盐时，标准做法就是 32 个零字节。

X3DH 的共享材料是 `DH1 || DH2 || DH3`，有一次性预密钥再接上 `DH4`，所以长度是 32 的倍数。然后：

```text
SK = HKDF-SHA256(ikm = 共享材料, salt = 32 个 0x00, info = b"x3dh-v1", length = 32)
```

这是 `hkdf_sk`。`SK` 只交给双棘轮做根，不加密聊天内容。

DH 棘轮用的是同一篇论文里盐本身也保密的那种用法。盐是上一把根钥匙，输入材料是这一次的 DH 输出，`info` 是 `b"dr-v1"`，展开 64 字节，前 32 字节是新根钥匙，后 32 字节是新链钥匙。这是 `kdf_rk`。`x3dh-v1` 和 `dr-v1` 不同，两次派生不会撞车。

对称棘轮不是 HKDF。它是双棘轮规范建议的 `KDF_CK`：

```text
MK     = HMAC-SHA256(key = ck, msg = 0x01)
下一把 CK = HMAC-SHA256(key = ck, msg = 0x02)
```

这是 `kdf_ck`。HMAC 单向性是前向安全在对称这一侧的原因：链钥匙往后走了，推不回已经用过的 `MK`。同一把棘轮公钥下面连续两条消息只走这一步，所以两把 `MK` 不同，头里的 `dh_pub` 相同。

## AES-256-GCM

McGrew 和 Viega 定义 GCM：计数器模式加密，再用二元域 `GF(2^128)` 上的 GHASH 做认证。初始化向量可以是任意长度，12 字节是不必再对向量做一次 GHASH 的那一档，也是他们建议的高速用法。认证标签覆盖密文和附加数据。附加数据只被认证，不被加密。

`encrypt` 对每一把 `MK` 做一次 `AESGCM.encrypt`。nonce 是 `os.urandom(12)`，随信封明文发送。库把 16 字节标签接在密文后面。短于 16 字节的密文在进 GCM 之前就拒绝。附加数据是：

```text
发送方用户名 UTF-8
|| 接收方用户名 UTF-8
|| N 的 4 字节大端
|| PN 的 4 字节大端
|| 当前棘轮公钥
```

密文换到另一对用户、改序号，或者换一把棘轮公钥，标签都对不上，界面报「GCM 失败」。解密先在棘轮状态的副本上做，标签通过才提交。伪造包不会把后面那条合法消息的钥匙提前烧掉。

Bellare 和 Tackmann 在 CRYPTO 2016 研究的是另一件事：同一把 GCM 钥匙加密很多条记录、很多个用户同时在用时，安全性如何下降，以及 TLS 1.3 讨论过的 nonce 随机化是在补这个多用户损失。同一把钥匙下 nonce 重复，GCM 的认证钥匙可以恢复。本仓库的聊天不处于那种「一把长期 GCM 钥匙、很多条记录」的用法。`MK` 是 32 字节，一条消息用一次，用完就从链上丢掉。同一把 `MK` 下面不存在第二次加密，因此也不存在这把钥匙上的 nonce 重复。256 比特的消息钥匙是为了让每条记录自己带一把完整的 AES-256 钥匙，而不是把一条 TLS 记录层的定理直接说成聊天的定理。

双棘轮规范建议的报文加密是另一套：把消息钥匙再用 HKDF 拆成加密钥匙、MAC 钥匙和初始向量，然后 AES-256-CBC 加 HMAC。本仓库按题目使用 AES-256-GCM，`MK` 直接就是 GCM 钥匙，nonce 在钥匙调度之外单独随机。Alwen 等人把报文加密收成独立的前向安全 AEAD 模块，棘轮证明不绑定 CBC。换上 AES-256-GCM 改的是这个模块，不改四次 DH 和两条 KDF 的形状。

## 破密恢复这个词

Cohn-Gordon、Cremers 和 Garratt 在 CSF 2016 把「对方的秘密已经泄露，以后的通信还能不能重新变安全」定义成 post-compromise security。长期身份钥匙一旦交出，传统密钥交换允许对手一直冒充这个人。他们指出，如果协议还会继续混入双方都没有在泄露时交出的新临时秘密，泄露之后的某一段可以重新变安全。Signal 文档里的 future secrecy 指的是同一类性质。

本仓库把这个时间点说死，避免说成「一泄露就立刻恢复」。对方回复、双方都换过棘轮公钥之后，旧的链钥匙推不出新的 DH 输出，也就解不开回复之后的新消息。回复发生之前，发送方还在旧的对称链上，这一段只有前向安全，没有 DH 棘轮意义上的恢复。前向安全是另一方向：这条消息的 `MK` 已经丢掉，后面的链钥匙泄露也倒推不回来。

## X3DH，以及多阶段证明

发起方在 `initiator_secret` 里按 X3DH 规范的顺序算四次，应答方在 `responder_secret` 里把角色对调。没有一次性预密钥时双方都省略第四次，`SK` 仍然要逐字节相同。

- DH1 = X25519(`IK_dh` 私钥, 对方 `SPK`)。把发起方的长期协商身份绑到对方签过名的预密钥上。
- DH2 = X25519(`EK` 私钥, 对方 `IK_dh`)。把这一次的临时钥匙绑到对方的长期协商身份。
- DH3 = X25519(`EK` 私钥, 对方 `SPK`)。长期身份以后泄露时，没有当时的 `EK`，重算不出这一次的材料。
- DH4 仅在拿到一次性预密钥时计算。服务器把这把公钥只发出去一次；接收方在第一条密文认证成功之后删除对应私钥。

Cohn-Gordon、Cremers、Dowling、Garratt 和 Stebila 把 Signal 的 X3DH 加上双棘轮抽成一个多阶段认证密钥交换。阶段排成一棵树，而不是一根线：每次 DH 棘轮开出新的链，每条链上又有很多把消息钥匙。他们在随机预言机模型下证明消息钥匙的不可区分性，并写出一条用 PRF-ODH 变体走向标准模型的路线。前向安全和破密恢复都表达成：哪些妥协发生之后，哪些阶段的钥匙仍然不可区分。他们对这个核心没有发现设计上的重大缺陷。期刊版是 *Journal of Cryptology* 2020。证明的对象是他们从实现里抽出的密钥调度，不是整个客户端。

和那篇证明逐条对齐时，本仓库有三处必须单独说：

1. 规范里签预密钥的身份钥匙就是做 DH 的那一把，靠 XEdDSA 合在一起。本仓库是两把钥匙。`SPK` 的签名输入是 `SPK 公钥 || 用户名`，不包含 `IK_dh`。屏幕上的指纹只覆盖 `IK_sign`。`fetch_bundle` 第一次返回时，`IK_sign` 和 `IK_dh` 会作为一对被钉住；以后这一对变了，客户端报「身份密钥发生变化」并拒绝覆盖。钉住之前，目录给出的 `IK_dh` 不在 `SPK` 签名里，也不在那串指纹里。发起方自己的 `IK_dh` 会放进初始消息，并由自己的 `IK_sign` 签名；应答方会先验这个签名，再核对它和目录里的登记是否同一把。
2. 规范把双方身份放进第一条消息的 AEAD 附加数据。本仓库改为用 Ed25519 签 `IK_dh || EK || OPK`。
3. KDF 的 `info` 用的是题目里的 `x3dh-v1` 和 `dr-v1`，不是 Signal 应用自己选的上下文字符串。派生的形状与规范建议的 `KDF_RK`、`KDF_CK` 一致：根钥匙做 HKDF 的盐，DH 输出做输入材料；链钥匙做 HMAC 的钥匙，常数是 `0x01` 和 `0x02`。

头也不加密。`dh_pub`、`n`、`pn` 在信封里是明文。证明保证的是没有消息钥匙就解不开正文。服务器看得到谁在和谁通信，也看得到当前棘轮公钥和序号。

## 双棘轮的三块积木

Alwen、Coretti 和 Dodis 在 EUROCRYPT 2019 给安全消息传递一个同时包含三件事的定义：前向安全、破密恢复，以及立即解密。立即解密是指一条消息永久丢失时，后面的消息照样能解，丢失的那一条如果后来到了也还能解。他们把广义的 Signal 拆成三块：

- 连续密钥协商，对应公钥棘轮。现在的 Signal 用 Diffie-Hellman 做；换成一般公钥加密就能留出后量子的位置，那一档分析可以不依赖随机预言机。本仓库用的是 Diffie-Hellman 这一档，没有做替换。
- 前向安全 AEAD，对应对称棘轮。链是确定的，所以它提供前向安全，不提供破密恢复。
- PRF-PRNG，对应把 DH 输出混进根钥匙的那次 HKDF。它的第一个输入要像伪随机函数的钥匙，第二个输入要像伪随机生成器的种子。

乱序靠跳过缓存实现立即解密。收到的序号比期望序号大时，中间那些 `MK` 先算出来，键是 `dh_pub || n`。缓存最多 40 把，再大就拒绝，避免一个巨大序号迫使客户端派生无界多的钥匙。这 40 把是实现上的上限；论文里的立即解密对多项式大小的空隙都成立。已经处理过的 `(dh_pub, n)` 再出现，直接「重放拒绝」。换到新的 DH 链之后，旧链里按 `PN` 缓存过的迟到消息仍用缓存里的那把 `MK`。

Bienstock、Fairoze、Garg、Mukherjee 和 Raghuraman 在 CRYPTO 2022 给出通用可组合定义 `F_DR`，并证明双棘轮实现它。对外介绍因此把这篇称作 *A Universally Composable Analysis of the Double Ratchet*；会议正式题名是 *A More Complete Analysis of the Signal Double Ratchet Algorithm*。模型用了可编程理想密码。这个定义把妥协之后立刻能做的选择密文类注入也算进去，并构造了六种改动过的双棘轮：它们在 2017 或 2019 的定义下仍算安全，在 `F_DR` 下不安全。双棘轮本身抵抗这些改动所对应的攻击。他们对 `F_DR` 的证明把公钥棘轮的 KDF 放在随机预言机里，并假定强 Diffie-Hellman，用来得到密文不可延展。2019 年那篇在不含这类篡改的定义下，用判定性 Diffie-Hellman 就够了。X3DH 如何得到初始共享秘密不在他们的定理里；本仓库把 `SK` 交给 `init_sender` / `init_receiver` 之后才进入这篇讨论的范围。

和 `src/double_ratchet.py` 的对应是：

- 对称棘轮，文中的 inner symmetric-key ratchet，是 `kdf_ck`。常数 `SYMMETRIC_RATCHET_MK_LABEL`（`0x01`）推出一次性 `MK`，`SYMMETRIC_RATCHET_CK_LABEL`（`0x02`）推出下一把链钥匙。同一把 `dh_pub` 下连续消息只走这一步。它提供前向安全，不提供破密恢复。
- DH 棘轮，文中的 public ratchet，是 `kdf_rk`、`init_sender`、`_prepare_sending_chain` 和 `_dh_ratchet`。一次 X25519 输出混进根钥匙，展开成新的根钥匙和链钥匙，序号归零。界面上的代数加一就是新的发送世代。
- 乱序和丢包，文中的 immediate decryption，是 `_skip_message_keys`。序号跳空时先把中间的 `MK` 放进 `skipped`，键是 `dh_pub || n`。永久丢掉的一条不挡住后面的消息；它若在上限内后到，仍用缓存里的那把 `MK`。换到新的 DH 链之前，按头里的 `PN` 把旧链上没到的 `MK` 也放进同一缓存。
- 消息钥匙用后即弃：`encrypt` 和 `decrypt` 不把已经用于 AES-256-GCM 的 `MK` 写进 `RatchetState`。`ChatEngine._send_one` 和 `_decrypt_envelope` 拿到返回的 `MK` 后立刻丢掉。跳过缓存里的 `MK` 要留到对应密文到来，解开时弹出。他们的变换 T1 是另一件事：把已经不需要的上一发送世代对称秘密继续留在状态里，妥协之后可以注入。本仓库在进入下一世代时不再保留上一把链钥匙。

本实现跟着写的是上面这四块积木的形状。没有在本仓库上重做 UC 证明。证明用的可编程理想密码、随机预言机和强 Diffie-Hellman，都不能从这段 Python 里读出来。报文加密是题目要求的 AES-256-GCM，头 `dh_pub`、`n`、`pn` 是明文。`MAX_SKIP = 40` 是实现上限；论文里的立即解密对多项式大小的空隙都成立，超过 40 条时本仓库选择拒绝。

同一篇文章写出双棘轮还留着的窗口，本仓库不满足他们用来补这个窗口的 `F_TR`。发送方必须把这一轮的棘轮私钥留到收到对方的下一把棘轮公钥，否则算不出下一次 DH。状态里的 `dhs_priv` 就是这把私钥。同一个人在这个窗口里被连续取走两次状态，两次快照可以拼出这一轮的消息钥匙，包括两次取走之间已经发出的那些。这既碰到他们期望的破密恢复，也碰到前向安全。2017 和 2019 的定义都没有把这个窗口写进去。他们的 Triple Ratchet 在算出本轮 DH 之后，对留下来的私钥材料再做一次本地单向更新，线上仍然只传一个群元素。`src/double_ratchet.py` 留着的是完整 X25519 私钥，没有这层更新。

## 群为什么是每人一封

Rösler、Mainka 和 Schwenk 在 EuroS&P 2018 写下当时 Signal、WhatsApp 和 Threema 的群机制。对外介绍把标题收成 *More is Less: On the Security of Instant Messaging Groups*；正式题名是 *More is Less: On the End-to-End Security of Group Chats in Signal, WhatsApp, and Threema*。他们给动态群一个同时考虑机密性、完整性和成员管理的模型。分析结论有三块：消息完整性没有端到端保护，群的 closeness（谁有权管理成员）没有端到端保护，以及两人会话上的 future secrecy 不会自动继承到 Signal / WhatsApp 的群正文。

他们分析的 Signal / WhatsApp 群，是先用两人会话把一把发送者钥匙分发出去，群正文再走这把发送者自己的对称链。那条群链不再做 DH 棘轮，所以两人双棘轮上的破密恢复停在分发钥匙的那一刻。

本仓库的回应写在 `ChatEngine.send_text`。一条群消息对其他每个成员各跑那一对已经建立的双棘轮，`_send_one` 发出独立信封，`encode_ratchet_payload` 上的 `group` 字段只标记这封信属于哪个群。服务器按收件人分发。没有全群共用的 Sender Key，也没有一条群对称链。每一封仍走 `kdf_ck` 和后续回复触发的 `kdf_rk`，所以那一对的前向安全、以及回复之后的破密恢复，留在这一封上。人数增加，信封数量线性增加，所以 `MAX_GROUP_MEMBERS = 8`。新成员只进入之后的消息；旧的 `MK` 已经丢掉，不会把历史补发给他。

这个选择回应的是论文里 future secrecy 到不了群正文的那一条。成员名单这块，本仓库补成 `src/groups.py` 的签名哈希链：创世状态由创建者签署，拉人状态由上一状态成员签署、成员只增一人、前驱哈希链接；服务器入库前验签，客户端收 `group_update` 时再独立验签，群消息密文里带 `gstate` 绑定到发送者所用的群状态。伪造的成员表（幽灵成员、给不同成员看不同名单）在客户端被拒绝或通过断链暴露，服务器只剩漏投。群里仍没有让其他成员互相核验「这条群消息确实来自声称的发送者」的群签名；每个收件人只能核对自己那一封的 GCM 标签。

## 后量子握手，以及本仓库做了多少

Fiedler 和 Günther 在 PKC 2025 分析 Signal 已经部署的 PQXDH。对外介绍把对象写成 *PQXDH: A Post-Quantum Extension of X3DH*；论文正式题名是 *Security Analysis of Signal's PQXDH Handshake*。PQXDH 保留 X3DH 的 Diffie-Hellman 组合，再加一个后量子密钥封装（部署里用的是 Kyber；他们也处理后来的 ML-KEM）。会话钥匙要在「最大暴露」模型里安全：长期钥匙、半静态的签名预密钥、临时钥匙都可以被细粒度地妥协，对手可以是经典的，也可以是量子的。先记录握手、等以后的量子计算机打破 X25519，这种 harvest-now-decrypt-later 要由密钥封装那一项挡住，前提是封装的秘密当时没有泄露。

他们的归约需要密钥封装的一个绑定性质，并证明 Kyber 和 ML-KEM 满足他们定义的那一版。缺少域分离会把具体安全界降下来。Bhargavan、Jacomme、Kiefer 和 Schmidt 在 USENIX Security 2024 用 ProVerif 和 CryptoVerif 核过同一份规范，并把发现送回修订版。那篇的全文在 USENIX 页面：<https://www.usenix.org/conference/usenixsecurity24/presentation/bhargavan>。USENIX 的版本不放进本仓库。

本仓库实现了这条路径，但停在「半静态 KEM 公钥」版本：目录里公布一把由身份签名的长期 PQK（ML-KEM-768，`sign_pq` 对「PQK 公钥 || 用户名」签名），发起方封装，KEM 共享秘密按 `info = b"pqxdh-v1"` 与经典 `x3dh-v1` 域分离后并入 HKDF（`initiator_hybrid_secret` / `responder_hybrid_secret` / `hkdf_pq_sk`）。KEM 绑定用两层处理：目录里的 PQK 公钥由身份签名背书，初始消息的 IK_sign 签名覆盖 `IK_dh || EK_A || OPK || IK_PQ || PQ_CT`。没有实现临时封装公钥那一版，也没有 Kyber。双棘轮侧的配合在 `kdf_rk_pq`（`info = b"pq-dr-v1"`）：每次换链对长期 PQK 重新封装，密文随链外带，双方都固定对端 PQK 后缺失即拒（防降级）；旧会话在收发前补拉 bundle 核验签名后升级。这不改变经典四次 DH 的顺序，也不把 X25519 输出说成后量子。

## 答辩时不能说成什么

上面的定理没有被在本仓库上重新跑过，也没有做机器证明。它们说明这些构造为什么是现在这样，以及哪些安全结论依赖哪些假设。

不能从这些 PDF 推出的话有四句。第一，PySide6 界面、服务器转发和 SQLite 保险库不在任何一篇的定理里。保险库是 PBKDF2-HMAC-SHA256、600000 次、16 字节盐，再 AES-256-GCM，只保护本机私钥和棘轮状态。第二，2019 和 2022 的立即解密没有 40 条上限；超过 40 条空隙时本仓库选择拒绝。第三，2022 年的 Triple Ratchet 是论文给出的更强构造，代码里没有；2025 年的 PQXDH 只实现了半静态 KEM 公钥那一版，且没有在他们的证明模型里重跑安全界。第四，屏幕指纹不覆盖 `IK_dh`；第一次取 bundle 时，协商身份和签名身份的绑定弱于 XEdDSA 那一版 Signal。钉住之后，这一对公钥再变会被拒绝。
