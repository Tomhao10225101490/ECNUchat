# 基于ECDH与AES-GCM的端到端加密聊天室

利用椭圆曲线Diffie-Hellman协商会话密钥，采用AES-GCM加密消息并校验完整性，结合数字签名认证身份，实现防窃听、防篡改的安全即时通讯。

## 1. 题目三句话分别对应哪段实现

答辩时必须能对上已上报的题目，不能把项目改叫 Signal。对应关系如下。

第一句「利用椭圆曲线 Diffie-Hellman 协商会话密钥」对应 **X25519**。本仓库没有自己写曲线运算。身份协商密钥 `IK_dh`、Signed Prekey `SPK`、一次性预密钥 `OPK`、发送方临时密钥 `EK_A`、以及双棘轮里每一把发送棘轮公钥，全部是 X25519。X3DH 里最多四次 `X25519(私钥, 对方公钥)`，输出串起来作为 HKDF 的输入；双棘轮每次更换发送链，再做一次 X25519。这就是题目里的 ECDH。

第二句「采用 AES-GCM 加密消息并校验完整性」对应 **AES-256-GCM**。X3DH 得到的 32 字节 `SK` 只交给双棘轮当根密钥，绝不直接拿去加密聊天内容。对称棘轮每次吐出一把 32 字节 `MK`，用它做 AES-256-GCM，nonce 12 字节随机并随明文头发送。AAD 绑定发送方用户名、接收方用户名、序号 `N`、上一链长度 `PN` 和本方当前棘轮公钥。改一个密文字节，认证标签对不上，接收方报「GCM 失败」。

第三句「结合数字签名认证身份」对应 **Ed25519**。每个用户另有一把只签名、不做 DH 的 `IK_sign`。它签三样东西：Signed Prekey 的「SPK 公钥原始字节 || 用户名」、X3DH 初始消息里的 `IK_dh || EK_A || OPK`、以及登录时服务器下发的 32 字节随机挑战。库里没有 XEdDSA，本项目也不现写；签名和 DH 从密钥生成起就分开。

## 2. X3DH：四次 DH 各自绑定了谁

A 给 B 发会话里的第一条消息之前，向服务器拉取 B 的 bundle：`IK_dh`、`IK_sign`、`SPK`、SPK 签名、以及可选的一把 OPK（服务器弹出即删）。A 必须先用 B 的 `IK_sign` 验 SPK，失败则中止并提示「对方预密钥签名无效」。

随后 A 生成临时 X25519 密钥 `EK_A`，计算：

- DH1 = X25519(`IK_dh_A` 私钥, `SPK_B` 公钥)。把 A 的长期身份绑到 B 已经签名过的预密钥上，防止服务器随便塞一把没有身份背书的 SPK。
- DH2 = X25519(`EK_A` 私钥, `IK_dh_B` 公钥)。把这次会话的新鲜性绑到 B 的长期协商身份。
- DH3 = X25519(`EK_A` 私钥, `SPK_B` 公钥)。即使长期身份密钥以后泄露，没有 `EK_A` 也重算不出这一次的共享材料。
- 若 bundle 里有 OPK：DH4 = X25519(`EK_A` 私钥, `OPK_B` 公钥)。这把 OPK 只发一次，提供一次性的重放与批量预计算抗性。B 用对应私钥解出 SK 后立刻删除该 OPK 私钥；本地池子少于 5 把时再补到 20。

共享材料是 `DH1||DH2||DH3`，有 DH4 再接上，长度必须是 32 的倍数。然后：

`SK = HKDF-SHA256(ikm=共享材料, salt=32 个 0x00, info=b"x3dh-v1", length=32)`。

B 侧角色对调：自己的 SPK 私钥配 A 的 `IK_dh` 公钥，自己的 `IK_dh` 私钥配 `EK_A`，以此类推。单测断言双方 SK 字节级一致，有 OPK 和无 OPK 两条路径都测。初始消息还带 A 的 `IK_dh`、`EK_A`、用掉的 OPK 公钥（没有则空）以及 `IK_sign_A` 的签名；B 先验签，再核对 A 的身份密钥与服务器登记是否一致。

Fiedler 和 Günther 在 PKC 2025 分析的 PQXDH，是在这四次 DH 之外再并入一次后量子密钥封装。对外介绍写成 *PQXDH: A Post-Quantum Extension of X3DH*；正式题名是 *Security Analysis of Signal's PQXDH Handshake*。Signal 部署用 Kyber，论文也处理 ML-KEM。`initiator_secret`、`responder_secret` 和 `hkdf_sk` 的输入只有 DH 输出。预密钥目录和初始消息里没有 KEM 公钥或封装密文。后量子扩展路径是：目录公布 KEM 公钥，发起方封装，双方把 KEM 共享秘密按单独的域分离并入 HKDF，并满足他们证明所需要的 KEM 绑定。这条路径没有实现，现有 X25519 材料也不被说成后量子安全。

## 3. 对称棘轮如何给出前向安全

KDF_CK(ck)：`MK = HMAC-SHA256(ck, 0x01)`，新 `CK = HMAC-SHA256(ck, 0x02)`。同一把 `dh_pub` 下连续两条消息只走对称棘轮，MK 不同。MK 用完就从结构体删除，跳过缓存里取走的也立刻 pop，不写日志。

前向安全的时间点是「这一条的 MK 已经丢掉」。之后即便发送链密钥 CK 泄露，HMAC 单向，攻击者不能倒推出已经用过的 MK，也就解不开那一条 AES-256-GCM。这不是「一把 ECDH 会话密钥用到底」：每条消息一把 MK。

乱序时若 `n` 大于期望序号，把中间的 MK 放进键为 `dh_pub || n` 的缓存，最多 40 把，超过拒绝。已经用过的 `(dh_pub, n)` 再出现直接「重放拒绝」，不必再走 GCM。

## 4. DH 棘轮如何在对方回复后恢复

KDF_RK(rk, dh_out) = HKDF-SHA256(ikm=dh_out, salt=rk, info=b"dr-v1", length=64)，前 32 字节新 RK，后 32 字节新链密钥。

A 用 SK 和 `X25519(R_A, SPK_B)` 初始化发送链，代数为 1。B 收到第一条后用 SPK 私钥重算，得到接收链。B **第一次回复前**生成 `R_B`，把当前接收链长度记入 PN，再 `KDF_RK(RK, X25519(R_B, R_A))` 换出发送链，代数加一。A 收到新的 `dh_pub` 后，先补齐旧接收链上要跳过的序号，再用自己当时的发送私钥与 `R_B` 算出接收链，并生成新的本地棘轮公钥换掉发送链。

破密恢复不要说成瞬间发生。报告采用题目要求的时间点：对方刚回复、双方都换过棘轮公钥之后。此时旧的发送链密钥即使泄露，也不能派生新 DH 输出下的 RK 与 CK，因此解不开回复之后的新消息。若对方还没回复，A 一直用同一把 `R_A` 走对称棘轮，这一阶段没有 DH 棘轮意义上的恢复。

单测里可以看见：先发方向上的两条 MK 不同但 `dh_pub` 相同；第一条回复到达后代数加一，回复之后再发送的 MK 与更换前不同。若先单方向走三条再回，更换发生在第 4 条（对方第一次回复）；若一人一条立刻回，则第 2 条就触发。

Bienstock、Fairoze、Garg、Mukherjee 和 Raghuraman 在 CRYPTO 2022 给出通用可组合功能 `F_DR`，并证明双棘轮实现它。对外介绍把这篇称作 *A Universally Composable Analysis of the Double Ratchet*；正式题名是 *A More Complete Analysis of the Signal Double Ratchet Algorithm*。本仓库与这篇对齐的是构造，不是把 UC 证明重跑一遍。

满足的部分：

- 对称棘轮是 `kdf_ck`。`0x01` 推出一次性 `MK`，`0x02` 推出下一把链钥匙。同一把棘轮公钥下的连续消息只走这一步，提供前向安全，不提供破密恢复。
- DH 棘轮是 `kdf_rk`、`init_sender`、`_prepare_sending_chain` 和 `_dh_ratchet`。新的 X25519 输出混进根钥匙，回复并完成换链之后，旧链钥匙推不出新的消息钥匙。
- 乱序和丢包是 `_skip_message_keys`。空隙里的 `MK` 按 `dh_pub || n` 缓存，永久丢失的一条不挡住后面的消息，上限内后到的仍能解开。换链前按 `PN` 把旧链没到的 `MK` 也放进缓存。
- 消息钥匙用后即弃。`encrypt` / `decrypt` 不把已经用于 AES-256-GCM 的 `MK` 写入 `RatchetState`。`ChatEngine` 拿到返回的 `MK` 后立刻丢掉。跳过缓存里的是还没解开的 `MK`，解开时弹出。

不满足的部分：

- 没有在本仓库上建立他们的 UC 证明。证明用了可编程理想密码，把公钥棘轮 KDF 放在随机预言机里，并假定强 Diffie-Hellman。
- `dhs_priv` 必须留到对方下一把棘轮公钥到来。这个窗口里对同一方连续取走两次状态，可以拼出本轮已经发出的消息钥匙。他们的 Triple Ratchet / `F_TR` 会在算出本轮 DH 之后对私钥材料再做一次本地单向更新。本仓库保存的是完整 X25519 私钥。
- `MAX_SKIP = 40`。论文里的立即解密对多项式大小的空隙都成立，超过 40 条时这里选择拒绝。
- 报文加密是题目要求的 AES-256-GCM，头是明文。X3DH 如何得到初始 `SK` 不在 `F_DR` 的定理里。

## 5. 指纹不核对时的中间人

预密钥目录在服务器上。不核对手动指纹时，服务器可以在 `fetch_bundle` 时把 B 的 `IK_dh` / SPK / OPK 换成攻击者的，再配一把能通过验签的 `IK_sign`。Alice 会和攻击者算出 SK，攻击者再对 Bob 另建一条会话，成为中间人。`scripts/demo_attack.py` 在内存里复现了「掉包后 Alice 的 SK 不等于真实 Bob、却等于 Mallory」。

指纹是 `IK_sign` 公钥的 SHA-256，16 组、每组 4 个大写十六进制。双方用线下渠道核对之后，服务器再换公钥会被发现。此后服务器只能按用户名转发信封：它看不到口令、私钥、明文、SK、RK、CK、MK，改密文则 GCM 失败。这不是「服务器是可信的」，而是「核对指纹之后，服务器的能力被收成转发」。

## 6. 群方案为什么不是 Sender Keys

做完单聊才加群。群最多 8 人。一条群消息就是 `ChatEngine.send_text` 对每个其他成员各跑各自那条双棘轮，`_send_one` 发出 N-1 个信封；服务器按收件人分发，每个收件人只能解开发给自己的那一份。`encode_ratchet_payload` 上的群名字段只标记会话，不表示全群共用一把钥匙。密钥数随人数线性增长，所以限制 8 人。

这是对 Rösler、Mainka、Schwenk，EuroS&P 2018 的回应。对外介绍把标题收成 *More is Less: On the Security of Instant Messaging Groups*；正式题名是 *More is Less: On the End-to-End Security of Group Chats in Signal, WhatsApp, and Threema*。他们写出当时 Signal / WhatsApp 的群先用两人会话分发 Sender Key，群正文再走发送者自己的对称链。那条群链不再做 DH 棘轮，两人双棘轮上的 future secrecy 停在分发钥匙的那一刻。逐人信封让每一封仍用 `kdf_ck`，并在对方回复后走 `kdf_rk`，所以那一对的前向安全和破密恢复留在这一封上。

论文另外两块没有被这个扇出补上。成员增减和「谁有权管理群」仍然先改服务器上的成员表，再发 `kind = group_meta` 的棘轮通知。服务器少投、多投或改写成员表，不在两人棘轮的保证里。群里也没有让其他成员互相核验发送者的群签名。拉人之后，只有此后发给新成员的消息才纳入他的棘轮，旧消息不会补发给他。这不是 MLS。

## 7. 与 Signal / WhatsApp 的差别

本项目按课程步骤自己拼协议，禁止 libsignal 和现成棘轮库，便于把每一跳 DH 和每一次 HMAC 讲清楚。有意不做的部分：

- 没有多设备。一台客户端一份加密 SQLite，新设备不能拉取旧链。
- 没有 PQXDH / Kyber / ML-KEM。`src/x3dh.py` 是经典 X3DH。抗量子不在已实现的范围内；后量子扩展路径见第 2 节，没有写成代码。
- 没有 Triple Ratchet。发送棘轮私钥留到对方下一把公钥到来，CRYPTO 2022 指出的窗口还在。
- 没有密封发送者（Sealed Sender）。信封 JSON 里明文带着 `from` / `to`，服务器知道社交图，只是不知道正文。
- 没有头加密。题目允许明文头 `dh_pub, n, pn`，不再加一层，避免做跑偏。
- 身份是分离的 Ed25519 + X25519，不是 XEdDSA。

登录没有邮箱和短信：服务器发 32 字节挑战，客户端用 `IK_sign` 签名。用户名 3 到 20 位字母数字下划线，注册时服务器先验 SPK 再入库。

私钥落盘也按题目：口令经 PBKDF2-HMAC-SHA256（600000 次、16 字节盐）派生 32 字节键，再用 AES-256-GCM 封存身份私钥、尚未用掉的 OPK 私钥和棘轮会话状态。进程退出后重新登录，必须能解开 blob 继续收。服务器 SQLite 只存公钥、签名、OPK 池和离线信封；重启服务器后目录和队列还在，但它始终解不开正文。

## 8. 实现边界与偏离

KDF 标签、字段和题目一致：`x3dh-v1`、`dr-v1`、HMAC 的 `0x01` / `0x02`、AAD 的用户名与大端序号。没有用静态 ECDH 一把密钥加密全部消息。无协议偏离需要单列。密码学运算全部调用 Python `cryptography`。服务器日志禁止明文和密钥材料，聊天内容只以 base64 出现。

安全审计后又加了四层防线。第一，接收方先在棘轮状态副本上跳号、换 DH 链并尝试 GCM，认证成功才原子提交；篡改包失败后，同一序号的合法原报文仍能解开。第二，OPK 私钥同样延迟到首条密文认证成功后删除。第三，第一次获取的 `IK_sign` 与 `IK_dh` 固定在本地，后续 bundle 若变化会提示身份密钥变化并拒绝覆盖，避免核对过的指纹失效。第四，推进后的发送状态和完整待发信封一起用本地保险库密钥加密、在 SQLite 事务中落盘；崩溃后重发原信封，不会丢掉 X3DH 初始字段。题目规定的 AAD 保持不变；群名和消息类别另复制进 AES-GCM 密文，解密后必须与外层一致，服务器篡改显示语义也会被拒绝。

桌面客户端使用 PySide6，采用 Telegram 的会话信息架构和可切换的微信绿色发送气泡：左侧显示头像、消息预览、时间、持久化未读数与在线绿点，右侧自己的消息靠右、对方靠左。界面支持中文本地历史搜索、乐观发送状态、断线重连、未确认加密 outbox 恢复、主题淡入和“减少动态效果”。「已发送」只表示服务器接受信封，不伪称已读。顶栏仍是项目全名，打开会话后能看到对端指纹前八组和棘轮代数；验签失败、重放拒绝和 GCM 失败均以红色安全气泡呈现，便于答辩时指着屏幕讲「现在双方已经换过公钥」。Qt 主线程不处理任何密钥，专用工作线程独占 asyncio、WebSocket、SQLite 和 `ChatEngine`，所以 PBKDF2 与网络操作不会卡住动画。原 rich 终端界面继续保留，用于脚本化演示；两套界面复用同一个密码协议实现。

## 9. 文献与代码的对应

对外介绍以三篇为主引用。正式题名写在书目里，口头简称和全文 PDF 的对应见 `docs/papers/README.md`。可以再分发的 ePrint 都在 `docs/papers/`。

- Bienstock、Fairoze、Garg、Mukherjee、Raghuraman，CRYPTO 2022，ePrint 2022/355。对外称 *A Universally Composable Analysis of the Double Ratchet*；正式题名 *A More Complete Analysis of the Signal Double Ratchet Algorithm*。对称棘轮 `kdf_ck`，DH 棘轮 `kdf_rk` / `_dh_ratchet` / `_prepare_sending_chain`，乱序与丢包 `_skip_message_keys`，消息钥匙用后即弃在 `encrypt` / `decrypt`。满足的是这四块积木的形状。不满足 `F_TR`：`dhs_priv` 留在窗口里，没有 Triple Ratchet。也没有把他们的 UC 证明说成已经在本仓库上成立。跳过超过 40 条会拒绝。
- Fiedler、Günther，PKC 2025，ePrint 2024/702。对外称 *PQXDH: A Post-Quantum Extension of X3DH*；正式题名 *Security Analysis of Signal's PQXDH Handshake*。本仓库满足的是经典 X3DH，函数是 `initiator_secret`、`responder_secret`、`hkdf_sk`。不满足的是后量子扩展：没有 Kyber 或 ML-KEM，没有 KEM 公钥和封装密文。扩展路径是把 KEM 共享秘密按域分离并入 HKDF，这一步没有写进代码。
- Rösler、Mainka、Schwenk，EuroS&P 2018，ePrint 2017/713。对外称 *More is Less: On the Security of Instant Messaging Groups*；正式题名 *More is Less: On the End-to-End Security of Group Chats in Signal, WhatsApp, and Threema*。`ChatEngine.send_text` 对每个其他成员各发一封双棘轮信封，用来回应他们关于 Sender Keys 继承不到 future secrecy 的分析。不满足的是群成员管理的端到端保护：成员表仍在服务器上，也没有群签名。

曲线、签名、派生和 AEAD 分别是：

- Bernstein，PKC 2006，*Curve25519: new Diffie-Hellman speed records*。X25519 就是这篇里的函数，RFC 7748 规定字节格式。作者 PDF 只允许引用，仓库里留链接，不收录文件。调用点是 `x25519_dh`。
- Bernstein、Duif、Lange、Schwabe、Yang，ePrint 2011/368，*High-speed high-security signatures*。Ed25519。本仓库用它做 `IK_sign`，不实现 XEdDSA，所以签名钥匙和 DH 钥匙从生成起就是两把。
- Krawczyk，ePrint 2010/264，HKDF 的 extract-then-expand。`hkdf_sk` 用 32 个零字节做盐、`info = x3dh-v1`；`kdf_rk` 用上一把根钥匙做盐、`info = dr-v1`。对称棘轮 `kdf_ck` 不是 HKDF，而是双棘轮规范里的 HMAC，常数 `0x01` 和 `0x02`。
- McGrew、Viega，ePrint 2004/193，GCM。12 字节 nonce，16 字节标签，附加数据进 GHASH。Bellare、Tackmann，CRYPTO 2016，讨论的是一把长期 GCM 钥匙加密许多条记录时的多用户安全。本仓库每条消息一把 32 字节 `MK`，用完即弃，不把那条 TLS 定理当成聊天本身的定理。

协议证明是：

- Cohn-Gordon、Cremers、Garratt，IEEE CSF 2016，ePrint 2016/221。破密恢复的定义：秘密已经泄露之后，只要继续混入泄露时没有交出的新临时 DH，回复并完成下一轮 DH 棘轮之后的新消息可以重新变安全。回复之前只有对称链上的前向安全。
- Cohn-Gordon、Cremers、Dowling、Garratt、Stebila，IEEE EuroS&P 2017，期刊版 *Journal of Cryptology* 2020。把 X3DH 加双棘轮做成一棵阶段树，在随机预言机模型下证明消息钥匙不可区分，并给出 PRF-ODH 变体下走向标准模型的路线。他们没有在这个核心里发现重大设计缺陷。
- Alwen、Coretti、Dodis，EUROCRYPT 2019。把棘轮拆成连续密钥协商、前向安全 AEAD 和 PRF-PRNG，并正式写入立即解密。本仓库的跳过缓存就是立即解密，上限 40 把。
- Bienstock、Fairoze、Garg、Mukherjee、Raghuraman，CRYPTO 2022。见本节开头：`F_DR` 对应现有双棘轮，`F_TR` / Triple Ratchet 没有实现。
- Rösler、Mainka、Schwenk，IEEE EuroS&P 2018。见本节开头：逐人双棘轮信封回应 Sender Keys 的 future secrecy 缺口；成员表本身仍在服务器上。
- Fiedler、Günther，PKC 2025。见本节开头：分析的是 PQXDH。Bhargavan、Jacomme、Kiefer、Schmidt，USENIX Security 2024，用 ProVerif 和 CryptoVerif 核过这份规范。本仓库没有密钥封装。

这些定理没有在本仓库上重新证明。屏幕指纹只覆盖 `IK_sign`，第一次取回的 `IK_dh` 不在 `SPK` 签名里；钉住之后这一对公钥再变会被拒绝。双棘轮规范建议的报文加密是 AES-256-CBC 加 HMAC；本仓库按题目把 `MK` 直接用作 AES-256-GCM 钥匙。头 `dh_pub`、`n`、`pn` 是明文。
