# 基于ECDH与AES-GCM的端到端加密聊天室

利用椭圆曲线Diffie-Hellman协商会话密钥，采用AES-GCM加密消息并校验完整性，结合数字签名认证身份，实现防窃听、防篡改的安全即时通讯。

## 1. 题目三句话分别对应哪段实现

答辩时必须能对上已上报的题目，不能把项目改叫 Signal。对应关系如下。

第一句「利用椭圆曲线 Diffie-Hellman 协商会话密钥」对应 **X25519**。本仓库没有自己写曲线运算。身份协商密钥 `IK_dh`、Signed Prekey `SPK`、一次性预密钥 `OPK`、发送方临时密钥 `EK_A`、以及双棘轮里每一把发送棘轮公钥，全部是 X25519。X3DH 里最多四次 `X25519(私钥, 对方公钥)`，输出串起来作为 HKDF 的输入；双棘轮每次更换发送链，再做一次 X25519。这就是题目里的 ECDH。

第二句「采用 AES-GCM 加密消息并校验完整性」对应 **AES-256-GCM**。X3DH 得到的 32 字节 `SK` 只交给双棘轮当根密钥，绝不直接拿去加密聊天内容。对称棘轮每次吐出一把 32 字节 `MK`，用它做 AES-256-GCM，nonce 12 字节随机并随明文头发送。AAD 绑定发送方用户名、接收方用户名、序号 `N`、上一链长度 `PN` 和本方当前棘轮公钥。改一个密文字节，认证标签对不上，接收方报「GCM 失败」。

第三句「结合数字签名认证身份」对应 **Ed25519**。每个用户另有一把只签名、不做 DH 的 `IK_sign`。它签这些东西：Signed Prekey 的「SPK 公钥原始字节 || 用户名」、长期 PQK 的「PQK 公钥 || 用户名」、一次性 PQOPK 的「前缀 pq-opk-v1 || 公钥 || 用户名」、初始消息里的 `IK_dh || EK_A || OPK || IK_PQ || PQ_EK || PQ_CT`、以及登录时服务器下发的 32 字节随机挑战。库里没有 XEdDSA，本项目也不现写；签名和 DH 从密钥生成起就分开。

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

Fiedler 和 Günther 在 PKC 2025 分析的 PQXDH，是在这四次 DH 之外再并入一次后量子密钥封装。对外介绍写成 *PQXDH: A Post-Quantum Extension of X3DH*；正式题名是 *Security Analysis of Signal's PQXDH Handshake*。Signal 部署用 Kyber，论文也处理 ML-KEM。本仓库实现了这条路径，并补上规范里的一次性封装公钥：每个用户注册时生成 ML-KEM-768 长期密钥 `PQK`，以及 8 把一次性 `PQOPK`。长期公钥由 `IK_sign` 对（PQK 公钥 || 用户名）签名；一次性公钥的签名输入带前缀 `pq-opk-v1`，与长期钥域分离（`src/prekeys.py`）。

发起会话时优先封装到 `PQOPK`。服务器不提供时，封装到签过名的长期 `PQK`。SK 的派生是

`SK = HKDF-SHA256(ikm=DH1||DH2||DH3[||DH4]||ss||SHA-256(封装公钥), salt=32 个 0x00, info=b"pqxdh-v1", length=32)`，

对应 `initiator_hybrid_secret`、`responder_hybrid_secret` 和 `hkdf_pq_sk`，与经典 `x3dh-v1` 域分离。初始消息的 `IK_sign` 覆盖 `IK_dh || EK_A || OPK || IK_PQ || PQ_EK || PQ_CT`。换掉封装公钥或 KEM 密文的任一字节，验签即失败。首条 GCM 成功后才删除用掉的 `PQOPK` 私钥。两端都支持 PQ 时，接收方拒绝没有 PQ 的经典初始消息。服务器可以扣留一次性钥，迫使这次握手使用长期 `PQK`；不能把 KEM 整个拿掉。没有实现 Kyber，也没有把 X25519 材料说成后量子。`scripts/demo_paper_binding.py` 把这几句直接打出来。

## 3. 对称棘轮如何给出前向安全

KDF_CK(ck)：`MK = HMAC-SHA256(ck, 0x01)`，新 `CK = HMAC-SHA256(ck, 0x02)`。同一把 `dh_pub` 下连续两条消息只走对称棘轮，MK 不同。MK 用完就从结构体删除，跳过缓存里取走的也立刻 pop，不写日志。

前向安全的时间点是「这一条的 MK 已经丢掉」。之后即便发送链密钥 CK 泄露，HMAC 单向，攻击者不能倒推出已经用过的 MK，也就解不开那一条 AES-256-GCM。这不是「一把 ECDH 会话密钥用到底」：每条消息一把 MK。

乱序时若 `n` 大于期望序号，把中间的 MK 放进键为 `dh_pub || n` 的缓存，最多 40 把，超过拒绝。已经用过的 `(dh_pub, n)` 再出现直接「重放拒绝」，不必再走 GCM。

## 4. DH 棘轮如何在对方回复后恢复

KDF_RK(rk, dh_out) = HKDF-SHA256(ikm=dh_out, salt=rk, info=b"dr-v1", length=64)，前 32 字节新 RK，后 32 字节新链密钥。

A 用 SK 和 `X25519(R_A, SPK_B)` 初始化发送链，代数为 1。B 收到第一条后用 SPK 私钥重算，得到接收链。B **第一次回复前**生成 `R_B`，把当前接收链长度记入 PN，再 `KDF_RK(RK, X25519(R_B, R_A))` 换出发送链，代数加一。A 收到新的 `dh_pub` 后，先补齐旧接收链上要跳过的序号，再用自己当时的发送私钥与 `R_B` 算出接收链，并生成新的本地棘轮公钥换掉发送链。

破密恢复不要说成瞬间发生。报告采用题目要求的时间点：对方刚回复、双方都换过棘轮公钥之后。此时旧的发送链密钥即使泄露，也不能派生新 DH 输出下的 RK 与 CK，因此解不开回复之后的新消息。若对方还没回复，A 一直用同一把 `R_A` 走对称棘轮，这一阶段没有 DH 棘轮意义上的恢复。

单测里可以看见：先发方向上的两条 MK 不同但 `dh_pub` 相同；第一条回复到达后代数加一，回复之后再发送的 MK 与更换前不同。若先单方向走三条再回，更换发生在第 4 条（对方第一次回复）；若一人一条立刻回，则第 2 条就触发。

混合棘轮（本仓库对「先记录、后打破」的棘轮侧回应）：每次开出新发送链，除 DH 输出外再对对方长期 `PQK` 公钥做一次新鲜封装，`KDF_RK_PQ(rk, dh_out, ss) = HKDF-SHA256(ikm=dh_out||ss, salt=rk, info=b"pq-dr-v1", length=64)`，对应 `src/double_ratchet.py` 的 `kdf_rk_pq`。封装目标是长期 `PQK`，不是握手里用过即删的 `PQOPK`。封装密文 `pq_ct` 随该链每条消息外带，收链方用自己的 `PQK` 私钥解封后并入同一次派生。双方都记录了对方 `PQK` 之后，新链缺 `pq_ct` 即拒绝（防降级）；篡改 `pq_ct` 导致解封失败或 GCM 失败。旧会话迁移是渐进的：收发前自动补拉 bundle 核验 PQK 签名（`ChatEngine._upgrade_pq_key`），这次补拉不消耗一次性 `PQOPK`。升级前的旧消息仍为经典密文，升级后不再依赖 X25519 的抗量子性。长期 `PQK` 泄露后，之后的混合棘轮退回经典 DH 保障；已经删掉私钥的一次性握手不受这次泄露打开。这也不是 Triple Ratchet，`dhs_priv` 的窗口照旧。同一把长期公钥的 ML-KEM 对象按原始字节缓存，换链时不再每次从种子重建。

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

论文另外两块没有被这个扇出补上。成员增减和「谁有权管理群」在本仓库补成**签名哈希链的群状态**（`src/groups.py`）：创世状态由创建者签名，成员表里只有创建者；每次拉人是一条新状态，纪元加一、成员只增一人、前驱哈希指向上一条、签署者必须是上一状态成员。对方先在服务器的邀请表上点同意，邀请人或审批人的客户端再补签。服务器入库前验签，客户端收 `group_update` 时再独立验签；群消息密文里带 `gstate`（发送者所用状态的 SHA-256），接收方只接受「状态在已验证链上且发送者在该成员表里」的消息。`scripts/demo_group_attack.py` 演示服务器伪造成员表被拒绝。于是服务器做不到幽灵成员和名单分歧，只剩漏投（DoS），漏投由 `group_sync` 补链暴露。同意本身不在签名里：恶意服务器可以谎称对方已经同意，邀请人的客户端会签下拉人状态。群里仍然没有让其他成员互相核验发送者的群签名。拉人之后，只有此后发给新成员的消息才纳入他的棘轮，旧消息不会补发给他。这不是 MLS。

## 7. 与 Signal / WhatsApp 的差别

本项目按课程步骤自己拼协议，禁止 libsignal 和现成棘轮库，便于把每一跳 DH 和每一次 HMAC 讲清楚。有意不做的部分：

- 没有多设备。一台客户端一份加密 SQLite，新设备不能拉取旧链。
- 没有 Kyber。握手是 X25519 + ML-KEM-768 的混合 PQXDH：优先一次性 PQOPK，否则长期 PQK。混合棘轮在换链时重新封装长期 PQK；见第 2、4 节。
- 没有 Triple Ratchet。发送棘轮私钥留到对方下一把公钥到来，CRYPTO 2022 指出的窗口还在。
- 没有密封发送者（Sealed Sender）。信封 JSON 里明文带着 `from` / `to`，服务器知道社交图，只是不知道正文。
- 没有头加密。题目允许明文头 `dh_pub, n, pn`，不再加一层，避免做跑偏。
- 身份是分离的 Ed25519 + X25519，不是 XEdDSA。

登录没有邮箱和短信：服务器发 32 字节挑战，客户端用 `IK_sign` 签名。用户名 3 到 20 位字母数字下划线，注册时服务器先验 SPK 再入库。

私钥落盘也按题目：口令经 PBKDF2-HMAC-SHA256（600000 次、16 字节盐）派生 32 字节键，再用 AES-256-GCM 封存身份私钥、尚未用掉的 OPK / PQOPK 私钥和棘轮会话状态。进程退出后重新登录，必须能解开 blob 继续收。服务器 SQLite 只存公钥、签名、OPK 池、PQOPK 公钥和离线信封；重启服务器后目录和队列还在，但它始终解不开正文。

## 8. 实现边界与偏离

KDF 标签、字段和题目一致：`x3dh-v1`、`dr-v1`、HMAC 的 `0x01` / `0x02`、AAD 的用户名与大端序号；扩展新增 `pqxdh-v1`、`pq-dr-v1` 与 ML-KEM 封装，经典路径保留并域分离。没有用静态 ECDH 一把密钥加密全部消息。密码学运算全部调用 Python `cryptography`（ML-KEM 需要 44.0+）。服务器日志禁止明文和密钥材料，聊天内容只以 base64 出现。

安全审计后又加了四层防线。第一，接收方先在棘轮状态副本上跳号、换 DH 链并尝试 GCM，认证成功才原子提交；篡改包失败后，同一序号的合法原报文仍能解开。第二，OPK 私钥同样延迟到首条密文认证成功后删除。第三，第一次获取的 `IK_sign`、`IK_dh` 与 `IK_PQ` 固定在本地，后续 bundle 若变化会提示身份密钥变化并拒绝覆盖，避免核对过的指纹失效。第四，推进后的发送状态和完整待发信封一起用本地保险库密钥加密、在 SQLite 事务中落盘；崩溃后重发原信封，不会丢掉 X3DH 初始字段。题目规定的 AAD 保持不变；群名和消息类别另复制进 AES-GCM 密文，解密后必须与外层一致，服务器篡改显示语义也会被拒绝。

研究生扩展部分另加五道检查。第一，群状态是签名哈希链，客户端端到端验证 `group_update` 和每条群消息的 `gstate` 绑定，伪造成员表被拒绝（见第 6 节）。第二，混合握手优先使用一次性 PQOPK，封装公钥与 KEM 密文都进身份签名，HKDF 再混入封装公钥的 SHA-256；PQ 握手缺失即拒绝降级。第三，一次性私钥只在首条 GCM 成功后删除，服务器补拉长期 PQK 时不消耗这把钥。第四，混合棘轮的新链缺 `pq_ct` 即拒绝，`pq_ct` 篡改导致解封失败，同样拒绝。第五，旧会话迁移只在核验 PQK 签名并固定后才把链升级为混合，升级前后消息钥匙域分离，升级不可逆（`remote_pq_pk` 一旦固定即要求 PQ）。

桌面客户端使用 PySide6，版式对齐 Telegram 桌面版：左列会话列表，右列聊天，菜单里进入联系人、朋友圈、文件和设置。可切换夜间、微信绿和日间。左侧显示头像、消息预览、时间、持久化未读数与在线绿点，右侧自己的消息靠右、对方靠左。界面支持中文本地历史搜索、乐观发送状态、断线重连、未确认加密 outbox 恢复、主题淡入和“减少动态效果”。「已发送」只表示服务器接受信封，不伪称已读。打开会话后能看到对端指纹摘要和棘轮代数；验签失败、重放拒绝和 GCM 失败均以红色安全气泡呈现，便于答辩时指着屏幕讲「现在双方已经换过公钥」。Qt 主线程不处理任何密钥，专用工作线程独占 asyncio、WebSocket、SQLite 和 `ChatEngine`，所以 PBKDF2 与网络操作不会卡住动画。原 rich 终端界面继续保留，用于脚本化演示；两套界面复用同一个密码协议实现。

好友关系、资料、隐私开关、朋友圈，以及入群邀请和入群申请，存在服务器 SQLite 里，不进双棘轮，服务器看得到这些字段。私聊必须先成为好友。建群时创世状态只有创建者；拉人除了签名群状态，还要求对方已经同意，并且发起人与对方已是好友。没有消息的群仍留在创建者的会话列表里。好友可以按群名搜到群并申请加入，不是好友的私密群搜不到。文件走分块密文附件，服务器只存密文块。

## 9. 文献与代码的对应

对外介绍以三篇为主引用。正式题名写在书目里，口头简称和全文 PDF 的对应见 `docs/papers/README.md`。可以再分发的 ePrint 都在 `docs/papers/`。

- Bienstock、Fairoze、Garg、Mukherjee、Raghuraman，CRYPTO 2022，ePrint 2022/355。对外称 *A Universally Composable Analysis of the Double Ratchet*；正式题名 *A More Complete Analysis of the Signal Double Ratchet Algorithm*。对称棘轮 `kdf_ck`，DH 棘轮 `kdf_rk` / `_dh_ratchet` / `_prepare_sending_chain`，乱序与丢包 `_skip_message_keys`，消息钥匙用后即弃在 `encrypt` / `decrypt`。满足的是这四块积木的形状。不满足 `F_TR`：`dhs_priv` 留在窗口里，没有 Triple Ratchet。也没有把他们的 UC 证明说成已经在本仓库上成立。跳过超过 40 条会拒绝。
- Fiedler、Günther，PKC 2025，ePrint 2024/702。对外称 *PQXDH: A Post-Quantum Extension of X3DH*；正式题名 *Security Analysis of Signal's PQXDH Handshake*。本仓库实现混合 PQXDH，函数是 `initiator_hybrid_secret`、`responder_hybrid_secret`、`hkdf_pq_sk`。握手优先封装一次性 PQOPK，否则封装签过名的长期 PQK；封装公钥进 HKDF，也进初始消息签名。不满足的是没有 Kyber，也没有在他们的证明模型里重跑安全界。服务器仍可扣留一次性钥。混合棘轮的封装目标仍是长期 PQK，这把长期钥泄露后新链退回经典 DH。
- Rösler、Mainka、Schwenk，EuroS&P 2018，ePrint 2017/713。对外称 *More is Less: On the Security of Instant Messaging Groups*；正式题名 *More is Less: On the End-to-End Security of Group Chats in Signal, WhatsApp, and Threema*。`ChatEngine.send_text` 对每个其他成员各发一封双棘轮信封，用来回应他们关于 Sender Keys 继承不到 future secrecy 的分析。成员表方面补上 `src/groups.py` 的签名哈希链与消息 `gstate` 绑定。入群要先在服务器邀请表上同意，再由当前成员签名。不满足的是把同意放进端到端协商，以及群签名。恶意服务器可以谎称对方已经同意。

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
- Rösler、Mainka、Schwenk，IEEE EuroS&P 2018。见本节开头：逐人双棘轮信封回应 Sender Keys 的 future secrecy 缺口；成员表由签名哈希链端到端保护，伪造成员表被拒。
- Fiedler、Günther，PKC 2025。见本节开头：分析的是 PQXDH，本仓库实现其混合握手。Bhargavan、Jacomme、Kiefer、Schmidt，USENIX Security 2024，用 ProVerif 和 CryptoVerif 核过这份规范；本仓库的混合实现没有在证明器里重新建模。

这些定理没有在本仓库上重新证明。屏幕指纹只覆盖 `IK_sign`，第一次取回的 `IK_dh` 不在 `SPK` 签名里；钉住之后这一对公钥再变会被拒绝。双棘轮规范建议的报文加密是 AES-256-CBC 加 HMAC；本仓库按题目把 `MK` 直接用作 AES-256-GCM 钥匙。头 `dh_pub`、`n`、`pn` 是明文。

## 10. 附件是第二层 AES-256-GCM

消息钥匙仍然只加密棘轮信封里的那一小段 JSON。文件本体另用一把 32 字节随机钥匙做 AES-256-GCM，按 8MiB 分块。普通文件上传一边从磁盘读取，一边计算 SHA-256，一边加密，一边把二进制密文送出，不再把整份密文先落盘，也不再做 base64。图片和视频会先把同一套分片密文写成加密缓存，再上传这些分片；钥匙放在口令封存的本地库里，不进历史正文。观看时临时解开，关闭播放器后删除临时明文。普通聊天可以把媒体另存成明文，私密聊天不可以。视频还可以另存一份不含钥匙的加密副本。同一好友可以有多条聊天，每条聊天的私密等级写在棘轮内层 JSON 里。nonce 前 8 字节随机、后 4 字节是块序号，附加数据包含文件编号、块序号和总块数，避免块被对调，也避免把钥匙挪到另一个文件上。整文件 SHA-256 和这把钥匙放在内层 JSON 的 `file` 字段里，外层 `kind` 仍要和内层一致。服务器把密文写在数据库旁边的文件里，表里只留分片序号；下载时还要核对登录用户是不是上传时声明的收件人。日志只记用户、文件编号和字节数。

8GiB 是发送前的明文上限，按文件大小拒绝，不先读入。聊天帧仍是 64KB。附件二进制帧上限约 8MiB。上传和下载同时在路上放 8 块，加密和网络重叠。连接关掉 permessage-deflate，因为密文压不下去，开着只会拖慢传输。一条附件只推进一次发送链。密文先上传完，再把含钥匙的信封和推进后的棘轮状态放进同一个本地事务；发送失败后重试的是这封原信封，不会把发送链再推一步。收件人先解开棘轮信封，再逐块验 GCM。普通文件把明文写入磁盘。图片和视频把密文分片写入加密缓存，核对 SHA-256 时明文只在内存里经过，不留下明文文件。任一块失败就丢掉整份文件，不把半截内容写进历史。群文件的钥匙信封同样带上当前群状态的 `gstate`。棘轮若已经混入后量子封装，这封钥匙信封走同一条混合链。
