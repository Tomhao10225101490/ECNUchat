# 基于ECDH与AES-GCM的端到端加密聊天室

利用椭圆曲线Diffie-Hellman协商会话密钥，采用AES-GCM加密消息并校验完整性，结合数字签名认证身份，实现防窃听、防篡改的安全即时通讯。

X25519 就是椭圆曲线 Diffie-Hellman；每条消息用 AES-256-GCM 加密并校验完整性；Ed25519 数字签名认证身份和预密钥。会话密钥由 X3DH（最多四次 DH）算出，只用来初始化双棘轮，不直接加密聊天内容。

## 依赖

- Python 3.11+
- 只使用 `requirements.txt`：`cryptography`、`websockets`、`rich`、`pytest`

```bash
python3 -m pip install -r requirements.txt
```

## 三个终端演示

口令一律使用 `password123`。先开服务器，再开 alice / bob / carol。

终端 1（服务器；日志里只会出现 base64，搜不到明文）：

```bash
python3 -m src.server --host 127.0.0.1 --port 8765 --db data/server.db
```

终端 2：

```bash
python3 -m src.client --user alice --password password123 --host 127.0.0.1 --port 8765
```

终端 3：

```bash
python3 -m src.client --user bob --password password123 --host 127.0.0.1 --port 8765
```

再开一个终端给 carol：

```bash
python3 -m src.client --user carol --password password123 --host 127.0.0.1 --port 8765
```

首次启动会在本地生成三把长期密钥（Ed25519 `IK_sign`、X25519 `IK_dh`、带签名的 X25519 Signed Prekey）和 20 把一次性预密钥，公钥上传服务器，私钥用口令经 PBKDF2-HMAC-SHA256（600000 次）派生的键做 AES-256-GCM 封存。

### 单聊

在 alice：

```
/chat bob
/fingerprint bob
你好鲍勃
```

在 bob：

```
/chat alice
你好爱丽丝
```

此时发生第一次 DH 棘轮更换：Bob 回复前生成自己的棘轮公钥，双方代数加一。同一把 `dh_pub` 下连续两条消息的消息密钥不同。服务器终端里搜索「你好鲍勃」应无结果，只能看到信封的 base64 长度。

### 三人小群

群消息是对每个其他成员各跑一条双棘轮，发出 N-1 个信封，**不是** WhatsApp Sender Keys。最多 8 人。

在 alice：

```
/group create 三人组 bob carol
群里大家好
```

bob、carol 应各收到一条中文。carol 解不开 alice 发给 bob 的那一封。

### 其它命令

```
/users
/history
/group add 三人组 新成员
/fingerprint 名字
/quit
```

界面用 rich 画成桌面即时通讯双栏：左侧会话列表（彩色头像、最后一条预览、时间、持久化未读数、在线绿点），右侧自己的消息靠右、对方靠左。默认是 Telegram 蓝色风格，输入 `/theme wechat` 可切成微信绿色发送气泡，`/theme telegram` 切回。窄终端会自动隐藏侧栏，只保留聊天和输入区。顶栏是项目全名。打开会话后能看到对端指纹前 8 组、棘轮代数，以及标红的「验签失败 / 重放拒绝 / GCM 失败」。

终端里直接打字回车发送。输入框为空时用 Tab 或上下键切换会话，Esc 关闭指纹卡片，PgUp/PgDn 滚动长浮层；Home、End、Delete 和 bracketed paste 均可用。`/help` 列出命令。管道或非交互终端会退回逐行模式。

安全细节：解密在临时棘轮副本上进行，只有 GCM 认证成功才提交状态，伪造包不能烧掉合法消息密钥；首次消息的 OPK 也只在认证成功后删除。第一次核对后两把身份公钥会固定，后续 bundle 变更会硬拒绝。发送状态和待发信封以加密 blob 原子落盘，崩溃后重发完全相同的信封。`group/kind` 等显示语义同时放在密文中并与外层字段核对。

## 测试

```bash
python3 -m pytest -q
```

单测只在内存里放两份状态，不连网，覆盖：

- 双方 X3DH 的 SK 完全一致（有 OPK / 无 OPK）
- 往返各 3 条明文一致
- 同一 `dh_pub` 下两条消息 MK 不同
- 回复后 DH 棘轮代数加一，更换前后 MK 不同
- 故意乱序仍能解开；重放拒绝；改一个密文字节 GCM 失败；跳过超过 40 条拒绝

`scripts/demo_attack.py` 演示：不核对指纹时，服务器可以在发 bundle 时换掉公钥做中间人；核对之后服务器只能转发。

```bash
python3 scripts/demo_attack.py
```

## 重启

- 停掉 `src.server` 再启动：SQLite 里的公钥、SPK、剩余 OPK、离线信封还在。
- 停掉客户端再启动：口令解开本地加密 blob，棘轮状态（RK、链密钥、棘轮私钥、跳过的 MK）可以接着收。

## 协议要点

| 题目表述 | 实现 |
| --- | --- |
| 椭圆曲线 Diffie-Hellman | X25519（X3DH 的 DH1–DH4 与双棘轮的 DH） |
| AES-GCM 加密并校验完整性 | 每条消息独立 MK，AES-256-GCM，12 字节随机 nonce |
| 数字签名认证身份 | Ed25519：SPK、X3DH 初始消息、登录挑战 |

服务器只做公钥目录、OPK 一次发放、按用户名转发信封和离线队列。单条 WebSocket JSON 超过 64KB 拒绝。
