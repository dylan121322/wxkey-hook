# wxkey-hook

**微信 4.x macOS 版数据库密钥提取 + 解密工具**

[English](README.md) · 零 pip 依赖 · 纯 Python stdlib + macOS `libcommonCrypto`

> ⚠️ **仅供研究和个人数据恢复。** 只在你自己的设备、你自己的微信账号上使用。见 [法律声明](#法律声明)。

## 为什么需要它

微信 4.1(macOS)的 32 字节数据库密钥**不再以明文驻留在进程内存中** —— 对运行中的
微信做 8.3 GB 内存扫描、搜索 21 个已知正确的密钥,**0 命中**。所有基于内存扫描的
工具(上一代 `find_all_keys_macos` 及大多数社区分支)都因此在 4.1 上失效。

密钥只在微信调用 Apple CommonCrypto 打开数据库的**那一瞬间**出现在 CPU 寄存器里。
本工具用 lldb 断点挂在 `CCCryptorCreate`(**系统库**符号,**未被 strip**)上,从
ARM64 `x3` 寄存器读取 AES key,并用 `--waitfor` 在任何数据库打开前就挂好断点 ——
一次启动捕获全部密钥。

完整逆向分析见 [MECHANISM.md](MECHANISM.md)。

## 系统要求

- **macOS**(Apple Silicon 已验证;Intel 理论通用但未测试)
- **Xcode Command Line Tools**(提供 `lldb`)—— `xcode-select --install`
- **Python 3.10+**(仅 stdlib —— 无需 `pip install`)
- **sudo**(`task_for_pid` 读取其他进程内存需要 root)

### 依赖声明

| 依赖 | 来源 | License |
|------|------|---------|
| Python `hashlib`, `hmac`, `ctypes`, `json`, `sqlite3` | Python 标准库 | PSF |
| `libcommonCrypto.dylib` | macOS 系统库 | APSL |
| `lldb` | Xcode CLT (LLVM) | Apache-2.0 with LLVM exception |

**无 pip / brew / npm 依赖。** 除上述系统工具外无需安装任何东西。

## 快速开始

### 1. 重签微信(只需一次)

```bash
bash resign_wechat.sh
```

微信自带 hardened runtime 会阻止调试器附着。此脚本将微信复制到
`~/WeChat-resign.app` 并 ad-hoc 重签,添加 `get-task-allow` 授权。重签副本
在重启后依然有效。

### 2. 提取密钥

```bash
python3 wxkey.py extract
```

这会:
1. 杀掉运行中的微信。
2. 以 `--waitfor` 模式启动 lldb(在 `_dyld_start` 处附着)。
3. 提示你启动 `~/WeChat-resign.app`。
4. 微信打开数据库时捕获密钥。
5. 把每个密钥匹配到对应 `.db` 文件,写入 `keys.json`。

微信加载完成(不再出现新密钥)后,按一次 `Ctrl-C` 停止捕获。

### 3. 解密

```bash
python3 wxkey.py decrypt
```

解密后的数据库在 `./decrypted/`,可用任意 SQLite 工具打开。

### 一键完成

```bash
python3 wxkey.py all      # 重签 + 提取 + 解密
```

## 子命令

| 命令 | 说明 |
|------|------|
| `wxkey.py resign` | 重签微信以允许调试 |
| `wxkey.py extract` | 提取密钥 → `keys.json` |
| `wxkey.py decrypt` | 解密全部数据库 → `decrypted/` |
| `wxkey.py verify <db> <key>` | HMAC 校验单个数据库密钥 |
| `wxkey.py all` | 重签 + 提取 + 解密 |

## 原理一段话

微信 4.x 用 SQLCipher 4 加密每个数据库(AES-256-CBC、HMAC-SHA512、4096 字节页、
80 字节 reserve),采用 **raw-key 模式**:32 字节密钥直接作为 AES key,不做 PBKDF2
拉伸。所有加密走 Apple CommonCrypto 而非 BoringSSL —— 这就是为什么 hook
`PKCS5_PBKDF2_HMAC` 或 `AES_set_decrypt_key` 从不命中。我们改 hook `CCCryptorCreate`
抓 key,再通过把文件 salt 与 `0x3A` 做 XOR(SQLCipher 的 MAC-salt 变换)去匹配
`CCKeyDerivationPBKDF` 记录的 salt,从而对应到具体文件。每个匹配的密钥在信任前都
用 page 1 的 HMAC 校验。

## 安全须知

- `keys.json` 含**明文数据库密钥**。妥善保管,已加入 `.gitignore`,建议 `chmod 600`。
- 本工具**完全本地运行**,无任何网络通信。
- 只**读取**微信进程内存和数据库文件,不修改微信任何数据。

## 法律声明

本项目用于**安全研究、教育和恢复你自己的数据**。提取密钥需要 root、物理访问和重签 ——
即只能在你已经掌控的机器和账号上运行。

请勿用于你不拥有的账号或设备。你需自行遵守微信服务条款及所在司法辖区的法律。

## 许可证

[MIT](LICENSE)
