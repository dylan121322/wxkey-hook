# WeChat 4.x macOS 数据库密钥机制

> 基于 2026-07-14 逆向分析。微信版本 4.1.11,Apple Silicon M1,macOS 15.6。

---

## 1. 数据库参数

| 参数 | 值 |
|------|-----|
| 加密引擎 | SQLCipher 4 (WCDB 封装) |
| 页大小 | 4096 bytes |
| 保留区 (reserve) | 80 bytes = IV(16) + HMAC(64) |
| 加密算法 | AES-256-CBC |
| HMAC 算法 | HMAC-SHA512 |
| Key 派生 | PBKDF2-HMAC-SHA512 (2 iterations, dklen=32) |

文件结构（每个 4096 字节页）:

```
Page 1:   salt(16)  |  encrypted_body(4000)  |  iv(16)  |  hmac(64)
        ├─ file_salt          ├─ AES-CBC              └─ HMAC-SHA512(mac_key, salt+enc_body+iv, page_number)

Page N:   encrypted_body(4016)  |  iv(16)  |  hmac(64)
```

---

## 2. Raw-Key 模式

微信 4.x 使用 SQLCipher 的 **raw-key 模式**: 32 字节加密密钥(enc_key)直接作为 AES key，不做 PBKDF2 密钥派生。

```
enc_key (32 bytes)  ──→  AES key (32 bytes)      ← 直接使用，不派生
enc_key (32 bytes)  ──→  PBKDF2(iter=2) ──→  mac_key (32 bytes)
```

证据:
1. `CCCryptorCreate` 断点捕获的 AES key 值 == `CCKeyDerivationPBKDF` 的 rawkey 参数 (rounds=2 调用)
2. `PKCS5_PBKDF2_HMAC` (BoringSSL) 断点 0 命中 → 微信不用 BoringSSL 做 PBKDF2
3. 旧版 `find_all_keys_macos` (C 内存扫描器) 抓到的 key 能直接解密 message_0 — 如果是 PBKDF2 模式则不行

---

## 3. 为什么内存扫描在 4.1 失效

### 3.1 旧方案 (微信 4.0 有效)

```
微信进程内存 ──→ mach_vm_read 扫描 RW 区域
                 ──→ 搜索 32 字节候选
                 ──→ 用 CommonCrypto HMAC 验证
                 ──→ 匹配到 .db 文件
```

失效原因: 微信 4.1 **32 字节明文 key 不驻留内存**。

### 3.2 实测证据 (2026-07-14)

| 测试 | 方法 | 结果 |
|------|------|------|
| 暴力扫描 | 多线程扫描 2500MB 可写内存 | 0 命中 |
| 全可读区域扫描 | 扫描 8361MB，21 个已知 key 精确搜索 | **0 命中** |
| CommonCrypto 断点 | lldb hook `CCCryptorCreate` | **26 个 key 全部捕获** (含 message_4) |
| BoringSSL 断点 | hook `PKCS5_PBKDF2_HMAC`, `AES_set_decrypt_key` | 0 命中 (微信不用 BoringSSL) |

结论: key 只在 `CCCryptorCreate` 调用瞬间存在于寄存器/栈上，调用结束后即被后续指令覆盖。任何基于内存 dump 的方案 (包括社区所有的 `find_all_keys_macos`/`wx-cli`/`chatlog`) 在 4.1 上必然失败。

---

## 4. CommonCrypto Hook 点

微信 4.1 的 SQLCipher 经过 Apple CommonCrypto 进行所有加密操作。这些是系统库的导出符号，**不会被 strip**，可以按名直接设断点。

### 4.1 三个关键函数

```
CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef)
  ARM64: x0=op  x1=alg  x2=options  x3=key(→32字节AES key)  x4=32  x5=iv

CCKeyDerivationPBKDF(alg, password, passwordLen, salt, saltLen, prf, rounds, dk, dkLen)
  ARM64: x0=alg  x1=password(→raw key明文)  x2=pwlen  x3=salt  x4=saltLen  x5=prf  x6=rounds  x7=out

CCHmacInit(ctx, algorithm, key, keyLength)
  ARM64: x0=ctx  x1=alg  x2=key(→32字节mac key)  x3=32
```

### 4.2 Hook 时序

```
微信启动
  └─ 打开 message_0.db
      ├─ CCKeyDerivationPBKDF(rounds=2, rawkey, salt)  → 派生 mac_key
      ├─ CCHmacInit(mac_key)                            → 设置 HMAC 上下文
      └─ CCCryptorCreate(key=AES_KEY)                   → ★ 此处抓取 32 字节 AES key
  └─ 打开 message_1.db
      └─ ...
  └─ 打开 message_4.db
      └─ ...
```

每个 .db 文件被打开时，以上三个函数依序调用一次。**key 必须在 `CCCryptorCreate` 断点处抓取** — 此时 x3 寄存器指向 32 字节明文 key。

### 4.3 为什么必须重启微信

- Key 只在 `CCCryptorCreate` 调用时出现
- 已打开的数据库不会再次触发 `CCCryptorCreate`
- 因此 hook 必须**在数据库打开之前**挂载
- 方案: `process attach --name WeChat --waitfor` 在进程创建瞬间附着

---

## 5. Salt 匹配机制

### 5.1 XOR 0x3A 推导

每个 .db 文件前 16 字节 = `file_salt`。SQLCipher 用 `mac_salt = file_salt XOR 0x3A` 作为 PBKDF2 的 salt。

```
file_salt ──→ xor 0x3A ──→ mac_salt ──→ PBKDF2(enc_key, mac_salt, 2) ──→ mac_key
```

因此，hook 日志中 `CCKeyDerivationPBKDF` 的 salt 参数 = `file_salt XOR 0x3A`。

### 5.2 匹配流程

hook 日志里 `CCKeyDerivationPBKDF` (rounds=2) 记录的 salt 是 `file_salt XOR 0x3A`，
而数据库文件头前 16 字节是 `file_salt` 本身。两者相差一次逐字节 XOR 0x3A，
所以匹配时必须对 file_salt 做 XOR 0x3A 变换后再查表。

```
captured_keys.txt (占位符示例):
  [PBKDF] rounds=2 pwlen=32 rawkey=<ENC_KEY_HEX_64> salt=<MAC_SALT_HEX_32>
  [AESKEY] len=32 key=<ENC_KEY_HEX_64>
  └─ MAC_SALT = FILE_SALT XOR 0x3A

message_4.db 文件头前 16 字节:
  file_salt = <FILE_SALT_HEX_32>

match_keys.py:
  1. file_salt = db.read(16).hex()
  2. mac_salt = file_salt XOR 0x3A
  3. if mac_salt in captured salts → rawkey 即该库的 enc_key
  4. verify_page1_hmac(db, rawkey) → 通过 → 写入 keys.json
```

---

## 6. 完整数据流

```
┌─────────────┐    sudo lldb --waitfor     ┌──────────────┐
│ WeChat 启动  │◄──────────────────────────│ extract_keys  │
│ (_dyld_start)│                           │   .sh         │
└──────┬───────┘                           └──────┬────────┘
       │ import hook_keys.py                      │
       │ breakpoint set -n CCCryptorCreate        │
       │ breakpoint set -n CCKeyDerivationPBKDF   │
       │                                          │
       ▼                                          │
┌─────────────┐                                   │
│ 打开 *.db   │──→ CCCryptorCreate(x3=AES key)    │
│             │──→ hook 触发, 写 captured_keys.txt │
└─────────────┘                                   │
                                                  ▼
┌─────────────┐                           ┌──────────────┐
│ match_keys  │──→ 解析 captured_keys.txt │              │
│   .py       │──→ 遍历 db_dir/*.db      │  keys.json   │
│             │──→ file_salt 匹配 key     │              │
│             │──→ HMAC 自校验             └──────┬────────┘
└─────────────┘                                   │
                                                  ▼
┌─────────────┐                           ┌──────────────┐
│ decrypt.py  │──→ 加载 keys.json         │  decrypted/  │
│             │──→ CCCrypt AES-CBC 解密    │  message_*.db│
│ (ctypes CC) │──→ sqlite3 验证            │              │
└─────────────┘                           └──────────────┘
```

---

## 7. 与社区方案对比

| 项目 | 平台 | 方法 | 4.1 状态 |
|------|------|------|----------|
| `find_all_keys_macos` (C) | macOS | mach_vm_read 内存扫描 | ❌ 失效 (key 不驻留) |
| wx-cli | Windows/macOS | 内存扫描 + PRAGMA key | ❌ 失效 |
| cocohahaha/wx-dump | Windows | DLL inject + sqlite3_key hook | ❌ macOS 无等效方案 |
| PyWxDump | Windows | 内存 + keychain | ❌ DMCA takedown |
| **本项目 wxkey-hook** | macOS | lldb + CommonCrypto hook | ✅ 已验证 (26 库全提取) |

核心差异: 所有旧方案假设 "key 明文常驻进程内存" — 这在 4.1 上不成立。本项目不扫内存，而是 **在加密操作发生的瞬间于寄存器中抓取 key**。

---

## 8. 局限性

1. **仅 macOS**: CommonCrypto hook 依赖 Apple 系统库和 lldb (Xcode CLT)。
2. **需 sudo**: `task_for_pid` 读取其他进程内存需要 root 权限。
3. **需重启微信**: 每次提取 key 必须重新启动微信。
4. **需重签名**: WeChat 原始签名含 hardened runtime，阻止调试；需先 adhoc 重签。
5. **系统更新风险**: 如果 Apple 修改 CommonCrypto ABI 或微信切换到自定义加密实现，方案可能失效。
6. **仅测 ARM64**: Intel Mac 理论上通用但未测试。

---

## 9. 更新记录

| 日期 | 事件 |
|------|------|
| 2025-07 | `find_all_keys_macos` 在微信 4.0 上成功 (key 明文驻留内存) |
| 2026-07 | 微信 4.1 内存扫描全部失效 |
| 2026-07-14 | 发现 CommonCrypto hook 方法，26/26 库一次性提取 |
| 2026-07-14 | 软件化为独立项目 wxkey-hook |
