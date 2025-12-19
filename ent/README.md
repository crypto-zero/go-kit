# Ent 加密工具

这是一个为 Ent 框架设计的通用加密工具包，提供了对称加密功能，支持在数据库保存前自动加密字段，在查询后自动解密字段。

## 主要特性

- ✅ **确定性加密**：相同的明文使用相同的密钥总是产生相同的密文，支持数据库 JOIN 查询
- ✅ **自动加密/解密**：通过 Ent Hooks 和 Interceptors 自动处理字段加密和解密
- ✅ **通用设计**：使用反射机制，适用于任何 Ent 实体类型
- ✅ **并发安全**：所有方法都是线程安全的，可以在多个 goroutine 中并发使用
- ✅ **RSA 密钥加密**：支持使用 RSA 公钥加密 AES 密钥，使用私钥解密
- ✅ **性能优化**：缓存 GCM 实例，使用 map 进行快速字段查找

## 核心概念

### 确定性加密

本工具使用**确定性加密**（Deterministic Encryption），这意味着：
- 相同的明文 + 相同的密钥 = 相同的密文
- 优点：支持在加密字段上进行数据库 JOIN 操作
- 缺点：会暴露相同的数据（攻击者可以知道哪些记录包含相同的数据）

**⚠️ 警告**：确定性加密会泄露数据模式，请根据安全需求谨慎使用。

## 快速开始

### 1. 创建加密器

```go
import "github.com/crypto-zero/go-kit/ent"

// 方式一：直接使用字符串密钥
encryptor, err := ent.NewEncryptor("my-secret-key-32-bytes-long!!")
if err != nil {
    log.Fatal(err)
}

// 方式二：从 RSA 加密的密钥创建（需要先解析 RSA 私钥）
import "github.com/crypto-zero/go-kit/encryption"

privateKey, _ := encryption.ParseRSAPrivateKeyFromString(privateKeyPEM)
encryptor, err := ent.NewEncryptorFromRSAEncryptedKey(encryptedKey, privateKey)
```

### 2. 在 Schema 中使用

```go
package schema

import (
    "os"
    
    "entgo.io/ent"
    "entgo.io/ent/schema/field"
    "github.com/crypto-zero/go-kit/ent"
)

type User struct {
    ent.Schema
}

func (User) Fields() []ent.Field {
    return []ent.Field{
        field.String("email"),
        field.String("phone"),
        field.String("password"),
    }
}

func (User) Hooks() []ent.Hook {
    // 方式一：使用全局默认加密器（推荐）
    return []ent.Hook{
        ent.EncryptHookWithDefault("email", "phone", "password"),
    }
    
    // 方式二：每次创建新的加密器
    // encryptor, _ := ent.NewEncryptor(os.Getenv("ENCRYPT_KEY"))
    // return []ent.Hook{
    //     encryptor.EncryptHook("email", "phone", "password"),
    // }
}

func (User) Interceptors() []ent.Interceptor {
    // 方式一：使用全局默认加密器（推荐）
    return []ent.Interceptor{
        ent.DecryptInterceptorWithDefault("email", "phone", "password"),
    }
    
    // 方式二：每次创建新的加密器
    // encryptor, _ := ent.NewEncryptor(os.Getenv("ENCRYPT_KEY"))
    // return []ent.Interceptor{
    //     encryptor.DecryptInterceptor("email", "phone", "password"),
    // }
}
```

### 3. 手动加密/解密

```go
// 加密
encrypted, err := encryptor.Encrypt("user@example.com")
if err != nil {
    log.Fatal(err)
}

// 解密
decrypted, err := encryptor.Decrypt(encrypted)
if err != nil {
    log.Fatal(err)
}
```

## API 文档

### 创建加密器

#### `NewEncryptor(key string) (*EntEncryptor, error)`

从字符串密钥创建加密器。

**参数：**
- `key`: 加密密钥字符串（不能为空）

**密钥长度处理：**
- 如果密钥长度为 16、24 或 32 字节，直接使用（对应 AES-128、AES-192、AES-256）
- 如果密钥长度不符合要求，自动使用 SHA256 哈希生成 32 字节密钥（AES-256）

**示例：**
```go
encryptor, err := ent.NewEncryptor("my-secret-key")
```

#### `NewEncryptorFromRSAEncryptedKey(encryptedKey string, privateKey *rsa.PrivateKey) (*EntEncryptor, error)`

从 RSA 加密的密钥创建加密器。首先使用 RSA 私钥解密密钥，然后创建加密器。

**参数：**
- `encryptedKey`: base64 编码的 RSA 加密密钥密文
- `privateKey`: 用于解密密钥的 RSA 私钥

**示例：**
```go
import "github.com/crypto-zero/go-kit/encryption"

privateKey, err := encryption.ParseRSAPrivateKeyFromString(privateKeyPEM)
if err != nil {
    log.Fatal(err)
}
encryptor, err := ent.NewEncryptorFromRSAEncryptedKey(encryptedKey, privateKey)
if err != nil {
    log.Fatal(err)
}
```

### 加密/解密方法

#### `Encrypt(plaintext string) (string, error)`

加密字符串，返回 base64 编码的密文。

**特性：**
- 确定性加密：相同明文总是产生相同密文
- 空字符串返回空字符串
- 线程安全

**示例：**
```go
encrypted, err := encryptor.Encrypt("user@example.com")
```

#### `Decrypt(ciphertext string) (string, error)`

解密 base64 编码的密文，返回明文。

**特性：**
- 自动处理 base64 解码
- 验证密文长度
- 线程安全

**示例：**
```go
decrypted, err := encryptor.Decrypt(encrypted)
```

### 全局默认加密器

#### `SetDefaultEncryptor(encryptor *EntEncryptor) error`

设置全局默认加密器。设置后，可以在 Schema 中使用 `EncryptHookWithDefault` 和 `DecryptInterceptorWithDefault`。

**参数：**
- `encryptor`: 要设置为默认的加密器实例（不能为 nil）

**示例：**
```go
encryptor, _ := ent.NewEncryptor(os.Getenv("ENCRYPT_KEY"))
ent.SetDefaultEncryptor(encryptor)
```

#### `GetDefaultEncryptor() *EntEncryptor`

获取全局默认加密器。如果未设置，返回 nil。

**示例：**
```go
encryptor := ent.GetDefaultEncryptor()
if encryptor != nil {
    encrypted, _ := encryptor.Encrypt("data")
}
```

### Ent 集成方法

#### `EncryptHook(fields ...string) ent.Hook`

创建加密 Hook，在保存数据前自动加密指定字段。

**参数：**
- `fields`: 要加密的字段名列表（可变参数）

**特性：**
- 只加密字符串类型字段
- 跳过空字符串
- 自动跳过不存在的字段
- 如果没有指定字段，返回 no-op hook

**示例：**
```go
// 使用实例方法
hook := encryptor.EncryptHook("email", "phone", "password")

// 或使用全局默认加密器
hook := ent.EncryptHookWithDefault("email", "phone", "password")
```

#### `EncryptHookWithDefault(fields ...string) ent.Hook`

使用全局默认加密器创建加密 Hook。这是 `GetDefaultEncryptor().EncryptHook()` 的便捷方法。

**注意**：使用前必须先调用 `SetDefaultEncryptor()` 设置默认加密器。

**示例：**
```go
ent.EncryptHookWithDefault("email", "phone", "password")
```

#### `DecryptInterceptor(fields ...string) ent.Interceptor`

创建解密 Interceptor，在查询后自动解密指定字段。

**参数：**
- `fields`: 要解密的字段名列表（可变参数）

**特性：**
- 自动处理单个实体和实体切片
- 只解密字符串类型字段
- 跳过空字符串
- 如果没有指定字段，返回 no-op interceptor

**示例：**
```go
// 使用实例方法
interceptor := encryptor.DecryptInterceptor("email", "phone", "password")

// 或使用全局默认加密器
interceptor := ent.DecryptInterceptorWithDefault("email", "phone", "password")
```

#### `DecryptInterceptorWithDefault(fields ...string) ent.Interceptor`

使用全局默认加密器创建解密 Interceptor。这是 `GetDefaultEncryptor().DecryptInterceptor()` 的便捷方法。

**注意**：使用前必须先调用 `SetDefaultEncryptor()` 设置默认加密器。

**示例：**
```go
ent.DecryptInterceptorWithDefault("email", "phone", "password")
```

#### `DecryptEntity(entity interface{}, fields ...string) error`

手动解密单个实体的指定字段。

**参数：**
- `entity`: 实体指针（不能为 nil）
- `fields`: 要解密的字段名列表

**示例：**
```go
user := &User{Email: encryptedEmail}
err := encryptor.DecryptEntity(user, "email")
```

#### `DecryptEntitySlice(entities interface{}, fields ...string) error`

手动解密实体切片中的所有实体的指定字段。

**参数：**
- `entities`: 实体切片
- `fields`: 要解密的字段名列表

**示例：**
```go
users := []*User{user1, user2, user3}
err := encryptor.DecryptEntitySlice(users, "email", "phone")
```

### 工具方法

#### `Clear()`

安全地清除内存中的加密密钥和 GCM 实例。调用后，加密器不应再使用。

**用途：**
- 防止密钥材料残留在内存中
- 在不再需要加密器时调用

**示例：**
```go
encryptor.Clear()
```

## 使用 RSA 加密密钥

### 生成 RSA 密钥对

```bash
# 生成 RSA 私钥（2048位）
openssl genrsa -out private_key.pem 2048

# 从私钥提取公钥
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### 使用 OpenSSL 加密密钥

在 macOS/Linux 上，可以使用以下命令加密密钥：

```bash
# 使用 RSA 公钥加密字符串（输出 base64）
echo -n "my-secret-key" | openssl pkeyutl -encrypt \
  -pubin -inkey public_key.pem \
  -pkeyopt rsa_padding_mode:oaep \
  -pkeyopt rsa_oaep_md:sha256 | base64
```

### 在代码中使用

```go
import (
    "github.com/crypto-zero/go-kit/ent"
    "github.com/crypto-zero/go-kit/encryption"
)

// 解析 RSA 私钥（从字符串）
privateKeyPEM := `-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----`
privateKey, err := encryption.ParseRSAPrivateKeyFromString(privateKeyPEM)
if err != nil {
    log.Fatal(err)
}

// 从 RSA 加密的密钥创建加密器
encryptor, err := ent.NewEncryptorFromRSAEncryptedKey(encryptedKey, privateKey)
if err != nil {
    log.Fatal(err)
}
```

**注意**：RSA 密钥解析函数位于 `github.com/crypto-zero/go-kit/encryption` 包中，需要单独导入。

## 使用全局默认加密器

为了避免在每个 Schema 的 Hooks 和 Interceptors 中重复创建加密器，可以使用全局默认加密器：

```go
package main

import (
    "log"
    "os"

    "github.com/crypto-zero/go-kit/ent"
)

func init() {
    // 在程序启动时设置全局默认加密器
    encryptor, err := ent.NewEncryptor(os.Getenv("ENCRYPT_KEY"))
    if err != nil {
        log.Fatal(err)
    }
    
    if err := ent.SetDefaultEncryptor(encryptor); err != nil {
        log.Fatal(err)
    }
}

// 在 Schema 中直接使用全局加密器
func (User) Hooks() []ent.Hook {
    return []ent.Hook{
        ent.EncryptHookWithDefault("email", "phone", "password"),
    }
}

func (User) Interceptors() []ent.Interceptor {
    return []ent.Interceptor{
        ent.DecryptInterceptorWithDefault("email", "phone", "password"),
    }
}
```

**优势：**
- 只需创建一次加密器，避免重复创建
- 代码更简洁，不需要在每个 Schema 中创建加密器
- 统一管理，便于维护

## 完整示例

```go
package main

import (
    "log"
    "os"

    "github.com/crypto-zero/go-kit/ent"
)

func init() {
    // 初始化全局默认加密器
    encryptor, err := ent.NewEncryptor(os.Getenv("ENCRYPT_KEY"))
    if err != nil {
        log.Fatal(err)
    }
    
    if err := ent.SetDefaultEncryptor(encryptor); err != nil {
        log.Fatal(err)
    }
}

func main() {
    // 1. 获取全局加密器（可选）
    encryptor := ent.GetDefaultEncryptor()
    if encryptor == nil {
        log.Fatal("default encryptor not set")
    }

    // 2. 手动加密
    encrypted, err := encryptor.Encrypt("user@example.com")
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Encrypted: %s", encrypted)

    // 3. 手动解密
    decrypted, err := encryptor.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Decrypted: %s", decrypted)

    // 4. 在 Schema 中使用全局加密器（见上面的示例）
}
```

## 安全注意事项

1. **密钥管理**：
   - 不要将密钥硬编码在代码中
   - 使用环境变量或密钥管理服务（如 AWS KMS、HashiCorp Vault）
   - 定期轮换密钥

2. **确定性加密的权衡**：
   - 确定性加密支持 JOIN 查询，但会泄露数据模式
   - 如果不需要 JOIN 查询，考虑使用随机 nonce 的加密方式

3. **密钥长度**：
   - 推荐使用 32 字节（256 位）密钥（AES-256）
   - 较短的密钥会自动哈希为 32 字节

4. **内存安全**：
   - 使用 `Clear()` 方法清除不再需要的加密器
   - 避免在日志中输出密钥或密文

5. **并发使用**：
   - 所有方法都是线程安全的
   - 可以在多个 goroutine 中共享同一个 `EntEncryptor` 实例

## 性能考虑

- **GCM 实例缓存**：加密器在创建时缓存 GCM 实例，避免每次加密/解密都重新创建
- **字段查找优化**：使用 map 进行字段名查找，时间复杂度 O(1)
- **早期返回**：如果没有指定字段，Hook 和 Interceptor 会立即返回，避免不必要的处理

## 常见问题

### Q: 为什么使用确定性加密？

A: 确定性加密允许在加密字段上进行数据库 JOIN 操作。如果不需要这个功能，可以考虑使用随机 nonce 的加密方式。

### Q: 密钥长度有什么要求？

A: 密钥可以是任意长度。如果长度不是 16、24 或 32 字节，会自动使用 SHA256 哈希为 32 字节。

### Q: 可以加密非字符串字段吗？

A: 目前只支持字符串字段。非字符串字段会被自动跳过。

### Q: 如何处理已加密的数据？

A: 如果字段已经是加密的，再次加密会导致数据损坏。确保只在保存时加密一次，在查询时解密。

### Q: 是否支持字段级别的加密控制？

A: 是的，通过 `EncryptHook` 和 `DecryptInterceptor` 的参数可以指定要加密/解密的字段。

## 许可证

请查看项目的 LICENSE 文件。

