# Ent 加密工具

## 使用 RSA 加密密钥

### 在 macOS 上使用 OpenSSL 一行命令加密

```bash
# 使用 RSA 公钥加密字符串（输出 base64）
echo -n "my-secret-key" | openssl pkeyutl -encrypt -pubin -inkey public_key.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 | base64
```
### 生成 RSA 密钥对

```bash
# 生成 RSA 私钥（2048位）
openssl genrsa -out private_key.pem 2048

# 从私钥提取公钥
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

### 解密（使用私钥）

```bash
# 使用 RSA 私钥解密（输入 base64）
echo "base64_encrypted_string" | base64 -d | openssl pkeyutl -decrypt -inkey private_key.pem -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
```