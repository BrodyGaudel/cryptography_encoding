
# CryptoUtil Java Library

`CryptoUtil` is a lightweight Java utility library that provides common cryptographic operations such as encoding/decoding, encryption/decryption, key generation, and digital signatures using standard Java APIs. It is designed for easy integration into enterprise or personal applications requiring robust and simple cryptographic support.

---

## Features

- ✅ Base64 and Hex encoding/decoding  
- 🔐 AES encryption/decryption (symmetric)
- 🔐 RSA encryption/decryption (asymmetric)
- 🔑 HMAC signature generation and verification
- 🔑 RSA digital signature creation and validation
- 🔑 AES and RSA key pair generation

---

## Requirements

- Java 21+
- Maven (for dependency management)

---

## Installation

To use `CryptoUtil` in your Maven project, install it locally or deploy it to your repository.  
(Instructions to publish on Maven Central or GitHub Packages can be added later.)

```xml
<dependency>
    <groupId>org.mounanga</groupId>
    <artifactId>cryptoutil</artifactId>
    <version>1.0.0</version>
</dependency>
```

---

## Usage

### 1. Base64 Utilities

```java
String encoded = CryptoUtil.encodeBase64("hello");
String decoded = CryptoUtil.decodeBase64(encoded);
```

---

### 2. Hex Utilities

```java
String hex = CryptoUtil.encodeHex("hello");
String decoded = CryptoUtil.decodeHex(hex);
```

---

### 3. AES Encryption/Decryption

```java
// Generate key and IV
SecretKey aesKey = CryptoUtil.generateAESKey(256);
byte[] iv = CryptoUtil.generateIV();

// Encrypt
byte[] encrypted = CryptoUtil.encryptAES("myData", aesKey, iv);

// Decrypt
String decrypted = CryptoUtil.decryptAES(encrypted, aesKey, iv);
```

---

### 4. RSA Encryption/Decryption

```java
// Generate key pair
KeyPair rsaKeyPair = CryptoUtil.generateRSAKeyPair(2048);

// Encrypt
byte[] encrypted = CryptoUtil.encryptRSA("mySecret", rsaKeyPair.getPublic());

// Decrypt
String decrypted = CryptoUtil.decryptRSA(encrypted, rsaKeyPair.getPrivate());
```

---

### 5. HMAC Signatures

```java
SecretKey key = CryptoUtil.generateHMACKey("HmacSHA256");

// Sign
byte[] signature = CryptoUtil.signHMAC("data", key, "HmacSHA256");

// Verify
boolean valid = CryptoUtil.verifyHMAC("data", signature, key, "HmacSHA256");
```

---

### 6. RSA Signatures

```java
KeyPair rsaKeyPair = CryptoUtil.generateRSAKeyPair(2048);

// Sign
byte[] signature = CryptoUtil.signRSA("message", rsaKeyPair.getPrivate(), "SHA256withRSA");

// Verify
boolean verified = CryptoUtil.verifyRSA("message", signature, rsaKeyPair.getPublic(), "SHA256withRSA");
```

---

## API Reference

### Key Generation

- `generateAESKey(int size)`  
  Generate an AES key (size: 128, 192, or 256 bits)

- `generateIV()`  
  Generate a 16-byte Initialization Vector (IV)

- `generateRSAKeyPair(int size)`  
  Generate an RSA key pair (size: 1024, 2048, 4096)

- `generateHMACKey(String algorithm)`  
  Generate an HMAC key using the given algorithm (e.g., `"HmacSHA256"`)

---

## Exception Handling

All low-level exceptions are wrapped into a `RuntimeException`. It is recommended to handle them at the application level for production usage. A custom `CryptoException` class will be added in future versions for more granular control.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Future Improvements

- Add PEM/DER file support for RSA keys
- Support for key storage in keystores
- Better error handling with custom exceptions
- CLI or GUI integration
- Publish to Maven Central / GitHub Packages
