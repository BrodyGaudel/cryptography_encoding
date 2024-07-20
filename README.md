Voici un fichier `README.md` pour le projet `CryptoUtil` :

```markdown
# CryptoUtil

CryptoUtil is a Java library providing cryptographic utility methods for encoding, decoding, encryption, decryption, key generation, and signing operations. 

## Features

- Base64 encoding/decoding
- Base64 URL-safe encoding/decoding
- Hexadecimal encoding
- AES encryption/decryption
- RSA encryption/decryption
- HMAC-SHA256 signing and verification
- RSA signing and verification
- Key generation (AES, RSA)
- Public/Private key extraction from Base64, certificates, and Java KeyStore (JKS)

## Installation

To use CryptoUtil in your project, add the following dependency to your `pom.xml` file:

```xml
<dependency>
    <groupId>org.mounanga</groupId>
    <artifactId>cryptoutil</artifactId>
    <version>1.0.0</version>
</dependency>
```

Alternatively, you can include the JAR file in your project's classpath.

## Usage

### Encoding and Decoding

```java
CryptoUtil cryptoUtil = new CryptoUtilImpl();

String base64Encoded = cryptoUtil.encodeToBase64(data);
byte[] base64Decoded = cryptoUtil.decodeFromBase64(base64Encoded);

String base64UrlEncoded = cryptoUtil.encodeToBase64Url(data);
byte[] base64UrlDecoded = cryptoUtil.decodeFromBase64Url(base64UrlEncoded);

String hexEncoded = cryptoUtil.encodeToHex(data);
```

### AES Encryption and Decryption

```java
SecretKey secretKey = cryptoUtil.generateSecretKey();

String encryptedData = cryptoUtil.encryptAES(data, secretKey);
byte[] decryptedData = cryptoUtil.decryptAES(encryptedData, secretKey);
```

### RSA Encryption and Decryption

```java
KeyPair keyPair = cryptoUtil.generateKeyPair();
PublicKey publicKey = keyPair.getPublic();
PrivateKey privateKey = keyPair.getPrivate();

String encryptedData = cryptoUtil.encryptRSA(data, publicKey);
byte[] decryptedData = cryptoUtil.decryptRSA(encryptedData, privateKey);
```

### HMAC-SHA256 Signing and Verification

```java
String signature = cryptoUtil.hmacSign(data, secret);
boolean isVerified = cryptoUtil.hmacSignVerify(signedDocument, secret);
```

### RSA Signing and Verification

```java
String signature = cryptoUtil.rsaSign(data, privateKey);
boolean isVerified = cryptoUtil.rsaSignVerify(signedDocument, publicKey);
```

## API Reference

### Methods

- `String encodeToBase64(byte[] data)`
- `byte[] decodeFromBase64(String dataBase64)`
- `String encodeToBase64Url(byte[] data)`
- `byte[] decodeFromBase64Url(String dataBase64)`
- `String encodeToHex(byte[] data)`
- `String encodeToHexNative(byte[] data) throws CryptoUtilException`
- `SecretKey generateSecretKey() throws CryptoUtilException`
- `SecretKey generateSecretKey(String secret)`
- `String encryptAES(byte[] data, SecretKey secretKey) throws CryptoUtilException`
- `byte[] decryptAES(String encodedEncryptedData, SecretKey secretKey) throws CryptoUtilException`
- `KeyPair generateKeyPair() throws CryptoUtilException`
- `PublicKey generatePublicKeyFromBase64(String publicKeyBase64) throws CryptoUtilException`
- `PrivateKey generatePrivateKeyFromBase64(String publicKeyBase64) throws CryptoUtilException`
- `String encryptRSA(byte[] data, PublicKey publicKey) throws CryptoUtilException`
- `byte[] decryptRSA(String dataBase64, PrivateKey privateKey) throws CryptoUtilException`
- `PublicKey publicKeyFromCertificate(String fileName) throws CryptoUtilException`
- `PrivateKey privateKeyFromJKS(String fileName, String jksPassword, String alias) throws CryptoUtilException`
- `String hmacSign(byte[] data, String privateSecret) throws CryptoUtilException`
- `boolean hmacSignVerify(String signedDocument, String secret) throws CryptoUtilException`
- `String rsaSign(byte[] data, PrivateKey privateKey) throws CryptoUtilException`
- `boolean rsaSignVerify(String signedDoc, PublicKey publicKey) throws CryptoUtilException`

## Exception Handling

All methods in CryptoUtil throw `CryptoUtilException` in case of an error. You should handle this exception appropriately in your code.

```java
try {
    String encryptedData = cryptoUtil.encryptAES(data, secretKey);
} catch (CryptoUtilException e) {
    e.printStackTrace();
}
```

## Author

**Brody Gaudel MOUNANGA BOUKA**