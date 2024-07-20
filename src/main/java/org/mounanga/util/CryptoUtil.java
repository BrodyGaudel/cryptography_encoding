package org.mounanga.util;

import org.mounanga.util.exception.CryptoUtilException;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Interface providing cryptographic utility methods for encoding, decoding,
 * encryption, decryption, key generation, and signing operations.
 *
 * @author Brody Gaudel MOUNANGA BOUKA
 */
public interface CryptoUtil {

    /**
     * Encodes the given byte array to a Base64 encoded string.
     *
     * @param data the byte array to encode
     * @return the Base64 encoded string
     */
    String encodeToBase64(byte[] data);

    /**
     * Decodes the given Base64 encoded string to a byte array.
     *
     * @param dataBase64 the Base64 encoded string
     * @return the decoded byte array
     */
    byte[] decodeFromBase64(String dataBase64);

    /**
     * Encodes the given byte array to a Base64 URL-safe encoded string.
     *
     * @param data the byte array to encode
     * @return the Base64 URL-safe encoded string
     */
    String encodeToBase64Url(byte[] data);

    /**
     * Decodes the given Base64 URL-safe encoded string to a byte array.
     *
     * @param dataBase64 the Base64 URL-safe encoded string
     * @return the decoded byte array
     */
    byte[] decodeFromBase64Url(String dataBase64);

    /**
     * Encodes the given byte array to a hexadecimal string.
     *
     * @param data the byte array to encode
     * @return the hexadecimal string
     */
    String encodeToHex(byte[] data);

    /**
     * Encodes the given byte array to a hexadecimal string using a native method.
     *
     * @param data the byte array to encode
     * @return the hexadecimal string
     * @throws CryptoUtilException if an encoding error occurs
     */
    String encodeToHexNative(byte[] data) throws CryptoUtilException;

    /**
     * Generates a new AES secret key.
     *
     * @return the generated secret key
     * @throws CryptoUtilException if a key generation error occurs
     */
    SecretKey generateSecretKey() throws CryptoUtilException;

    /**
     * Generates a new AES secret key from the given secret string.
     *
     * @param secret the secret string
     * @return the generated secret key
     */
    SecretKey generateSecretKey(String secret);

    /**
     * Encrypts the given byte array using AES encryption with the specified secret key.
     *
     * @param data the byte array to encrypt
     * @param secretKey the secret key to use for encryption
     * @return the Base64 encoded encrypted string
     * @throws CryptoUtilException if an encryption error occurs
     */
    String encryptAES(byte[] data, SecretKey secretKey) throws CryptoUtilException;

    /**
     * Decrypts the given Base64 encoded encrypted string using AES decryption with the specified secret key.
     *
     * @param encodedEncryptedData the Base64 encoded encrypted string
     * @param secretKey the secret key to use for decryption
     * @return the decrypted byte array
     * @throws CryptoUtilException if a decryption error occurs
     */
    byte[] decryptAES(String encodedEncryptedData, SecretKey secretKey) throws CryptoUtilException;

    /**
     * Generates a new RSA key pair.
     *
     * @return the generated key pair
     * @throws CryptoUtilException if a key generation error occurs
     */
    KeyPair generateKeyPair() throws CryptoUtilException;

    /**
     * Generates a public key from the given Base64 encoded string.
     *
     * @param publicKeyBase64 the Base64 encoded public key string
     * @return the generated public key
     * @throws CryptoUtilException if a key generation error occurs
     */
    PublicKey generatePublicKeyFromBase64(String publicKeyBase64) throws CryptoUtilException;

    /**
     * Generates a private key from the given Base64 encoded string.
     *
     * @param privateKeyBase64 the Base64 encoded private key string
     * @return the generated private key
     * @throws CryptoUtilException if a key generation error occurs
     */
    PrivateKey generatePrivateKeyFromBase64(String privateKeyBase64) throws CryptoUtilException;

    /**
     * Encrypts the given byte array using RSA encryption with the specified public key.
     *
     * @param data the byte array to encrypt
     * @param publicKey the public key to use for encryption
     * @return the Base64 encoded encrypted string
     * @throws CryptoUtilException if an encryption error occurs
     */
    String encryptRSA(byte[] data, PublicKey publicKey) throws CryptoUtilException;

    /**
     * Decrypts the given Base64 encoded encrypted string using RSA decryption with the specified private key.
     *
     * @param dataBase64 the Base64 encoded encrypted string
     * @param privateKey the private key to use for decryption
     * @return the decrypted byte array
     * @throws CryptoUtilException if a decryption error occurs
     */
    byte[] decryptRSA(String dataBase64, PrivateKey privateKey) throws CryptoUtilException;

    /**
     * Extracts the public key from a certificate file.
     *
     * @param fileName the name of the certificate file
     * @return the extracted public key
     * @throws CryptoUtilException if a key extraction error occurs
     */
    PublicKey publicKeyFromCertificate(String fileName) throws CryptoUtilException;

    /**
     * Extracts the private key from a Java KeyStore (JKS) file.
     *
     * @param fileName the name of the JKS file
     * @param jksPassword the password for the JKS file
     * @param alias the alias of the private key in the JKS file
     * @return the extracted private key
     * @throws CryptoUtilException if a key extraction error occurs
     */
    PrivateKey privateKeyFromJKS(String fileName, String jksPassword, String alias) throws CryptoUtilException;

    /**
     * Generates a HMAC-SHA256 signature for the given data using the specified secret.
     *
     * @param data the data to sign
     * @param privateSecret the secret to use for signing
     * @return the Base64 encoded signature
     * @throws CryptoUtilException if a signing error occurs
     */
    String hmacSign(byte[] data, String privateSecret) throws CryptoUtilException;

    /**
     * Verifies a HMAC-SHA256 signature for the given signed document using the specified secret.
     *
     * @param signedDocument the signed document containing the data and the signature
     * @param secret the secret to use for verification
     * @return true if the signature is valid, false otherwise
     * @throws CryptoUtilException if a verification error occurs
     */
    boolean hmacSignVerify(String signedDocument, String secret) throws CryptoUtilException;

    /**
     * Generates an RSA signature for the given data using the specified private key.
     *
     * @param data the data to sign
     * @param privateKey the private key to use for signing
     * @return the Base64 encoded signature
     * @throws CryptoUtilException if a signing error occurs
     */
    String rsaSign(byte[] data, PrivateKey privateKey) throws CryptoUtilException;

    /**
     * Verifies an RSA signature for the given signed document using the specified public key.
     *
     * @param signedDoc the signed document containing the data and the signature
     * @param publicKey the public key to use for verification
     * @return true if the signature is valid, false otherwise
     * @throws CryptoUtilException if a verification error occurs
     */
    boolean rsaSignVerify(String signedDoc, PublicKey publicKey) throws CryptoUtilException;
}
