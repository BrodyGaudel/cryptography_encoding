package org.mounanga.util;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.mounanga.util.exception.CryptoUtilException;

import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;
import static org.junit.jupiter.api.Assertions.*;

class CryptoUtilImplTest {

    private CryptoUtilImpl cryptoUtil;
    private SecretKey secretKey;
    private KeyPair keyPair;

    @BeforeEach
    public void setUp() throws Exception {
        cryptoUtil = new CryptoUtilImpl();
        secretKey = cryptoUtil.generateSecretKey();
        keyPair = cryptoUtil.generateKeyPair();
    }

    @Test
    void testEncodeToBase64() {
        String encoded = cryptoUtil.encodeToBase64("test".getBytes());
        assertEquals(Base64.getEncoder().encodeToString("test".getBytes()), encoded);
    }

    @Test
    void testDecodeFromBase64() {
        byte[] decoded = cryptoUtil.decodeFromBase64(Base64.getEncoder().encodeToString("test".getBytes()));
        assertArrayEquals("test".getBytes(), decoded);
    }

    @Test
    void testEncodeToBase64Url() {
        String encoded = cryptoUtil.encodeToBase64Url("test".getBytes());
        assertEquals(Base64.getUrlEncoder().encodeToString("test".getBytes()), encoded);
    }

    @Test
    void testDecodeFromBase64Url() {
        byte[] decoded = cryptoUtil.decodeFromBase64Url(Base64.getUrlEncoder().encodeToString("test".getBytes()));
        assertArrayEquals("test".getBytes(), decoded);
    }

    @Test
    void testEncodeToHex() {
        String encoded = cryptoUtil.encodeToHex("test".getBytes());
        assertEquals(Hex.encodeHexString("test".getBytes()), encoded);
    }

    @Test
    void testEncodeToHexNative() throws CryptoUtilException {
        String encoded = cryptoUtil.encodeToHexNative("test".getBytes());
        assertEquals(Hex.encodeHexString("test".getBytes()), encoded);
    }

    @Test
    void testGenerateSecretKey() throws CryptoUtilException {
        SecretKey key = cryptoUtil.generateSecretKey();
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
    }

    @Test
    void testGenerateSecretKeyWithString() {
        String secret = "thisisaverysecretkey";
        SecretKey key = cryptoUtil.generateSecretKey(secret);
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
    }

    @Test
    void testEncryptAES() throws CryptoUtilException {
        String encrypted = cryptoUtil.encryptAES("test".getBytes(), secretKey);
        assertNotNull(encrypted);
    }

    @Test
    void testDecryptAES() throws CryptoUtilException {
        String encrypted = cryptoUtil.encryptAES("test".getBytes(), secretKey);
        byte[] decrypted = cryptoUtil.decryptAES(encrypted, secretKey);
        assertArrayEquals("test".getBytes(), decrypted);
    }

    @Test
    void testGenerateKeyPair() throws CryptoUtilException {
        KeyPair keyPairs = cryptoUtil.generateKeyPair();
        assertNotNull(keyPairs);
        assertNotNull(keyPairs.getPublic());
        assertNotNull(keyPairs.getPrivate());
    }

    @Test
    void testGeneratePublicKeyFromBase64() throws Exception {
        String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        PublicKey publicKey = cryptoUtil.generatePublicKeyFromBase64(publicKeyBase64);
        assertNotNull(publicKey);
        assertEquals(keyPair.getPublic(), publicKey);
    }

    @Test
    void testGeneratePrivateKeyFromBase64() throws Exception {
        String privateKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        PrivateKey privateKey = cryptoUtil.generatePrivateKeyFromBase64(privateKeyBase64);
        assertNotNull(privateKey);
        assertEquals(keyPair.getPrivate(), privateKey);
    }

    @Test
    void testEncryptRSA() throws CryptoUtilException {
        String encrypted = cryptoUtil.encryptRSA("test".getBytes(), keyPair.getPublic());
        assertNotNull(encrypted);
    }

    @Test
    void testDecryptRSA() throws CryptoUtilException {
        String encrypted = cryptoUtil.encryptRSA("test".getBytes(), keyPair.getPublic());
        byte[] decrypted = cryptoUtil.decryptRSA(encrypted, keyPair.getPrivate());
        assertArrayEquals("test".getBytes(), decrypted);
    }

    @Test
    void testHmacSign() throws CryptoUtilException {
        String signature = cryptoUtil.hmacSign("test".getBytes(), "secret");
        assertNotNull(signature);
    }

    @Test
    void testHmacSignVerify() throws CryptoUtilException {
        String signedDocument = "test_.._" + cryptoUtil.hmacSign("test".getBytes(), "secret");
        assertTrue(cryptoUtil.hmacSignVerify(signedDocument, "secret"));
    }

    @Test
    void testRsaSign() throws CryptoUtilException {
        String signature = cryptoUtil.rsaSign("test".getBytes(), keyPair.getPrivate());
        assertNotNull(signature);
    }

    @Test
    void testRsaSignVerify() throws CryptoUtilException {
        String signedDocument = "test_.._" + cryptoUtil.rsaSign("test".getBytes(), keyPair.getPrivate());
        assertTrue(cryptoUtil.rsaSignVerify(signedDocument, keyPair.getPublic()));
    }
}