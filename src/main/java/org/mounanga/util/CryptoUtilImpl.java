package org.mounanga.util;

import org.apache.commons.codec.binary.Hex;
import org.jetbrains.annotations.NotNull;
import org.mounanga.util.exception.CryptoUtilException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

public class CryptoUtilImpl implements CryptoUtil {

    private static final int KEY_SIZE = 1024;
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String HMAC_SHA256 = "HmacSHA256";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";

    public CryptoUtilImpl() {
        super();
    }

    @Override
    public String encodeToBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    @Override
    public byte[] decodeFromBase64(@NotNull String dataBase64) {
        return Base64.getDecoder().decode(dataBase64.getBytes());
    }

    @Override
    public String encodeToBase64Url(byte[] data) {
        return Base64.getUrlEncoder().encodeToString(data);
    }

    @Override
    public byte[] decodeFromBase64Url(@NotNull String dataBase64) {
        return Base64.getUrlDecoder().decode(dataBase64.getBytes());
    }

    @Override
    public String encodeToHex(byte[] data) {
        return Hex.encodeHexString(data);
    }

    @Override
    public String encodeToHexNative(byte @NotNull [] data) throws CryptoUtilException {
        try (Formatter formatter = new Formatter()) {
            for (byte b : data) {
                formatter.format("%02x", b);
            }
            return formatter.toString();
        } catch (Exception e) {
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public SecretKey generateSecretKey() throws CryptoUtilException {
        try{
            KeyGenerator keyGenerator = KeyGenerator.getInstance(AES);
            keyGenerator.init(256);
            return keyGenerator.generateKey();
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public SecretKey generateSecretKey(@NotNull String secret) {
        return new SecretKeySpec(secret.getBytes(), 0, secret.length(), AES);
    }

    @Override
    public String encryptAES(byte[] data, SecretKey secretKey) throws CryptoUtilException {
        try{
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = cipher.doFinal(data);
            return Base64.getEncoder().encodeToString(encryptedData);
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decryptAES(String encodedEncryptedData, SecretKey secretKey) throws CryptoUtilException {
        try{
            byte[] decodedEncryptedData = Base64.getDecoder().decode(encodedEncryptedData);
            Cipher cipher = Cipher.getInstance(AES);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return cipher.doFinal(decodedEncryptedData);
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public KeyPair generateKeyPair() throws CryptoUtilException {
        try{
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public PublicKey generatePublicKeyFromBase64(String publicKeyBase64) throws CryptoUtilException {
        try{
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            byte[] decodedPK = Base64.getDecoder().decode(publicKeyBase64);
            return keyFactory.generatePublic(new X509EncodedKeySpec(decodedPK));
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public PrivateKey generatePrivateKeyFromBase64(String publicKeyBase64) throws CryptoUtilException {
        try{
            KeyFactory keyFactory = KeyFactory.getInstance(RSA);
            byte[] decodedPK = Base64.getDecoder().decode(publicKeyBase64);
            return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(decodedPK));
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public String encryptRSA(byte[] data, PublicKey publicKey) throws CryptoUtilException {
        try{
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] bytes = cipher.doFinal(data);
            return encodeToBase64(bytes);
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public byte[] decryptRSA(String dataBase64, PrivateKey privateKey) throws CryptoUtilException{
        try{
            Cipher cipher = Cipher.getInstance(RSA);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decodedEncryptedData = decodeFromBase64(dataBase64);
            return cipher.doFinal(decodedEncryptedData);
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }

    }

    @Override
    public PublicKey publicKeyFromCertificate(String fileName) throws CryptoUtilException {
        try{
            FileInputStream fileInputStream = new FileInputStream(fileName);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            Certificate certificate = certificateFactory.generateCertificate(fileInputStream);
            return certificate.getPublicKey();
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }

    }

    @Override
    public PrivateKey privateKeyFromJKS(String fileName, @NotNull String jksPassword, String alias) throws CryptoUtilException {
        try{
            FileInputStream fileInputStream = new FileInputStream(fileName);
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(fileInputStream, jksPassword.toCharArray());
            Key key = keyStore.getKey(alias, jksPassword.toCharArray());
            return (PrivateKey) key;
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public String hmacSign(byte[] data, @NotNull String privateSecret) throws CryptoUtilException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(privateSecret.getBytes(), HMAC_SHA256);
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(secretKeySpec);
            byte[] signature = mac.doFinal(data);
            return Base64.getEncoder().encodeToString(signature);
        }catch (Exception e) {
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public boolean hmacSignVerify(@NotNull String signedDocument, @NotNull String secret) throws CryptoUtilException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(secret.getBytes(), HMAC_SHA256);
            Mac mac = Mac.getInstance(HMAC_SHA256);
            mac.init(secretKeySpec);
            String[] splitedDocument = signedDocument.split("_.._");
            String document = splitedDocument[0];
            String documentSignature = splitedDocument[1];
            byte[] sign = mac.doFinal(document.getBytes());
            String signBase64 = Base64.getEncoder().encodeToString(sign);
            return (signBase64.equals(documentSignature));
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public String rsaSign(byte[] data, PrivateKey privateKey) throws CryptoUtilException {
        try{
            Signature signature = Signature.getInstance(SHA256_WITH_RSA);
            signature.initSign(privateKey, new SecureRandom());
            signature.update(data);
            byte[] sign = signature.sign();
            return Base64.getEncoder().encodeToString(sign);
        }catch (Exception e){
            throw new CryptoUtilException(e.getMessage(), e);
        }
    }

    @Override
    public boolean rsaSignVerify(@NotNull String signedDoc, PublicKey publicKey) throws CryptoUtilException {
        try{
            Signature signature = Signature.getInstance(SHA256_WITH_RSA);
            signature.initVerify(publicKey);
            String[] data = signedDoc.split("_.._");
            String document = data[0];
            String sign = data[1];
            byte[] decodeSignature = Base64.getDecoder().decode(sign);
            signature.update(document.getBytes());
            return signature.verify(decodeSignature);
        }catch (Exception e){
           throw new CryptoUtilException(e.getMessage(), e);
        }

    }
}
