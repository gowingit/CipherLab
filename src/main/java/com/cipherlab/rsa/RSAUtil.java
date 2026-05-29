package com.cipherlab.rsa;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;

/**
 * RSA encryption and decryption operations
 */
public class RSAUtil {
    private static final String ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;

    /**
     * Generates an RSA key pair
     * @return KeyPair containing public and private keys
     */
    public static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(KEY_SIZE);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("RSA algorithm not available: " + e.getMessage());
        }
    }

    /**
     * Encrypts plaintext using RSA public key
     * @param plaintext the text to encrypt
     * @param publicKey the RSA public key
     * @return Base64 encoded encrypted text
     */
    public static String encrypt(String plaintext, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(plaintext.getBytes());
            return Base64.getEncoder().encodeToString(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed: " + e.getMessage());
        }
    }

    /**
     * Decrypts ciphertext using RSA private key
     * @param ciphertext the Base64 encoded encrypted text
     * @param privateKey the RSA private key
     * @return decrypted plaintext
     */
    public static String decrypt(String ciphertext, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decodedBytes = Base64.getDecoder().decode(ciphertext);
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);
            return new String(decryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed: " + e.getMessage());
        }
    }

    /**
     * Encrypts plaintext using RSA public key from byte array
     * @param plaintext the text to encrypt
     * @param publicKeyBytes the public key in byte array format
     * @return Base64 encoded encrypted text
     */
    public static String encryptWithKeyBytes(String plaintext, byte[] publicKeyBytes) {
        try {
            PublicKey publicKey = getPublicKeyFromBytes(publicKeyBytes);
            return encrypt(plaintext, publicKey);
        } catch (Exception e) {
            throw new RuntimeException("Encryption with key bytes failed: " + e.getMessage());
        }
    }

    /**
     * Decrypts ciphertext using RSA private key from byte array
     * @param ciphertext the Base64 encoded encrypted text
     * @param privateKeyBytes the private key in byte array format
     * @return decrypted plaintext
     */
    public static String decryptWithKeyBytes(String ciphertext, byte[] privateKeyBytes) {
        try {
            PrivateKey privateKey = getPrivateKeyFromBytes(privateKeyBytes);
            return decrypt(ciphertext, privateKey);
        } catch (Exception e) {
            throw new RuntimeException("Decryption with key bytes failed: " + e.getMessage());
        }
    }

    /**
     * Reconstructs PublicKey from byte array
     * @param publicKeyBytes the public key bytes
     * @return PublicKey object
     */
    public static PublicKey getPublicKeyFromBytes(byte[] publicKeyBytes) throws Exception {
        java.security.spec.X509EncodedKeySpec spec =
            new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    /**
     * Reconstructs PrivateKey from byte array
     * @param privateKeyBytes the private key bytes
     * @return PrivateKey object
     */
    public static PrivateKey getPrivateKeyFromBytes(byte[] privateKeyBytes) throws Exception {
        java.security.spec.PKCS8EncodedKeySpec spec =
            new java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }
}

