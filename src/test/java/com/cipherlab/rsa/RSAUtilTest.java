package com.cipherlab.rsa;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import static org.junit.jupiter.api.Assertions.*;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAUtilTest {

    private KeyPair keyPair;

    @BeforeEach
    public void setUp() {
        keyPair = RSAUtil.generateKeyPair();
    }

    @Test
    public void testGenerateKeyPair() {
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
    }

    @Test
    public void testGenerateKeyPairPublicKeyIsNotNull() {
        PublicKey publicKey = keyPair.getPublic();
        assertNotNull(publicKey);
        assertEquals("RSA", publicKey.getAlgorithm());
    }

    @Test
    public void testGenerateKeyPairPrivateKeyIsNotNull() {
        PrivateKey privateKey = keyPair.getPrivate();
        assertNotNull(privateKey);
        assertEquals("RSA", privateKey.getAlgorithm());
    }

    @Test
    public void testEncryptReturnsBase64String() {
        PublicKey publicKey = keyPair.getPublic();
        String plaintext = "Hello, RSA!";
        String encrypted = RSAUtil.encrypt(plaintext, publicKey);

        assertNotNull(encrypted);
        assertNotEquals(plaintext, encrypted);
        assertTrue(encrypted.length() > 0);
    }

    @Test
    public void testDecryptReturnsOriginalText() {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String plaintext = "Hello, RSA!";

        String encrypted = RSAUtil.encrypt(plaintext, publicKey);
        String decrypted = RSAUtil.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testEncryptDecryptRoundTrip() {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String original = "The quick brown fox jumps over the lazy dog";

        String encrypted = RSAUtil.encrypt(original, publicKey);
        String decrypted = RSAUtil.decrypt(encrypted, privateKey);

        assertEquals(original, decrypted);
    }

    @Test
    public void testEncryptDifferentTextsProduceDifferentCiphertexts() {
        PublicKey publicKey = keyPair.getPublic();
        String text1 = "Message 1";
        String text2 = "Message 2";

        String encrypted1 = RSAUtil.encrypt(text1, publicKey);
        String encrypted2 = RSAUtil.encrypt(text2, publicKey);

        assertNotEquals(encrypted1, encrypted2);
    }

    @Test
    public void testEncryptEmptyString() {
        PublicKey publicKey = keyPair.getPublic();
        String plaintext = "";

        String encrypted = RSAUtil.encrypt(plaintext, publicKey);
        assertNotNull(encrypted);
    }

    @Test
    public void testEncryptLongText() {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String plaintext = "A".repeat(100); // 100 character string

        String encrypted = RSAUtil.encrypt(plaintext, publicKey);
        String decrypted = RSAUtil.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testEncryptSpecialCharacters() {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String plaintext = "!@#$%^&*()_+-=[]{}|;':\",./<>?";

        String encrypted = RSAUtil.encrypt(plaintext, publicKey);
        String decrypted = RSAUtil.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testEncryptUnicodeCharacters() {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        String plaintext = "Hello 世界 مرحبا мир";

        String encrypted = RSAUtil.encrypt(plaintext, publicKey);
        String decrypted = RSAUtil.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testMultipleEncryptionsSamePlaintext() {
        PublicKey publicKey = keyPair.getPublic();
        String plaintext = "Test";

        // RSA should produce different ciphertexts for the same plaintext (due to padding)
        // But we're testing with the same plaintext
        String encrypted1 = RSAUtil.encrypt(plaintext, publicKey);
        String encrypted2 = RSAUtil.encrypt(plaintext, publicKey);

        assertNotNull(encrypted1);
        assertNotNull(encrypted2);
    }

    @Test
    public void testPublicKeyFromBytes() throws Exception {
        PublicKey originalKey = keyPair.getPublic();
        byte[] keyBytes = originalKey.getEncoded();

        PublicKey reconstructedKey = RSAUtil.getPublicKeyFromBytes(keyBytes);

        assertNotNull(reconstructedKey);
        assertEquals(originalKey.getAlgorithm(), reconstructedKey.getAlgorithm());
        assertEquals(originalKey.getFormat(), reconstructedKey.getFormat());
    }

    @Test
    public void testPrivateKeyFromBytes() throws Exception {
        PrivateKey originalKey = keyPair.getPrivate();
        byte[] keyBytes = originalKey.getEncoded();

        PrivateKey reconstructedKey = RSAUtil.getPrivateKeyFromBytes(keyBytes);

        assertNotNull(reconstructedKey);
        assertEquals(originalKey.getAlgorithm(), reconstructedKey.getAlgorithm());
        assertEquals(originalKey.getFormat(), reconstructedKey.getFormat());
    }

    @Test
    public void testEncryptWithKeyBytes() throws Exception {
        PublicKey publicKey = keyPair.getPublic();
        byte[] keyBytes = publicKey.getEncoded();
        PrivateKey privateKey = keyPair.getPrivate();

        String plaintext = "Test with key bytes";
        String encrypted = RSAUtil.encryptWithKeyBytes(plaintext, keyBytes);
        String decrypted = RSAUtil.decrypt(encrypted, privateKey);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testDecryptWithKeyBytes() throws Exception {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        byte[] keyBytes = privateKey.getEncoded();

        String plaintext = "Test with key bytes";
        String encrypted = RSAUtil.encrypt(plaintext, publicKey);
        String decrypted = RSAUtil.decryptWithKeyBytes(encrypted, keyBytes);

        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testEncryptWithNullPlaintextThrowsException() {
        PublicKey publicKey = keyPair.getPublic();
        assertThrows(NullPointerException.class, () -> {
            RSAUtil.encrypt(null, publicKey);
        });
    }

    @Test
    public void testDecryptWithNullCiphertextThrowsException() {
        PrivateKey privateKey = keyPair.getPrivate();
        assertThrows(NullPointerException.class, () -> {
            RSAUtil.decrypt(null, privateKey);
        });
    }

    @Test
    public void testFullEncryptionDecryptionCycle() {
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String message = "Confidential Information";
        String encrypted = RSAUtil.encrypt(message, publicKey);
        String decrypted = RSAUtil.decrypt(encrypted, privateKey);

        assertEquals(message, decrypted);
        assertNotEquals(message, encrypted);
    }

    @Test
    public void testNewKeyPairsProduceDifferentResults() {
        KeyPair keyPair1 = RSAUtil.generateKeyPair();
        KeyPair keyPair2 = RSAUtil.generateKeyPair();

        String plaintext = "Test";
        String encrypted1 = RSAUtil.encrypt(plaintext, keyPair1.getPublic());
        String encrypted2 = RSAUtil.encrypt(plaintext, keyPair2.getPublic());

        // Different keys should produce different ciphertexts
        assertNotEquals(encrypted1, encrypted2);

        // Each key pair should decrypt its own ciphertext
        assertEquals(plaintext, RSAUtil.decrypt(encrypted1, keyPair1.getPrivate()));
        assertEquals(plaintext, RSAUtil.decrypt(encrypted2, keyPair2.getPrivate()));
    }

    @Test
    public void testDecryptWithWrongKeyFails() {
        String plaintext = "Secret";
        String encrypted = RSAUtil.encrypt(plaintext, keyPair.getPublic());

        KeyPair wrongKeyPair = RSAUtil.generateKeyPair();

        // Decryption with wrong private key should fail
        assertThrows(RuntimeException.class, () -> {
            RSAUtil.decrypt(encrypted, wrongKeyPair.getPrivate());
        });
    }
}

