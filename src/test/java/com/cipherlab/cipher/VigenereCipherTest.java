package com.cipherlab.cipher;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class VigenereCipherTest {

    @Test
    public void testBasicEncryption() {
        String plaintext = "HELLO";
        String key = "KEY";
        String expected = "RIJVS";
        assertEquals(expected, VigenereCipher.encrypt(plaintext, key));
    }

    @Test
    public void testBasicDecryption() {
        String ciphertext = "RIJVS";
        String key = "KEY";
        String expected = "HELLO";
        assertEquals(expected, VigenereCipher.decrypt(ciphertext, key));
    }

    @Test
    public void testEncryptionLowercase() {
        String plaintext = "hello";
        String key = "key";
        String expected = "rijvs";
        assertEquals(expected, VigenereCipher.encrypt(plaintext, key));
    }

    @Test
    public void testDecryptionLowercase() {
        String ciphertext = "rijvs";
        String key = "key";
        String expected = "hello";
        assertEquals(expected, VigenereCipher.decrypt(ciphertext, key));
    }

    @Test
    public void testMixedCaseEncryption() {
        String plaintext = "Hello World";
        String key = "KEY";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        String decrypted = VigenereCipher.decrypt(encrypted, key);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testPreservesNonAlphabeticCharacters() {
        String plaintext = "HELLO, WORLD! 123";
        String key = "KEY";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        assertTrue(encrypted.contains(","));
        assertTrue(encrypted.contains("!"));
        assertTrue(encrypted.contains("123"));
    }

    @Test
    public void testRepeatingKeyLogic() {
        String plaintext = "ABCDEFGHIJ";
        String key = "ABC";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        String decrypted = VigenereCipher.decrypt(encrypted, key);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testSingleCharacterKey() {
        String plaintext = "HELLO";
        String key = "A";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        assertEquals(plaintext, encrypted); // A means shift by 0
    }

    @Test
    public void testLongKey() {
        String plaintext = "ATTACK";
        String key = "SECRETKEY";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        String decrypted = VigenereCipher.decrypt(encrypted, key);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testKeyLongerThanText() {
        String plaintext = "HI";
        String key = "VERYLONGKEY";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        String decrypted = VigenereCipher.decrypt(encrypted, key);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testEncryptDecryptRoundTrip() {
        String original = "The quick brown fox jumps over the lazy dog";
        String key = "SECRET";
        String encrypted = VigenereCipher.encrypt(original, key);
        String decrypted = VigenereCipher.decrypt(encrypted, key);
        assertEquals(original, decrypted);
    }

    @Test
    public void testEmptyStringHandling() {
        String plaintext = "";
        String key = "KEY";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        assertEquals("", encrypted);
    }

    @Test
    public void testNullKeyThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> {
            VigenereCipher.encrypt("HELLO", null);
        });
    }

    @Test
    public void testEmptyKeyThrowsException() {
        assertThrows(IllegalArgumentException.class, () -> {
            VigenereCipher.encrypt("HELLO", "");
        });
    }

    @Test
    public void testAlphabetIndexing() {
        // Testing with key that cycles through alphabet
        String plaintext = "AAAA";
        String key = "BCDE";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        assertEquals("BCDE", encrypted);
    }

    @Test
    public void testWrapAroundEncryption() {
        String plaintext = "XYZ";
        String key = "DEF";
        String encrypted = VigenereCipher.encrypt(plaintext, key);
        String decrypted = VigenereCipher.decrypt(encrypted, key);
        assertEquals(plaintext, decrypted);
    }

    @Test
    public void testRepeatKeyMethod() {
        String text = "HELLO WORLD";
        String key = "KEY";
        String repeated = VigenereCipher.repeatKey(text, key);
        assertEquals("KEYKEYKEYK", repeated);
    }

    @Test
    public void testRepeatKeyWithSpecialCharacters() {
        String text = "H-E-L-L-O";
        String key = "ABC";
        String repeated = VigenereCipher.repeatKey(text, key);
        assertEquals("ABCAB", repeated);
    }

    @Test
    public void testCaseSensitiveKeyHandling() {
        String plaintext = "HELLO";
        String keyLower = "key";
        String keyUpper = "KEY";
        String encryptedLower = VigenereCipher.encrypt(plaintext, keyLower);
        String encryptedUpper = VigenereCipher.encrypt(plaintext, keyUpper);
        assertEquals(encryptedLower, encryptedUpper);
    }
}

