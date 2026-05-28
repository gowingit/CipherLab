package com.cipherlab.cipher;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CaesarCipherTest {

    @Test
    public void testEncryptWithShiftOne() {
        String encrypted = CaesarCipher.encrypt("abc", 1);
        assertEquals("bcd", encrypted);
    }

    @Test
    public void testDecryptWithShiftOne() {
        String decrypted = CaesarCipher.decrypt("bcd", 1);
        assertEquals("abc", decrypted);
    }

    @Test
    public void testEncryptUpperCase() {
        String encrypted = CaesarCipher.encrypt("ABC", 1);
        assertEquals("BCD", encrypted);
    }

    @Test
    public void testEncryptMixedCase() {
        String encrypted = CaesarCipher.encrypt("AaBbCc", 1);
        assertEquals("BbCcDd", encrypted);
    }

    @Test
    public void testEncryptWithShiftThirteen() {
        String encrypted = CaesarCipher.encrypt("hello", 13);
        assertEquals("uryyb", encrypted);
    }

    @Test
    public void testDecryptWithShiftThirteen() {
        String decrypted = CaesarCipher.decrypt("uryyb", 13);
        assertEquals("hello", decrypted);
    }

    @Test
    public void testEncryptPreservesNonAlphabetic() {
        String encrypted = CaesarCipher.encrypt("Hello, World!", 1);
        assertEquals("Ifmmp, Xpsme!", encrypted);
    }

    @Test
    public void testEncryptWithZeroShift() {
        String encrypted = CaesarCipher.encrypt("hello", 0);
        assertEquals("hello", encrypted);
    }

    @Test
    public void testEncryptWithShiftGreaterThanTwentySix() {
        String encrypted = CaesarCipher.encrypt("abc", 27);
        assertEquals("bcd", encrypted);
    }

    @Test
    public void testEncryptWithNegativeShift() {
        String encrypted = CaesarCipher.encrypt("bcd", -1);
        assertEquals("abc", encrypted);
    }

    @Test
    public void testDecryptWithNegativeShift() {
        String decrypted = CaesarCipher.decrypt("abc", -1);
        assertEquals("bcd", decrypted);
    }

    @Test
    public void testEncryptDecryptRoundTrip() {
        String original = "The Quick Brown Fox Jumps Over The Lazy Dog";
        int shift = 5;
        String encrypted = CaesarCipher.encrypt(original, shift);
        String decrypted = CaesarCipher.decrypt(encrypted, shift);
        assertEquals(original, decrypted);
    }

    @Test
    public void testEncryptEmptyString() {
        String encrypted = CaesarCipher.encrypt("", 5);
        assertEquals("", encrypted);
    }

    @Test
    public void testEncryptOnlyNumbers() {
        String encrypted = CaesarCipher.encrypt("123456", 5);
        assertEquals("123456", encrypted);
    }

    @Test
    public void testEncryptSpecialCharacters() {
        String encrypted = CaesarCipher.encrypt("!@#$%^&*()", 5);
        assertEquals("!@#$%^&*()", encrypted);
    }
}

