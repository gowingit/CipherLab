package com.cipherlab.cipher;

public class CaesarCipher {

    /**
     * Encrypts text using Caesar cipher with a given shift
     * @param text the text to encrypt
     * @param shift the number of positions to shift
     * @return encrypted text
     */
    public static String encrypt(String text, int shift) {
        StringBuilder result = new StringBuilder();
        shift = shift % 26;

        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                result.append((char) ((c - 'A' + shift) % 26 + 'A'));
            } else if (Character.isLowerCase(c)) {
                result.append((char) ((c - 'a' + shift) % 26 + 'a'));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Decrypts text using Caesar cipher with a given shift
     * @param text the text to decrypt
     * @param shift the number of positions used in encryption
     * @return decrypted text
     */
    public static String decrypt(String text, int shift) {
        return encrypt(text, 26 - (shift % 26));
    }
}

