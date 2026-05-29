package com.cipherlab.cipher;

public class VigenereCipher {

    /**
     * Encrypts text using Vigenere cipher with a given key
     * @param text the text to encrypt
     * @param key the encryption key (alphabetic characters only)
     * @return encrypted text
     */
    public static String encrypt(String text, String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int keyIndex = 0;

        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                int shift = getAlphabetIndex(key.charAt(keyIndex % key.length()));
                result.append((char) ((c - 'A' + shift) % 26 + 'A'));
                keyIndex++;
            } else if (Character.isLowerCase(c)) {
                int shift = getAlphabetIndex(key.charAt(keyIndex % key.length()));
                result.append((char) ((c - 'a' + shift) % 26 + 'a'));
                keyIndex++;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Decrypts text using Vigenere cipher with a given key
     * @param text the text to decrypt
     * @param key the decryption key (same as encryption key)
     * @return decrypted text
     */
    public static String decrypt(String text, String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be null or empty");
        }

        StringBuilder result = new StringBuilder();
        key = key.toUpperCase();
        int keyIndex = 0;

        for (char c : text.toCharArray()) {
            if (Character.isUpperCase(c)) {
                int shift = getAlphabetIndex(key.charAt(keyIndex % key.length()));
                result.append((char) ((c - 'A' - shift + 26) % 26 + 'A'));
                keyIndex++;
            } else if (Character.isLowerCase(c)) {
                int shift = getAlphabetIndex(key.charAt(keyIndex % key.length()));
                result.append((char) ((c - 'a' - shift + 26) % 26 + 'a'));
                keyIndex++;
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    /**
     * Gets the index of a character in the alphabet (A/a = 0, B/b = 1, ... Z/z = 25)
     * @param c the character
     * @return the alphabet index
     */
    private static int getAlphabetIndex(char c) {
        return Character.toUpperCase(c) - 'A';
    }

    /**
     * Repeats the key to match the length of the text (alphabetic characters only)
     * @param text the text
     * @param key the key to repeat
     * @return the repeated key
     */
    public static String repeatKey(String text, String key) {
        StringBuilder repeatedKey = new StringBuilder();
        int keyIndex = 0;

        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                repeatedKey.append(key.charAt(keyIndex % key.length()));
                keyIndex++;
            }
        }
        return repeatedKey.toString();
    }
}

