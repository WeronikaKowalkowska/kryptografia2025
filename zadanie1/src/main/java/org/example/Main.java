package org.example;

import java.util.Arrays;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {

        int keysize = 128;
        Encryptor encryptor = new Encryptor("Szyfrowanie AES używa bloków 128-bitowych".getBytes(), keysize);
        encryptor.encrypt();
        String text = Base64.getEncoder().withoutPadding().encodeToString(encryptor.joinEncryptedText());
        System.out.println("Wynik: " + text);
        System.out.println("Wynik bajtowy: " + Arrays.toString(encryptor.joinEncryptedText()));

        Decryptor decryptor = new Decryptor(encryptor.joinEncryptedText(), keysize, encryptor.getRoundKeys(), encryptor.getPaddingCount());
        decryptor.decrypt();
        System.out.println("Wynik:" + decryptor.getDecryptedText());


    }
}