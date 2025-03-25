package org.example;

import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) {

        int keysize = 128;
        Encryptor encryptor = new Encryptor("Szyfrowanie AES używa bloków 128-bitowych;;;;;;;;lkjhgfdqwertyuiop[;lkjhgfdsazxcvbnm,.;lkjhgfds", keysize);
        encryptor.encrypt();
        String text = encryptor.joinEncryptedText();
        System.out.println("Wynik:");
        System.out.println(text);

        Decryptor decryptor = new Decryptor(encryptor.joinEncryptedText(), keysize, encryptor.getRoundKeys());
        decryptor.decrypt();

//        System.out.println("Main key: " + Arrays.toString(encryptor.mainKey));
//        System.out.println("Words: ");
//        encryptor.keyExpansion();
//        for (int i=1; i<encryptor.keys.length; i++) {
//            System.out.println(encryptor.keys[i]);
//        }
//        encryptor.encrypt();
//        encryptor.keyExpansion();
//        byte[][] kEy = encryptor.keys;
//        for (int i = 0; i < kEy.length; i++) {
//            System.out.println(kEy[i]);
//        }

    }
}