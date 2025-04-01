package org.example;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class Main {
    public static void main(String[] args) {

        int keysize = 128;
        //String originalText = "Witaj, świecie!";
        String originalText = "hejka";

        Encryptor encryptor = new Encryptor(originalText.getBytes(StandardCharsets.UTF_8), keysize);
        encryptor.encrypt();
        System.out.println("Szyfrogram: " + encryptor.bytesToHex(encryptor.joinEncryptedText()));

        Decryptor decryptor = new Decryptor(encryptor.joinEncryptedText(), keysize, encryptor.getRoundKeys());
        decryptor.decrypt();

        String decryptedText = decryptor.decryptedText();
        System.out.println("Test odszyfrowany: " + decryptedText);


        //sprawdzenie poprawności
        if (originalText.equals(decryptedText)) {
            System.out.println("✅ Odszyfrowany tekst jest zgodny z oryginałem!");
        } else {
            System.out.println("❌ Błąd: Odszyfrowany tekst NIE zgadza się z oryginałem!");
        }
    }
}