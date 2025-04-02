package org.example;

import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) {

        int keysize = 128;
        String originalText = "Witaj, świecie!";
        //String originalText = "Kryptologia – dziedzina wiedzy o przekazywaniu informacji w sposób zabezpieczony przed niepowołanym dostępem. Współcześnie kryptologia jest uznawana za gałąź zarówno matematyki, jak i informatyki; ponadto jest blisko związana z teorią informacji, inżynierią oraz bezpieczeństwem komputerowym.";
        //String originalText = "hejka";

        Encryptor encryptor = new Encryptor(originalText.getBytes(StandardCharsets.UTF_8), keysize);
        encryptor.encrypt();
        int padding = encryptor.getPadding();
        byte[] mainKey = encryptor.getMainKey();
        System.out.println("Szyfrogram: " + encryptor.bytesToHex(encryptor.joinEncryptedText()));

        Decryptor decryptor = new Decryptor(encryptor.joinEncryptedText(), keysize, mainKey);
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