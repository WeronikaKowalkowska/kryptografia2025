package org.example;

public class Main {
    public static void main(String[] args) {

        Encryptor encryptor = new Encryptor("Szyfrowanie AES używa bloków 128-bitowych", 128);
        encryptor.encrypt();

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