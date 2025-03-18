package org.example;

import javax.crypto.SecretKey;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {

        Encryptor encryptor = new Encryptor("Szyfrowanie AES używa bloków 128-bitowych", 128);

        encryptor.encrypt();
        SecretKey[] keys = encryptor.keyExpansion();
        for (SecretKey key : keys) {
            System.out.println(Arrays.toString(key.getEncoded()));
        }

    }
}