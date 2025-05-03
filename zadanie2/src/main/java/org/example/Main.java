package org.example;

public class Main {
    public static void main(String[] args) {
        String text = "Kocham kryptografie!";
        Encryptor encryptor = new Encryptor(640, text.getBytes());
        Decryptor decryptor = new Decryptor(encryptor.getClenSignature(), text.getBytes(), encryptor.getP(), encryptor.getQ(), encryptor.getH(), encryptor.getB());
        System.out.println(decryptor.isSignatureValid);
    }
}