package org.example;

import java.security.MessageDigest;

public class Encryptor {
    private int p; //duża liczba pierwsza
    private int q; //mniejsza liczba pierwsza dzieląca p-1
    private int g; //element wyliczony z p i g pełniący funckję generataora

    //generacja p,q i g
    private void generate_params(){

    }

    private int x; //klucz prywatny, wartość losowa z (0,q)
    private int y; //klucz publiczny, y=(g^x) mod p

    //tworzenie pary kluczy
    private void generate_keys(){

    }

    private String m; //wiadomość do zaszyfrowania
    private String h; //skrót wiadomości liczony funkcją hashującą SHA 1 lub 2 - w naszym przypadku SHA 1

    private int k; //losowa, tajna i unikalna wartosć z przedziału (0,q)

    private int r; // r = [(g^k) mod p] mod q

    private int s; // s=[k^-1 (h+xr) ] mod q  ;  k^-1 - odwrotonośc k mod q ; jeśli s==0 trzeba wybrać nowe k

    //signature -> (r, s)

    private int keyLength;


    //konstrunktor
    public Encryptor() {

        h=hash_message(m);

    }

    //funkcja służąca generacji losowej wartosci z zakresu
//    private int rand_value(int min, int max){
//
//    }

    //https://stackoverflow.com/questions/4895523/java-string-to-sha1
    private static String hash_message(String password)
    {
        String sha1 = "";
        try
        {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            crypt.reset();
            crypt.update(password.getBytes("UTF-8"));
            sha1 = bytesToHex(crypt.digest());
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return sha1;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

}
