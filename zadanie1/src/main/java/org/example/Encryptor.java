package org.example;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Encryptor {
    public boolean choice; //true- tekst z konoloi (gui) ; false-test z pliku ; default- z konsoli
    public String plainText;
    public byte[] plainBytes;
    public List<byte[]> blocks = new ArrayList();
    public int keySize;

    //konstruktor
    public Encryptor(String plainText, int keySize) {
        this.plainText = plainText;
        this.keySize = keySize;
        plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
    }

    //metoda, która dzieli tekst jawny na bloki po 16 bajtów
    public void textToBytesBlocks() {
        // sprawdz dlugosc plainTextChars i uzupelnij zerami jesli brakuje
        if(plainBytes.length%16!=0)
        {
            //cos tam
        }
        //petla for na wczytanie i dzialanie na blokach -> zrob mape i przypisz charom numer bloku? enum?
        for (int i = 0; i < plainBytes.length; i += 16) {
            byte[] block = Arrays.copyOfRange(plainBytes, i, i + 16);
            blocks.add(block);
        }
    }

    public SecretKey[] keyExpansion() {
        KeyGenerator gen = null;

        SecretKey[] keys = null;
        int rounds = 0;
        if (keySize == 128) {
            rounds = 10;
        }
        if (keySize == 192) {
            rounds = 12;
        }
        if (keySize == 256) {
            rounds = 14;
        }

        try {
            gen = KeyGenerator.getInstance("AES");
            gen.init(128);
            keys = new SecretKey[rounds+1];
            for (int i = 0; i <rounds+1; i++) {
                keys[i] = gen.generateKey();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return keys;
    }

    public void addRoundKey(byte[] block) {

    }

    public void encrypt() {
        textToBytesBlocks();
        System.out.println("Ile bloków: " + blocks.size());
        for (byte[] block : blocks) {
            System.out.print("{");
            for (byte b : block) {
                //przekształcenie na zakres 0-255 (unsigned byte)
                System.out.print(b & 0xFF);
                System.out.print(", ");
            }
            System.out.print("}");
            System.out.println();
        }
    }

    //wybierz długość klucza
//    public enum keyLenght{128,192,256};
//    public enum rounds {10,12,14};

    //1. key expansions??? - wygenerowanie z gory wszytskich kluczy??

    //2.add round key

    //3. rundy

        //a. sub bytes - zamiana bajtu z bloku na bajt z sub_box

        //b. shift rows- pierwszy wiersz bloku bez zmian, drugi o jedno miejsce w lewo, trzeci o dwa w lewo a czwarty o trzy w lewo (Rotate left)

        //c. mix columns - przemnarzanie bloku do zaszyfrowania przez dana macierz (wbudowana? kolumna? ) (caly blok przemnozyc przez jakas kolumne?)
            //mam macierz b z tekstu jawnego i wybieram sobie macierz a ktora mnoze przez patrz wzor wikipeedia i nowy b = operacja macierzy z a
        //d. add round key - caly blok xor z wygenerowanym podkluczem z key extensions?

    //4. ostatnia runda bez mix columns


    //Deszyfrowanie w odwrotnej kolejności
    //● inne S-Boxy
    //● MixColumns


}
