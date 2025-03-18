package org.example;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Encryptor {
    public boolean choice; //true- tekst z konoloi (gui) ; false-test z pliku ; default- z konsoli
    public String plainText;
    public byte[] plainBytes;
    public List<byte[]> blocks = new ArrayList();

    //konstruktor
    public Encryptor(String plainText) {
        this.plainText = plainText;
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
