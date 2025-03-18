package org.example;

public class Encryptor {
    public boolean choice; //true- tekst z konoloi (gui) ; false-test z pliku ; default- z konsoli
    public String plainText;

    //konstruktor
    public Encryptor() {}

    //podziel tekst jawny na bloki po 16 bajtów

    //wybierz długość klucza
    public enum keyLenght{128,192,256};
    public enum rounds {10,12,14};

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
