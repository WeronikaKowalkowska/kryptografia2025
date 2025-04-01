package org.example;

import javax.crypto.KeyGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;


public class Encryptor {
    private byte[] plainBytes;                  //tekst jawny zamieniony na bajty
    private int keySize;                        //długość klucza
    private int rounds;                         //ilość rund do wykonania na pojedynczym bloku tekstu
    private byte[] mainKey;                     //klucz główny

    public int getKeySize() {
        return keySize;
    }

    private ArrayList<byte[][]> blocksList;     //lista tablic bajtów tekstu jawnego podzielonego na 16-bajtowe bloki
    private int padding;                        //ilość dodanych zer do ostatniego bloku
    //pierwszy wymiar określa liczbę kluczy rundowych; drugi wymiar to tablica bajtów reprezentujących klucz dla danej rundy
    private byte[][] roundKeys;                 //lista kluczy dla każdej rundy na blokach

    private static final int[] sbox = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
            0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
            0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
            0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23,
            0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
            0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52,
            0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
            0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9,
            0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
            0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
            0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
            0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0,
            0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62,
            0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
            0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
            0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
            0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
            0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
            0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41,
            0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

    private static final int[] rcon = {
            0x00, //nie używana
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    //konstruktor
    public Encryptor(byte[] plainText, int keySize) {

        this.keySize = keySize;
        plainBytes = plainText;

        //przypisanie klasie ilości rund do wykonania w zależności od długości klucza
        if (keySize == 128) {
            rounds = 10;
        }
        if (keySize == 192) {
            rounds = 12;
        }
        if (keySize == 256) {
            rounds = 14;
        }

        this.roundKeys = new byte[rounds + 1][];    //rozmiar jest o jeden więcej, ponieważ generujemy na jeden podklucz więcej niż ilość rund
        this.blocksList = new ArrayList<>();

        mainKeyGenerate();     //generacja klucza głównego
        keyExpansion();        //generowanie podkluczy dla wszystkich rund
        textToByteBlocks();    //podział teksu jawnego w postaci bajtów na bloki

        System.out.println("Klucz główny: " + bytesToHex(mainKey));

    }

    //podział na dwuwymiarowe bloki
    public void textToByteBlocks() {
        int length = plainBytes.length;          //długość tekstu jawnego zamienionego na bajty

        if (length % 16 != 0) {                  //sprawdzenie i uzupełnienie zerami, jeżeli tekst nie jest wielokrotnością 16 bajtów
            this.padding = 16 - (length % 16);   //liczba dodanych bajtów zapisywana do zmiennej
            byte[] padded = new byte[plainBytes.length + padding];
            for (int i = 0; i < length; i++) {
                padded[i] = plainBytes[i];  //kopiujemy bajty
            }
            for (int i = length; i < padded.length; i++) {
                padded[i] = (byte) padding;     //zapisujemy ile dodaliśmy paddingu jako dodatkowe padding bajtów
            }
            this.plainBytes = padded;
        }

        //podział tekstu na bloki
        for (int i = 0; i < plainBytes.length; i += 16) {    //iteracja po blokach teksu
            byte[][] block = new byte[4][4];
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    block[row][col] = plainBytes[i + (col * 4) + row];
                }
            }

            blocksList.add(block);      //dodanie nowo stworzonego bloku do listy bloków
        }

    }

    //generacja klucza głównego
    public void mainKeyGenerate() {
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(keySize);
            mainKey = gen.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Błąd podczas generowania klucza głównego AES", e);
        }
    }

    public void keyExpansion() {
        byte[] allKeys = new byte[(rounds + 1) * 16];     //jednowymiarowa tablica na wszystkie podklucze, jej rozmiar to ilość podkluczy razy ich rozmiar, czyli 16

        for (int i = 0; i < mainKey.length; i++) {
            allKeys[i] = mainKey[i];        //kopiowanie klucza głownego jako pierwszego podklucza
        }

        int positionInAllKeys = mainKey.length;     //klicz głowny już dodano do tablicy
        int rconIteration = 1;
        byte[] temp = new byte[4];
        byte[] lastGeneratedWord = new byte[4];     //ostatnie słowo poprzednio wygenerowanego podklucza

        while (positionInAllKeys < allKeys.length) {    //dopóki nie wypełnimy całą tablicę podkluczy

            for (int i = 0; i < 4; i++) {
                lastGeneratedWord[i] = allKeys[positionInAllKeys - 4 + i];      //kopiowanie ostatniego wygenerowanego słowa
            }

            if (positionInAllKeys % (keySize / 32 * 4) == 0) {      //co 4,6 lub 8 słow -  w zależność od długości klucza, razy 4, bo iterujemy po bitach a nie słowach
                temp = subWord(rotWord(lastGeneratedWord));
                temp[0] = (byte) ((temp[0] & 0xFF) ^ rcon[rconIteration]);       //mapuje wartość na zakres 0-255
                rconIteration++;
                lastGeneratedWord = temp;
            }

            for (int i = 0; i < 4; i++) {
                allKeys[positionInAllKeys] = (byte) (allKeys[positionInAllKeys - (keySize / 32 * 4)] ^ lastGeneratedWord[i]); //(keySize / 32 * 4) - bait co 4,6 lub 8 słow temu
                positionInAllKeys++;
            }

        }

        byte[][] roundKeys = new byte[rounds + 1][16];

        for (int i = 0; i < rounds + 1; i++) {
            System.arraycopy(allKeys, i * 16, roundKeys[i], 0, 16);        //przepisanie podkluczy do tablicy dwuwymiarowej
        }

        this.roundKeys = roundKeys;

    }

    //zamiana pojedynczego bajta na wartość z S-boxa
    public byte subByte(byte input) {
        int index = input & 0xFF;       //mapuje wartość na zakres 0-255
        return (byte) sbox[index];      //podmiana na odpowiedni bajt w S-boxie
    }

    //zamiana słowa na wartości z S-boxa
    public byte[] subWord(byte[] input) {
        byte[] output = new byte[4];        //nowe słowo z wartościami z S-boxa
        for (int i = 0; i < 4; i++) {
            output[i] = subByte(input[i]);  //zamienia każdy bit
        }
        return output;
    }

    //przesunięcie w lewo bajtów w słowie
    public byte[] rotWord(byte[] word) {
        byte[] rotWord = new byte[4];
        rotWord[3] = word[0];
        for (int i = 0; i < 3; i++) {
            rotWord[i] = word[i + 1];         //przesunięcie
        }
        return rotWord;
    }

    //przesunięcie wierszy w bloku, jako paramenty podajemy wiersz i o ile trzeba przesunąć wartości
    public byte[] shiftRow(byte[] row, int howMuch) {
        byte[] temp = new byte[4];
        for (int i = 0; i < row.length; i++) {
            temp[i] = row[i];       //kopiowanie row do temp
        }
        for (int i = 0; i < howMuch; i++) {
            temp = rotWord(temp);   //przesunięcie 'howMuch' razy
        }
        return temp;
    }

    //wykonanie operacji xor-owania dla danego bloku i danej rundy
    public void addRoundKey(byte[][] block, int round) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                block[row][col] ^= roundKeys[round][col * 4 + row];
            }
        }
    }

    //mnożenie pola Galois (dla mnożenia razy 1, 2 i 3)
    public byte multiplyBy(byte b, int howMuch) {
        switch (howMuch) {
            case 1:
                return b;
            case 2:
                int result = (b & 0xFF) << 1;
                if ((b & 0x80) != 0) {         //jeśli najstarszy bit to 1 (przekroczenie 8 bitów)
                    result ^= 0x1B;             //redukcja przez xor-owanie 0x1B
                }
                return (byte) (result & 0xFF);
            case 3:
                return (byte) (multiplyBy(b, 2) ^ b);

        }
        return 0;
    }

    public void encrypt() {
        for (int blockCount = 0; blockCount < blocksList.size(); blockCount++) {    //dla każdego bloku wykonaj rundy
            byte[][] block = blocksList.get(blockCount);    //zmienna przechowująca bierzący blok, dla którego wykonujemy szyfrowanie

            //AddRoundKey początkowe
            addRoundKey(block, 0);                     //addRoundKey z pierwszym podkluczem (zerowy podklucz w tabeli podkluczy)

            for (int round = 1; round <= rounds; round++) {  //pozostałe rundy (zaczynamy od jedynki, ponieważ zerowy podklucz został już użyty)

                //SubBytes - każdy bajt bloku jest zamieniany na inny z S-boxa
                for (int row = 0; row < 4; row++) {
                    for (int col = 0; col < 4; col++) {
                        block[row][col] = subByte(block[row][col]);
                    }
                }

                //ShiftRows - rotacja wierszy
                for (int row = 0; row < 4; row++) {
                    byte[] blockRow = new byte[4];
                    for (int col = 0; col < 4; col++) {
                        blockRow[col] = block[row][col];    //zapisywanie pojedynczego wiersza do zmiennej
                    }

                    if (row != 0) {                                      //pierwszy wiersz jest bez zmian
                        byte[] shiftedRow = shiftRow(blockRow, row);     //przesuwanie
                        for (int col = 0; col < 4; col++) {
                            block[row][col] = shiftedRow[col];      //zapisywanie zmienionego wiersza do bloku
                        }
                    }
                }

                //MixColumns
                if (round != rounds) {                    //operacja nie jest wykonywana dla ostatniej rundy
                    for (int col = 0; col < 4; col++) {
                        byte[] blockCol = new byte[4];
                        for (int row = 0; row < 4; row++) {
                            blockCol[row] = block[row][col];    //zapisywanie pojedynczej kolumny do zmiennej
                        }

                        byte b0 = (byte) (multiplyBy(blockCol[0], 2) ^ multiplyBy(blockCol[1], 3) ^ multiplyBy(blockCol[2], 1) ^ multiplyBy(blockCol[3], 1));
                        byte b1 = (byte) (multiplyBy(blockCol[0], 1) ^ multiplyBy(blockCol[1], 2) ^ multiplyBy(blockCol[2], 3) ^ multiplyBy(blockCol[3], 1));
                        byte b2 = (byte) (multiplyBy(blockCol[0], 1) ^ multiplyBy(blockCol[1], 1) ^ multiplyBy(blockCol[2], 2) ^ multiplyBy(blockCol[3], 3));
                        byte b3 = (byte) (multiplyBy(blockCol[0], 3) ^ multiplyBy(blockCol[1], 1) ^ multiplyBy(blockCol[2], 1) ^ multiplyBy(blockCol[3], 2));

                        blockCol[0] = b0;
                        blockCol[1] = b1;
                        blockCol[2] = b2;
                        blockCol[3] = b3;

                        for (int row = 0; row < 4; row++) {
                            block[row][col] = blockCol[row];         //zapisywanie zmienionej kolumny do bloku
                        }

                    }
                }

                //AddRoundKey dla bierzącej rundy
                addRoundKey(block, round);

            }

            blocksList.set(blockCount, block);   //dodajemy zmieniony blok do listy
        }

    }

    //zwraca zaszyfrowany tekst w postaci tablicy bajtów (razem z padding)
    public byte[] joinEncryptedText() {
        byte[] all = new byte[16 * blocksList.size()];
        int index = 0;
        for (byte[][] block : blocksList) {     //dla wszystkich bloków tekstu
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    all[index] = block[row][col];
                    index++;
                }
            }
        }
        return all;
    }

    public String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    public byte[][] getRoundKeys() {
        return roundKeys;
    }

    public int getPadding() {
        return padding;
    }
}
