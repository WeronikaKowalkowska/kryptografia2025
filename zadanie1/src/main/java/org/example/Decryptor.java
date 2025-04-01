package org.example;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class Decryptor {
    private int keySize;
    private int rounds;
    private byte[][] roundKeys = new byte[rounds + 1][];
    private byte[] cipherBytes;
    private ArrayList<byte[][]> cipherBlocksList;

    private static final int[] invertedSbox = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    //konstruktor
    public Decryptor(byte[] cipherText, int keySize, byte[][] roundKeys) {

        this.keySize = keySize;
        cipherBytes = cipherText;

        if (keySize == 128) {
            rounds = 10;
        }
        if (keySize == 192) {
            rounds = 12;
        }
        if (keySize == 256) {
            rounds = 14;
        }

        this.roundKeys = reverseRoundKeys(roundKeys);
        this.cipherBlocksList = new ArrayList<>();

        textToByteBlocks();

    }

    //podział na dwuwymiarowe bloki
    public void textToByteBlocks() {
        //podział tekstu na bloki
        for (int i = 0; i < cipherBytes.length; i += 16) {    //iteracja po blokach szyfrogramu
            byte[][] block = new byte[4][4];
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    block[row][col] = cipherBytes[i + (col * 4) + row];
                }
            }

            cipherBlocksList.add(block);      //dodanie nowo stworzonego bloku do listy bloków
        }

    }

    //zapisuje klucze wykorzystane do szyfrowania w odwrotnej kolejności
    public byte[][] reverseRoundKeys(byte[][] roundKeys) {
        byte[][] temp = new byte[roundKeys.length][];
        for (int i = 0; i < roundKeys.length; i++) {
            temp[i] = roundKeys[roundKeys.length - 1 - i];      //odwrócenie kolejności
        }
        return temp;
    }

    //zamiana słowa na wartości z inverted S-boxa
    public byte invertedSubByte(byte input) {
        int index = input & 0xFF;       //mapuje wartość na zakres 0-255
        return (byte) invertedSbox[index];      //podmiana na odpowiedni bajt w inverted S-boxie
    }

    //przesunięcie w prawo bajtów w słowie
    public byte[] invertedRotWord(byte[] word) {
        byte[] rotWord = new byte[4];
        rotWord[0] = word[3];
        for (int i = 1; i < 4; i++) {
            rotWord[i] = word[i - 1];
        }
        return rotWord;
    }

    //przesunięcie wierszy w bloku, jako paramenty podajemy wiersz i o ile trzeba przesunąć wartości
    public byte[] invertedShiftRow(byte[] row, int howMuch) {
        byte[] temp = new byte[4];
        for (int i = 0; i < row.length; i++) {
            temp[i] = row[i];       //kopiowanie row do temp
        }
        for (int i = 0; i < howMuch; i++) {
            temp = invertedRotWord(temp);   //przesunięcie 'howMuch' razy
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

    //mnożenie pola Galois (dla mnożenia razy 9, 11, 13 i 14)
    public byte invertedMultiplyBy(byte b, int howMuch) {
        switch (howMuch) {
            case 9:
                return (byte) (multiplyBy(multiplyBy(multiplyBy(b, 2), 2), 2) ^ b);
            case 11:
                return (byte) (multiplyBy((byte) (multiplyBy(multiplyBy(b, 2), 2) ^ b), 2) ^ b);
            case 13:
                return (byte) (multiplyBy(multiplyBy((byte) (multiplyBy(b, 2) ^ b), 2), 2) ^ b);
            case 14:
                return (byte) (multiplyBy((byte) (multiplyBy((byte) (multiplyBy(b, 2) ^ b), 2) ^ b), 2));
        }
        return 0;
    }

    public void decrypt() {
        for (int blockCount = 0; blockCount < cipherBlocksList.size(); blockCount++) {      //dla każdego bloku wykonaj rundy
            byte[][] block = cipherBlocksList.get(blockCount);    //zmienna przechowująca bierzący blok, dla którego wykonujemy deszyfrowanie

            //AddRoundKey początkowe
            addRoundKey(block, 0);  //zaczynamy deszyfrowanie od ostatniego klucza (odwrotna kolejność)

            for (int round = 1; round <= rounds; round++) {

                //INVERTED ShiftRows - rotacja wierszy
                for (int row = 0; row < 4; row++) {
                    byte[] blockRow = new byte[4];
                    for (int col = 0; col < 4; col++) {
                        blockRow[col] = block[row][col];    //zapisywanie pojedynczego wiersza do zmiennej
                    }

                    if (row != 0) {                              //pierwszy wiersz jest bez zmian
                        byte[] shiftedRow = invertedShiftRow(blockRow, row);     //przesuwanie
                        for (int col = 0; col < 4; col++) {
                            block[row][col] = shiftedRow[col];     //zapisywanie zmienionego wiersza do bloku
                        }
                    }
                }

                //INVERTED SubBytes - każdy bajt bloku jest zamieniany na inny z S-boxa
                for (int row = 0; row < 4; row++) {
                    for (int col = 0; col < 4; col++) {
                        block[row][col] = invertedSubByte(block[row][col]);
                    }
                }

                //AddRoundKey dla bierzącej rundy
                addRoundKey(block, round);

                //INVERTED mix columns - POPRAWIĆ
                if (round != rounds) {       //operacja nie jest wykonywana dla ostatniej rundy
                    for (int col = 0; col < 4; col++) {
                        byte[] blockCol = new byte[4];
                        for (int row = 0; row < 4; row++) {
                            blockCol[row] = block[row][col];      //zapisywanie pojedynczej kolumny do zmiennej
                        }
                        byte a0 = (byte) (invertedMultiplyBy(blockCol[0], 14) ^ invertedMultiplyBy(blockCol[1], 11) ^ invertedMultiplyBy(blockCol[2], 13) ^ invertedMultiplyBy(blockCol[3], 9));
                        byte a1 = (byte) (invertedMultiplyBy(blockCol[0], 9) ^ invertedMultiplyBy(blockCol[1], 14) ^ invertedMultiplyBy(blockCol[2], 11) ^ invertedMultiplyBy(blockCol[3], 13));
                        byte a2 = (byte) (invertedMultiplyBy(blockCol[0], 13) ^ invertedMultiplyBy(blockCol[1], 9) ^ invertedMultiplyBy(blockCol[2], 14) ^ invertedMultiplyBy(blockCol[3], 11));
                        byte a3 = (byte) (invertedMultiplyBy(blockCol[0], 11) ^ invertedMultiplyBy(blockCol[1], 13) ^ invertedMultiplyBy(blockCol[2], 9) ^ invertedMultiplyBy(blockCol[3], 14));

                        blockCol[0] = a0;
                        blockCol[1] = a1;
                        blockCol[2] = a2;
                        blockCol[3] = a3;

                        for (int row = 0; row < 4; row++) {
                            block[row][col] = blockCol[row];        //zapisywanie zmienionej kolumny do bloku
                        }

                    }
                }

                cipherBlocksList.set(blockCount, block);     //dodajemy zmieniony blok do listy
            }
        }

    }

    //zwraca odszyfrowany tekst w postaci tablicy bajtów (razem z padding)
    public byte[] joinEncryptedText() {
        byte[] all = new byte[16 * cipherBlocksList.size()];
        int index = 0;
        for (byte[][] block : cipherBlocksList) {     //dla wszystkich bloków
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    all[index] = block[row][col];
                    index++;
                }
            }
        }
        return all;
    }

    //usuwanie dodanych zer
    public byte[] removePadding() {

        byte[] blockOneDimensional = joinEncryptedText();    //tablica jednowymiarowa dla zapisu wszystkich bloków

//        if (blockOneDimensional.length % 16 == 0) {     //przypadek, gdzy nie ma paddingu
//            return blockOneDimensional;
//        }
//            System.out.println(Arrays.toString(blockOneDimensional));
//
//        int padLength = blockOneDimensional[blockOneDimensional.length - 1] & 0xFF; //liczba dodanego paddingu z ostatniego bajta
//
//        System.out.println(blockOneDimensional.length);
//        System.out.println(padLength);
//
//        byte[] blockOneDimensionalNoPadding = new byte[blockOneDimensional.length - padLength];     //przepisuje wszystkie wartości oprócz paddingu
//
//        for (int i = 0; i < blockOneDimensionalNoPadding.length; i++) {
//            blockOneDimensionalNoPadding[i] = blockOneDimensional[i];
//        }
//
//        return blockOneDimensionalNoPadding;
        int padLength = blockOneDimensional[blockOneDimensional.length - 1] & 0xFF;
        byte[] unpadded = new byte[blockOneDimensional.length - padLength];
        System.arraycopy(blockOneDimensional, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }

    public String decryptedText() {
        return new String(removePadding(), StandardCharsets.UTF_8);
    }


}
