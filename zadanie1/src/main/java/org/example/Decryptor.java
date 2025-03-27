package org.example;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class Decryptor {
    private int keySize;
    private int rounds;
    private byte[][] roundKeys = new byte[rounds + 1][];
    private byte[] cipherBytes;
    private int paddingCount;
    private ArrayList<byte[][]> cipherBlocksList;

    private static final int[] invertedSbox = {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
            0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3,
            0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4,
            0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D,
            0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1,
            0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B,
            0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4,
            0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
            0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
            0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4,
            0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA,
            0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF,
            0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD,
            0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47,
            0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E,
            0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79,
            0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4, 0x1F, 0xDD,
            0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27,
            0x80, 0xEC, 0x5F, 0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D,
            0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B,
            0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53,
            0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1,
            0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

    //konstruktor
    public Decryptor(byte[] cipherText, int keySize, byte[][] roundKeys, int paddingCount) {

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
        this.paddingCount = paddingCount;

        textToByteBlocks();

    }

    //zapisuje klucze wykorzystane do szyfrowania w odwrotnej kolejności
    public byte[][] reverseRoundKeys(byte[][] roundKeys) {
        byte[][] temp = new byte[roundKeys.length][];
        for (int position = 0; position < roundKeys.length; position++) {
            for (int i = 0; i < roundKeys.length; i++) {
                for (int j = roundKeys.length - 1; j >= 0; j--) {
                    temp[i] = roundKeys[j];
                }
            }
        }
        return temp;
    }

    //wykonanie operacji xor-owania dla danego bloku i danej rundy
    public void addRoundKey(byte[][] block, int round) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                block[row][col] ^= roundKeys[round][row * 4 + col];
            }
        }
    }

    //podział na dwuwymiarowe bloki
    public void textToByteBlocks() {
        for (int i = 0; i < cipherBytes.length; i += 16) {      //iteracja po blokach szyfrogramu
            byte[][] block = new byte[4][4];
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    block[row][col] = cipherBytes[i + (col * 4) + row];
                }
            }

            cipherBlocksList.add(block);        //dodanie bloku do listy bloków
        }
    }

    //przesunięcie w prawo bajtów w słowie
    public byte[] InvertedRotWord(byte[] word) {
        byte[] rotWord = new byte[4];
        rotWord[0] = word[3];
        for (int i = 1; i < 4; i++) {
            rotWord[i] = word[i-1];
        }
        return rotWord;
    }

    public byte[] InvertedShiftRow(byte[] row, int howMuch) {
        byte[] temp = new byte[4];
        switch (howMuch) {
            case 1:
                temp=InvertedRotWord(row);
                break;
            case 2:
                temp[0] = row[2];
                temp[1] = row[3];
                temp[2] = row[0];
                temp[3] = row[1];
                break;
            case 3:
                temp[0] = row[1];
                temp[1] = row[2];
                temp[2] = row[3];
                temp[3] = row[0];
                break;
        }
        return temp;
    }


    public byte InvertedSubByte(byte input) {
        int index = input & 0xFF;           //mapuje na zakres 0-255
        return (byte) invertedSbox[index];  //podmiana na odpowiednią wartość
    }

    //mnożenie pola Galois (dla mnożenia razy 1, 2 i 3)
    public byte multiplyBy(byte b, int howMuch) {
        switch (howMuch) {
            case 1:
                return b;
            case 2:
                int result = (b & 0xFF) << 1;
                if ((b & 0x100) != 0) {     //jeśli najstarszy bit to 1 (przekroczenie 8 bitów)
                    result ^= 0x1B;         //redukcja przez xor-owanie 0x1B
                }
                return (byte) (result & 0xFF);
            case 3:
                return (byte) (multiplyBy(b, 2) ^ b);
        }
        return 0;
    }

    //mnożenie pola Galois (dla mnożenia razy 9, 11, 13 i 14)
    public byte InvertedMultiplyBy(byte b, int howMuch) {
        switch (howMuch) {
            case 9:
                return (byte) (multiplyBy(multiplyBy(multiplyBy(b, 2), 2), 2) ^ b);
            case 11:
                return (byte) (multiplyBy((byte) (multiplyBy(multiplyBy(b, 2), 2) ^ b), 2) ^ b);
            case 13:
                return (byte) (multiplyBy(multiplyBy((byte) (multiplyBy(b, 2) ^ b), 2), 2) ^ b);
            case 14:
                return (byte) (multiplyBy((byte) (multiplyBy(multiplyBy(b, 2), 2) ^ b), 2));
        }
        return 0;
    }


    public void decrypt() {
        for (int blockCount = 0; blockCount < cipherBlocksList.size(); blockCount++) {      //dla każdego bloku wykonaj rundy
            byte[][] block = cipherBlocksList.get(blockCount);    //zmienna przechowująca bierzący blok, dla którego wykonujemy deszyfrowanie

            //AddRoundKey początkowe
            addRoundKey(block, 0); //zaczynamy deszyfrowanie od ostatniego klucza (odwrotna kolejność)

            for (int round = 1; round <= rounds; round++) {
                byte[][] blockTemp = new byte[4][4];    //zmienna tymczasowa, która przechowuje zmiany na bierzącym bloku
                for (int row = 0; row < 4; row++) {
                    blockTemp[row] = cipherBlocksList.get(blockCount)[row].clone(); //pobieramy kopię bloku, którą będziemy zmieniać
                }

                //INVERTED ShiftRows - rotacja wierszy
                for (int row = 0; row < 4; row++) {
                    byte[] blockRow = new byte[4];
                    for (int col = 0; col < 4; col++) {
                        blockRow[col] = blockTemp[row][col];    //zapisywanie pojedynczego wiersza do zmiennej
                    }
                    if (row != 0) {                              //pierwszy wiersz jest bez zmian
                        byte[] shiftedRow = InvertedShiftRow(blockRow, row);     //przesuwanie
                        for (int col = 0; col < 4; col++) {
                            blockTemp[row][col] = shiftedRow[col];     //zapisywanie zmienionego wiersza do bloku
                        }
                    }
                }

                //INVERTED SubBytes - każdy bajt bloku jest zamieniany na inny z S-boxa
                for (int row = 0; row < 4; row++) {
                    for (int col = 0; col < 4; col++) {
                        blockTemp[row][col] = InvertedSubByte(blockTemp[row][col]);
                    }
                }

                //INVERTED mix columns
                if (round != rounds) {       //operacja nie jest wykonywana dla ostatniej rundy
                    for (int col = 0; col < 4; col++) {
                        byte[] blockCol = new byte[4];
                        for (int row = 0; row < 4; row++) {
                            blockCol[row] = blockTemp[row][col];      //zapisywanie pojedynczej kolumny do zmiennej
                        }
                        byte a0 = (byte) (InvertedMultiplyBy(blockCol[0], 14) ^ InvertedMultiplyBy(blockCol[1], 11) ^ InvertedMultiplyBy(blockCol[2], 13) ^ InvertedMultiplyBy(blockCol[3], 9));
                        byte a1 = (byte) (InvertedMultiplyBy(blockCol[0], 9) ^ InvertedMultiplyBy(blockCol[1], 14) ^ InvertedMultiplyBy(blockCol[2], 11) ^ InvertedMultiplyBy(blockCol[3], 13));
                        byte a2 = (byte) (InvertedMultiplyBy(blockCol[0], 13) ^ InvertedMultiplyBy(blockCol[1], 9) ^ InvertedMultiplyBy(blockCol[2], 14) ^ InvertedMultiplyBy(blockCol[3], 11));
                        byte a3 = (byte) (InvertedMultiplyBy(blockCol[0], 11) ^ InvertedMultiplyBy(blockCol[1], 13) ^ InvertedMultiplyBy(blockCol[2], 9) ^ InvertedMultiplyBy(blockCol[3], 14));

                        blockCol[0] = a0;
                        blockCol[1] = a1;
                        blockCol[2] = a2;
                        blockCol[3] = a3;

                        for (int row = 0; row < 4; row++) {
                            blockTemp[row][col] = blockCol[row];        //zapisywanie zmienionej kolumny do bloku
                        }

                    }
                }

                //AddRoundKey dla bierzącej rundy
                addRoundKey(blockTemp, round);

                byte[][] newBlock = new byte[4][4];     //tworzymy nową tablicę
                for (int row = 0; row < 4; row++) {
                    newBlock[row] = Arrays.copyOf(blockTemp[row], 4);  //kopiujemy zawartość blockTemp, ponieważ nie chcemy dopuścić przekazywanie referencji
                }

                cipherBlocksList.set(blockCount, newBlock);     //dodajemy bezpieczną kopię tablicy
            }
        }

    }

    //usuwanie dodanych zer
    public byte[] removePadding() {

        byte[] blockOneDimensional = new byte[cipherBlocksList.size() * 16];    //tablica jednowymiarowa dla zapisu wszystkich bloków

        int index = 0;                                   //indeks w tablicy jednowymiarowej
        for (byte[][] block : cipherBlocksList) {
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    blockOneDimensional[index++] = block[row][col];
                }
            }
        }

        byte[] blockOneDimensionallNoPadding = new byte[blockOneDimensional.length - paddingCount];     //przepisuje wszystkie wartości oprócz paddingu
        for (int i = 0; i < blockOneDimensionallNoPadding.length; i++) {
            blockOneDimensionallNoPadding[i] = blockOneDimensional[i];
        }

        return blockOneDimensionallNoPadding;
    }

    // wynik w postaci String po usunięciu padding
    public String getDecryptedText() {
        byte[] table = removePadding();
        return new String(table);
    }

}
