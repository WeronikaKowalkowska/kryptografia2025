import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

public class Decryptor {
    private int keySize;
    private int rounds;
    private byte[][] roundKeys = new byte[rounds + 1][];
    private byte[] cipherBytes;
   // private int paddingCount;
    private byte[] mainKey;
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
    public Decryptor(byte[] cipherText, int keySize, byte[] mainKey) {

        this.keySize = keySize;
        this.mainKey = mainKey;
        this.cipherBytes = cipherText;

        if (keySize == 128) {
            rounds = 10;
        }
        if (keySize == 192) {
            rounds = 12;
        }
        if (keySize == 256) {
            rounds = 14;
        }

        this.cipherBlocksList = new ArrayList<>();
        //this.paddingCount = paddingCount;

        keyExpansion();        //generowanie podkluczy dla wszystkich rund
        textToByteBlocks();

        this.roundKeys = reverseRoundKeys(roundKeys);   //podmiana kolejności kluczy
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

//        if (paddingCount == 0) {     //przypadek, gdzy nie ma paddingu
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
