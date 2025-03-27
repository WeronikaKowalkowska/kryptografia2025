package org.example;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class Decryptor {
    private int keySize;
    private int rounds;
    private byte[][] roundKeys=new byte[rounds+1][];
    private byte[] cipherBytes;
    private int paddingCount;
    private ArrayList<byte[][]> cipherBlocksList;
    private static final int[] invertedSbox = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5,
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
            0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D };

    public Decryptor(byte[] cipherText, int keySize, byte[][] roundKeys, int paddingCount) {

        this.keySize=keySize;
        cipherBytes= cipherText;

        if (keySize == 128) {
            rounds = 10;
        }
        if (keySize == 192) {
            rounds = 12;
        }
        if (keySize == 256) {
            rounds = 14;
        }

        this.roundKeys=reverseRoundKeys(roundKeys);
        this.cipherBlocksList = new ArrayList<>();
        this.paddingCount = paddingCount;

        textToByteBlocks();

    }

    //zapisuje kluczy wykorzystane do szyfrowania w odwrotnej kolejności
    public byte[][] reverseRoundKeys(byte[][] roundKeys){
        byte[][] temp=new byte[roundKeys.length][];
        for(int position=0;position<roundKeys.length;position++){
            for(int i=0;i<roundKeys.length;i++){
                for(int j=roundKeys.length-1;j>=0;j--){
                    temp[i]=roundKeys[j];
                }
            }
        }
        return temp;
    }

    //wykonuje operacje dla danego bloku i danej rundy
    public void addRoundKey(byte[][] block, int round) {
        //cały blok jest XORowany z  wygenerowanym podkluczem.
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                block[row][col] ^= roundKeys[round][row * 4 + col];
            }
        }
    }

    //podział na dwuwymiarowe bloki
    public void textToByteBlocks(){
        //podzial tekstu na bloki
        for (int i = 0; i < cipherBytes.length; i += 16) {
            byte[][] block = new byte[4][4];

            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    block[row][col] = cipherBytes[i + (col * 4) + row];
                }
            }

            cipherBlocksList.add(block);
        }
    }

    //przesunięcie w prawo bajtow w slowie
    public byte[] InvertedRotWord(byte[] word) {
        byte[] rotWord = new byte[4];
        rotWord[0] = word[3];
        for (int i = 1; i < 4; i++) {
            rotWord[i] = word[i-1]; //zmien kolejnosc
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
                temp[0]=row[2];
                temp[1]=row[3];
                temp[2]=row[0];
                temp[3]=row[1];
                break;
            case 3:
                temp[0]=row[1];
                temp[1]=row[2];
                temp[2]=row[3];
                temp[3]=row[0];
                break;
        }
        return temp;
    }

//    public byte InvertedMultiplyBy(byte b,int howMuch){
//        switch (howMuch) {
//            case 2:
//                int[] values = {0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
//                                0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c,0x1e,
//                                0x20, 0x22, 0x24, 0x26, 0x28, 0x2a, 0x2c, 0x2e,
//                                0x30, 0x32, 0x34, 0x36, 0x38, 0x3a, 0x3c,0x3e,
//                                0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
//                                0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c,0x5e,
//                                0x60, 0x62, 0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e,
//                                0x70, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c,0x7e,
//                                0x80, 0x82, 0x84, 0x86, 0x88, 0x8a, 0x8c, 0x8e,
//                                0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c,0x9e,
//                                0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae,
//                                0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc,0xbe,
//                                0xc0, 0xc2, 0xc4, 0xc6, 0xc8, 0xca, 0xcc, 0xce,
//                                0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda, 0xdc,0xde,
//                                0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
//                                0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc,0xfe,
//                                0x1b, 0x19, 0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15,
//                                0x0b, 0x09, 0x0f, 0x0d, 0x03, 0x01, 0x07,0x05,
//                                0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31, 0x37, 0x35,
//                                0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27,0x25,
//                                0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55,
//                                0x4b, 0x94, 0x4f, 0x4d, 0x43, 0x41, 0x47,0x45,
//                                0x7b, 0x79, 0x7f, 0x7d, 0x73, 0x71, 0x77, 0x75,
//                                0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61, 0x67,0x65,
//                                0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
//                                0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87,0x85,
//                                0xbb, 0xb9, 0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5,
//                                0xab, 0xa9, 0xaf, 0xad, 0xa3, 0xa1, 0xa7,0xa5,
//                                0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1, 0xd7, 0xd5,
//                                0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7,0xc5,
//                                0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5,
//                                0xeb, 0xe9, 0xef, 0xed, 0xe3, 0xe1, 0xe7,0xe5,
//                };
//                break;
//            case 9:
//                break;
//            case 11:
//                break;
//            case 13:
//                break;
//            case 14:
//                break;
//        }
//        return 0;
//    }

    public byte InvertedSubByte(byte input) {
        int index = input & 0xFF;   //mapuje na zakres 0-255
        return (byte) invertedSbox[index];  //podmien na odpowiedni bajt
    }

    public byte multiplyBy(byte b, int howMuch) {
        switch (howMuch) {
            case 1:
                return b;
            case 2:
                int result = (b & 0xFF) << 1;
                if ((b & 0x80) != 0) {  //jeśli MSB było 1 (przekroczenie 8 bitów)
                    result ^= 0x1B;  //redukcja modulo 0x1B
                }
                return (byte) (result & 0xFF);
            case 3:
                return (byte) (multiplyBy(b, 2) ^ b);

        }
        return 0;
    }

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


    public void decrypt(){
        for (int blockCount = 0; blockCount < cipherBlocksList.size(); blockCount++) {  //dla każdego bloku wykonaj rundy
            byte[][] block = cipherBlocksList.get(blockCount);    //zmienna przechowująca bierzący blok, dla którego wykonujemy deszyfrowanie
            addRoundKey(block,0); //zaczynamy deszyfrowanie od ostatniego klucza (odwrotna kolejność)
            for(int round=1;round<=rounds;round++){
                byte[][] blockTemp = cipherBlocksList.get(blockCount); //zmienna tymczasowa, która przechowuje zmiany na bierzącym bloku
                for(int row=0;row<4;row++){
                    byte[] blockRow=new byte[4];
                    for(int col=0;col<4;col++){
                        blockRow[col]=blockTemp[row][col];
                    }
                    if(row!=0){
                        byte[] shiftedRow=InvertedShiftRow(blockRow,row);
                        for(int col=0;col<4;col++){
                            blockTemp[row][col]=shiftedRow[col];  // INVERTED shift rows
                        }
                    }
                }
                for(int row=0;row<4;row++){
                    for(int col=0;col<4;col++){
                        blockTemp[row][col]=InvertedSubByte(blockTemp[row][col]);   // INVERTED sub bytes
                    }
                }

                //INVERTED mix columns
                if(round!=rounds){
                    for(int col=0;col<4;col++){
                        byte[] blockCol=new byte[4];
                        for(int row=0;row<4;row++){
                            blockCol[row]=blockTemp[row][col];
                        }
                        byte a0 = (byte) (InvertedMultiplyBy(blockCol[0], 14) ^ InvertedMultiplyBy(blockCol[1], 11) ^ InvertedMultiplyBy(blockCol[2], 13) ^ InvertedMultiplyBy(blockCol[3], 9));
                        byte a1 = (byte) (InvertedMultiplyBy(blockCol[0], 9) ^ InvertedMultiplyBy(blockCol[1], 14) ^ InvertedMultiplyBy(blockCol[2], 11) ^ InvertedMultiplyBy(blockCol[3], 13));
                        byte a2 = (byte) (InvertedMultiplyBy(blockCol[0], 13) ^ InvertedMultiplyBy(blockCol[1], 9) ^ InvertedMultiplyBy(blockCol[2], 14) ^ InvertedMultiplyBy(blockCol[3], 11));
                        byte a3 = (byte) (InvertedMultiplyBy(blockCol[0], 11) ^ InvertedMultiplyBy(blockCol[1], 13) ^ InvertedMultiplyBy(blockCol[2], 9) ^ InvertedMultiplyBy(blockCol[3], 14));

                        blockCol[0]=a0;
                        blockCol[1]=a1;
                        blockCol[2]=a2;
                        blockCol[3]=a3;

                        for(int row=0;row<4;row++){
                            blockTemp[row][col]=blockCol[row];
                        }

                    }
                }

                addRoundKey(blockTemp, round);    //add round key na koniec
                cipherBlocksList.set(blockCount,blockTemp); //podmiana bloku na zmieniony po operacjach
            }
        }

    }

    public byte[] removePadding() {

        byte[] blockOneDimensional = new byte[cipherBlocksList.size()*16]; //bloki jako tablica jednowymiarowa
           for(int blockCount = 0; blockCount < cipherBlocksList.size(); blockCount++) {
               byte[][] block = cipherBlocksList.get(blockCount);
               for (int col = 0; col < 4; col++) {
                   for (int row = 0; row < 4; row++) {
                       blockOneDimensional[(blockCount * 16  + col * 4) + row]= block[row][col];
                   }
               }
           }

        byte[] blockOneDimensionallNoPadding = new byte[blockOneDimensional.length-paddingCount]; //przepisuje wszystkie oprócz padding
            for (int i=0; i<blockOneDimensionallNoPadding.length; i++){
                blockOneDimensionallNoPadding[i] = blockOneDimensional[i];
            }

        return blockOneDimensionallNoPadding;
    }


    // wynik po usunięciu padding
    public String getDecryptedText() {
        byte[] table = removePadding();
        return new String(table);
    }

    public byte[] getDecryptedBytes(){
        return removePadding();
    }


}
