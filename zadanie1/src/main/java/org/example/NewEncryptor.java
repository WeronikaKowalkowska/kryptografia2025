package org.example;

import javax.crypto.KeyGenerator;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;

public class NewEncryptor {
    public byte[] plainBytes;   //takest jawny zamieniony na bajty
    public int keySize;     //długość klucza
    public int rounds;      //ilość rund do wykonania na pojedynczym bloku tekstu
    public byte[] mainKey;  //klucz glowny
    public ArrayList<byte[][]> blocksList;     //lista tablic bajtów tekstu jawnego podszielonego na 16bajtowe bloki
    //pierwszy wymiar określa liczbę kluczy rundowych; drugi wymiar to tablica bajtów reprezentujących klucz dla danej rundy
    public byte[][] roundKeys = new byte[rounds+1][];       //lista kluczy dla każdej rundy na blokach
    private static final int[] sbox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
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
            0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };
    private static final int[] Rcon = {
            //CZY SKRÓCIĆ??
            0x00000000,
            0x01000000,
            0x02000000,
            0x04000000,
            0x08000000,
            0x10000000,
            0x20000000,
            0x40000000,
            0x80000000,
            0x1B000000,
            0x36000000,
            0x6C000000,
            0xD8000000,
            0xAB000000,
            0x4D000000
    };
    //konstruktor
    public NewEncryptor(String plainText, int keySize) {

        this.keySize = keySize;
        plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
        //przypisanie klasie ilości rund do wykonania w zależności od dłufości klucza
        if (keySize == 128) {
            rounds = 10;
        }
        if (keySize == 192) {
            rounds = 12;
        }
        if (keySize == 256) {
            rounds = 14;
        }
        mainKeyGenerate();      //generacja klucza głównego
        //keyExpansion - kazdy blok używa tych samych kluczy rund
        keyExpansion();
    }
    //generacja klucza głównego
    public void mainKeyGenerate() {
        KeyGenerator gen = null;
        try {
            gen = KeyGenerator.getInstance("AES");
            gen.init(keySize);
            mainKey = gen.generateKey().getEncoded();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
    public void keyExpansion() {
        //podział klucza głównego na słowa
        int howManyWordsInKey=keySize/32;
        byte[][] mainKeyWords = new byte[howManyWordsInKey][];    //[ile słów dla danej dlugosci klucza (w1-w4)][4 bajty reprezentujace pojedyncze slowo] - nr slowa/to slowo
        for (int i = 0; i < howManyWordsInKey; i++) {
            //iteruje po numerze słowa
            byte[] word = new byte[4]; //tworzy pojedyncze slowo
            for (int j = 0; j < 4; j ++) {
                //iteruje po bajtach w słowie
                word[j] = mainKey[i*4+j]; //zapisuje bajty z klucza do słowa
            }
            mainKeyWords[i] = word; //zapisuje wyciete slowo z klucza
        }
        for(int i=0;i<rounds;i++) {
            roundKeys[i] = generateKey(i, mainKeyWords);
        }
    }
    //gemeruje pojedynczy klucz dla numeru rundy przedazanego jako parament
    public byte[] generateKey(int round, byte[][] mainKeyWords) {
        byte[] temp = new byte[4]; //wyrazenie dla dla slowa pierwszego słowa w podlluczu
        byte[] key = new byte[keySize/8];   //zwracany podklucz, rozmiar=(keysize/8)=liczba bajtów
        byte[] rcon = intToByteTable(Rcon[round]);

        temp = SubWord(RotWord(mainKeyWords[mainKeyWords.length-1]));

        for (int i = 0; i < 4; i++) {
            temp[i] ^= rcon[i]; //xorowanie sub words z rcon
        }

        //pierwsze słowo klucza
        //xorowanie pierwszego slowa z klucza glownego z wyliczonym wyrazeniem
        for (int i = 0 ; i < 4; i++) {
            key[i] = (byte) (mainKeyWords[0][i] ^ temp[i]);
        }

        //licznik miejsca w kluczu (4 poprzednie już są dodane)
        int positionInMainKey = 4;

        for (int i=1;i<mainKeyWords.length;i++)
        {
            //iteruje po słowach
            for (int j = 0; j < 4; j++) {
                key[positionInMainKey + j] = (byte) (key[positionInMainKey + j - 4] ^ mainKeyWords[i][j]);  //xorowanie pozostalych slow
            }
            positionInMainKey+=4;
        }

        return key;
    }

    //zamień int na tablicę bajtów
    public byte[] intToByteTable(int input) {
        byte[] output = new byte[4];
        output[0] = (byte) (input >>> 24);
        output[1] = (byte) (input >>> 16);
        output[2] = (byte) (input >>> 8);
        output[3] = (byte) (input);
        return output;
    }

    //przesunięcie w lewo bajtow w slowie
    public byte[] RotWord(byte[] word) {
        byte[] rotWord = new byte[4];
        rotWord[3] = word[0];
        for (int i = 0; i < 3; i++) {
            rotWord[i] = word[i+1]; //zmien kolejnosc
        }
        return rotWord;
    }

    public byte[] ShiftRow(byte[] row, int howMuch) {
        byte[] temp = new byte[4];
        switch (howMuch) {
            case 1:
                temp=RotWord(row);
                break;
            case 2:
                temp[0]=row[2];
                temp[1]=row[3];
                temp[2]=row[0];
                temp[3]=row[1];
                break;
            case 3:
                temp[0]=row[3];
                temp[1]=row[0];
                temp[2]=row[1];
                temp[3]=row[2];
                break;
        }
        return temp;
    }

    public byte SubByte(byte input) {
        int index = input & 0xFF;   //mapuje na zakres 0-255
        return (byte) sbox[index];  //podmien na odpowiedni bajt
    }

    //zamienia slowo na wartosci z subbox
    public byte[] SubWord(byte[] input) {
        byte[] output = new byte[4]; //nowe slowo z wartosciami z sub boxa. ma 4 bajty
        for (int i = 0; i < 4; i++) {
            output[i] = (byte) SubByte(input[i]); //zamieniam kazdy bajt
        }
        return output;
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
        int length = plainBytes.length;

        //sprawdzenie i uzupełnienie zerami jeśli tekst nie jest wielokrotnościa 16 bajtów
        if (length % 16 != 0) {
            int padding = 16 - (length % 16);
            byte[] paddedBytes = Arrays.copyOf(plainBytes, length + padding);
            plainBytes = paddedBytes;
        }

        //podzial tekstu na bloki
        for (int i = 0; i < plainBytes.length; i += 16) {
            byte[][] block = new byte[4][4];

            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    block[row][col] = plainBytes[i + (col * 4) + row];
                }
            }

            blocksList.add(block);
        }
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
                return (byte) result;
            case 3:
                return (byte) (multiplyBy(b, 2) ^ b);

        }
        return 0;
    }

    //wykonanie pierwszego addround key i zapetlenie
    public void encrypt(){
        //pierwsza runda - add round key i xor bloku z pierwszym podkluczem
        addRoundKey(blocksList.get(0),0);
        //pozostałe rundy
        for(int round=1;round<=rounds;round++){
            byte[][] block = blocksList.get(round);
            for(int row=0;row<4;row++){
                for(int col=0;col<4;col++){
                    block[row][col]=SubByte(block[row][col]);   //sub bytes
                }
            }

            for(int row=0;row<4;row++){
                byte[] blockRow=new byte[4];
                for(int col=0;col<4;col++){
                    blockRow[col]=block[row][col];
                }
                if(row!=0){
                    blockRow=ShiftRow(blockRow,row);
                    for(int col=0;col<4;col++){
                        block[row][col]=blockRow[col];  //shift rows
                    }
                }
            }

            //mix columns
            if(round!=rounds){
                for(int col=0;col<4;col++){
                    byte[] blockCol=new byte[4];
                    for(int row=0;row<4;row++){
                        blockCol[row]=block[row][col];
                    }
                    byte b0 = (byte) (multiplyBy(blockCol[0], 2) ^ multiplyBy(blockCol[1], 3) ^ multiplyBy(blockCol[2], 1) ^ multiplyBy(blockCol[3], 1));
                    byte b1 = (byte) (multiplyBy(blockCol[0], 1) ^ multiplyBy(blockCol[1], 2) ^ multiplyBy(blockCol[2], 3) ^ multiplyBy(blockCol[3], 1));
                    byte b2 = (byte) (multiplyBy(blockCol[0], 1) ^ multiplyBy(blockCol[1], 1) ^ multiplyBy(blockCol[2], 2) ^ multiplyBy(blockCol[3], 3));
                    byte b3 = (byte) (multiplyBy(blockCol[0], 3) ^ multiplyBy(blockCol[1], 1) ^ multiplyBy(blockCol[2], 1) ^ multiplyBy(blockCol[3], 2));

                    blockCol[0]=b0;
                    blockCol[1]=b1;
                    blockCol[2]=b2;
                    blockCol[3]=b3;

                    for(int row=0;row<4;row++){
                        block[row][col]=blockCol[row];
                    }

                }
            }

            blocksList.set(round,block);//podmiana bloku na danepo operacjach

            //add round key na koniec
            addRoundKey(blocksList.get(round),round);
            
        }


    }

    public byte[][] getRoundKeys() {
        return roundKeys;
    }

    public ArrayList<byte[][]> getBlocksList() {
        return blocksList;
    }
}
