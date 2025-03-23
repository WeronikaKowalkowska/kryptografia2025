//package org.example;
//
//import javax.crypto.KeyGenerator;
//import javax.crypto.SecretKey;
//import java.nio.charset.StandardCharsets;
//import java.security.NoSuchAlgorithmException;
//import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.List;
//
////NA TEN MOMENT PIERWSZY KLUCZ JEST GENEROWANY RAZEM Z RESZTĄ
//public class Encryptor {
//    public boolean choice; //true- tekst z konoloi (gui) ; false-test z pliku ; default- z konsoli
//    public String plainText;    //tekst jawny podawany przez uzytkownika
//    public byte[] plainBytes;   //takest jawny zamieniony na bajty
//    public byte[][] singleBlock;    //pojedynczy blok tekstu jawnego w bajtach
//    public List<singleBlock> blocks = new ArrayList();   //tekst jawny w bajtach podzielony na bloki
//    public int keySize;
//    public byte[] mainKey;
//    //pierwszy wymiar określa liczbę kluczy rundowych; drugi wymiar to tablica bajtów reprezentujących klucz dla danej rundy
//    public byte[][] keys = new byte[15][];
//    private static final int[] sbox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F,
//            0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82,
//            0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C,
//            0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
//            0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23,
//            0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27,
//            0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52,
//            0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED,
//            0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
//            0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9,
//            0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92,
//            0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
//            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
//            0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
//            0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0,
//            0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62,
//            0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E,
//            0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78,
//            0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B,
//            0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
//            0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
//            0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55,
//            0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41,
//            0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };
//
//    private static final int[] Rcon = {
//            0x00000000,
//            0x01000000,
//            0x02000000,
//            0x04000000,
//            0x08000000,
//            0x10000000,
//            0x20000000,
//            0x40000000,
//            0x80000000,
//            0x1B000000,
//            0x36000000,
//            0x6C000000,
//            0xD8000000,
//            0xAB000000,
//            0x4D000000
//    };
//
//    //konstruktor
//    public Encryptor(String plainText, int keySize) {
//        this.plainText = plainText;
//        this.keySize = keySize;
//        plainBytes = plainText.getBytes(StandardCharsets.UTF_8);
//    }
//
//    //metoda, która dzieli tekst jawny na bloki po 16 bajtów
//    public void textToBytesBlocks() {
//        // sprawdz dlugosc plainTextChars i uzupelnij zerami jesli brakuje
//        if(plainBytes.length%16!=0)
//        {
//            //cos tam
//        }
//        //petla for na wczytanie i dzialanie na blokach -> zrob mape i przypisz charom numer bloku? enum?
//        for (int i = 0; i < plainBytes.length; i += 16) {
//            byte[] block = Arrays.copyOfRange(plainBytes, i, i + 16);
//            blocks.add(block);
//        }
//    }
//
//    //generacja klucza głównego
//    public void mainKeyGenerate() {
//        KeyGenerator gen = null;
//        try {
//            gen = KeyGenerator.getInstance("AES");
//            gen.init(keySize);
//            mainKey = gen.generateKey().getEncoded();
//        } catch (NoSuchAlgorithmException e) {
//            throw new RuntimeException(e);
//        }
//    }
//
//    //przesunięcie w lewo
//    public byte[] RotWord(byte[] word) {
//        byte[] rotWord = new byte[word.length];
//        rotWord[word.length-1] = word[0];
//        for (int i = 0; i < word.length - 1; i++) {
//            rotWord[i] = word[i+1];
//        }
//        return rotWord;
//    }
//
//    public byte SubByte(byte input) {
//        int index = input & 0xFF;
//        return (byte) sbox[index];
//    }
//
//    public byte[] SubWord(byte[] input) {
//        byte[] output = new byte[input.length];
//        for (int i = 0; i < input.length; i++) {
//            output[i] = (byte) SubByte(input[i]);
//        }
//        return output;
//    }
//
//    public byte[] intToByteTable(int input) {
//        byte[] output = new byte[4];
//        output[0] = (byte) (input >>> 24);
//        output[1] = (byte) (input >>> 16);
//        output[2] = (byte) (input >>> 8);
//        output[3] = (byte) (input);
//        return output;
//    }
//
//    //gemeruje pojedynczy klucz dla numeru rundy przedazanego jako parament
//    public byte[] generateKey(int round, byte[][] words) {
//        byte[] temp = new byte[4];
//        byte[] key = new byte[keySize/8];
//        byte[] rcon = intToByteTable(Rcon[round]);
//
//        temp = SubWord(RotWord(words[words.length-1]));
//
//        for (int i = 0; i < 4; i++) {
//            temp[i] ^= rcon[i];
//        }
//
//        //zerowe słowo klucza
//        for (int i = 0 ; i < 4; i++) {
//            key[i] = (byte) (words[0][i] ^ temp[i]);
//        }
//
//        //wskazuje na liczone slowo ("zerowe" jest liczone poza pętlą)
//        int count = 1;
//        //licznik miejsca w kluczu (4 poprzednie już są dodane)
//        int i = 4;
//
//        //pozostałe słowa klucza
//        while (count < words.length) {
//            //dodatkowe SubWord (dla klucza 256)
////            if (count == 4 && keySize == 256) {
////                temp = SubWord(words[count]);
////                for (int j = 0; j < 4; j++) {
////                    key[i + j] = (byte) (key[i + j - 4] ^ temp[j]);
////                }
////            }
//           for (int j = 0; j < 4; j++) {
//               key[i + j] = (byte) (key[i + j - 4] ^ words[count][j]);
//           }
//            count++;
//            i+=4;
//        }
//
//        return key;
//    }
//
//    //generacja podkluczy
//    public void keyExpansion() {
//
//        int rounds = 0;
//        if (keySize == 128) {
//            rounds = 10;
//        }
//        if (keySize == 192) {
//            rounds = 12;
//        }
//        if (keySize == 256) {
//            rounds = 14;
//        }
//
//        //podział klucza głównego na słowa
//        byte[][] words = new byte[keySize/32][4];
//        for (int i = 0; i < keySize/32; i++) {
//            byte[] block = new byte[4];
//            for (int j = 0; j < 4; j ++) {
//                block[j] = mainKey[i*4+j];
//            }
//            words[i] = block;
//        }
//
//        //licznik rund
//        int k = 0;
//
//        //generowanie kluczy
//        while ( k <= rounds) {
//           keys[k] = generateKey(k, words);
//            k++;
//        }
//
//        //DEBUGOWANIE
//        for (int i = 0; i < words.length; i++) {
//            System.out.println(Arrays.toString(words[i]));
//        }
//
//        System.out.println("Podklucze: ");
//
//        for (int i = 0; i < keys.length; i++) {
//            System.out.println(Arrays.toString(keys[i]));
//        }
//
//    }
//
//    //wykonuje operacje dla danego bloku i danej rundy
//    public void addRoundKey(byte[][] block, int round) {
//        //cały blok jest XORowany z  wygenerowanym podkluczem.
//
//        if (block.length != keys.length) {
//            throw new IllegalArgumentException("Block size and key size must match.");
//        }
//
//        for (int i = 0; i < block.length; i++) {
//            block[i] ^= keys[round][i]; // XORowanie bajtów
//        }
//    }
//
//    //wykonaj pierwasza runde i reszte potem
//   /* public void encrypt() {
//        textToBytesBlocks();
//        mainKeyGenerate();
//        keyExpansion();
//        addRoundKey(blocks[0],0);
//        //pierwsza runda
//    }*/
//
//    //3. rundy
//
//        //a. sub bytes - zamiana bajtu z bloku na bajt z sub_box
//
//        //b. shift rows- pierwszy wiersz bloku bez zmian, drugi o jedno miejsce w lewo, trzeci o dwa w lewo a czwarty o trzy w lewo (Rotate left)
//
//        //c. mix columns - przemnarzanie bloku do zaszyfrowania przez dana macierz (wbudowana? kolumna? ) (caly blok przemnozyc przez jakas kolumne?)
//            //mam macierz b z tekstu jawnego i wybieram sobie macierz a ktora mnoze przez patrz wzor wikipeedia i nowy b = operacja macierzy z a
//        //d. add round key - caly blok xor z wygenerowanym podkluczem z key extensions?
//
//    //4. ostatnia runda bez mix columns
//
//
//    //Deszyfrowanie w odwrotnej kolejności
//    //● inne S-Boxy
//    //● MixColumns
//
//
//}
