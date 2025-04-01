package org.example;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;

public class AESCipher {
    // Parametry AES-128
    private static final int Nb = 4;  // liczba kolumn stanu (zawsze 4)
    private static final int Nk = 4;  // liczba słów klucza (AES-128: 4)
    private static final int Nr = 10; // liczba rund (AES-128: 10)

    // Tablica S-box (substytucja bajtów)
    private static final int[] sbox = {
            0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
            0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
            0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
            0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
            0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
            0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
            0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
            0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
            0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
            0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
            0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
            0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
            0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
            0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
            0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
            0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    // Odwrotny S-box
    private static final int[] invSbox = {
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
    };

    // Wartości Rcon używane przy rozbudowie klucza
    private static final int[] Rcon = {
            0x00, // nie używana
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
    };

    // Mnożenie w ciele GF(2^8) – podstawowa operacja w MixColumns
    private static int multiply(int a, int b) {
        int result = 0;
        while (b > 0) {
            if ((b & 1) != 0) {
                result ^= a;
            }
            a <<= 1;
            if ((a & 0x100) != 0) {
                a ^= 0x11B; // x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
        }
        return result;
    }

    // Dodawanie klucza rundy (operacja XOR)
    private static void addRoundKey(byte[] state, byte[] roundKey) {
        for (int i = 0; i < 16; i++) {
            state[i] ^= roundKey[i];
        }
    }

    // Podstawienie bajtów (SubBytes) przy pomocy S-boxa
    private static void subBytes(byte[] state) {
        for (int i = 0; i < 16; i++) {
            state[i] = (byte) (sbox[state[i] & 0xFF]);
        }
    }

    // Odwrotność SubBytes przy użyciu odwrotnego S-boxa
    private static void invSubBytes(byte[] state) {
        for (int i = 0; i < 16; i++) {
            state[i] = (byte) (invSbox[state[i] & 0xFF]);
        }
    }

    // Przesunięcie wierszy (ShiftRows)
    private static void shiftRows(byte[] state) {
        byte[] temp = new byte[16];
        System.arraycopy(state, 0, temp, 0, 16);

        // Wiersz 0 - bez zmian

        // Wiersz 1 - przesunięcie o 1 w lewo
        state[1]  = temp[5];
        state[5]  = temp[9];
        state[9]  = temp[13];
        state[13] = temp[1];

        // Wiersz 2 - przesunięcie o 2
        state[2]  = temp[10];
        state[6]  = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];

        // Wiersz 3 - przesunięcie o 3
        state[3]  = temp[15];
        state[7]  = temp[3];
        state[11] = temp[7];
        state[15] = temp[11];
    }

    // Odwrotność ShiftRows – przesunięcie wierszy w prawo
    private static void invShiftRows(byte[] state) {
        byte[] temp = new byte[16];
        System.arraycopy(state, 0, temp, 0, 16);

        // Wiersz 0 - bez zmian

        // Wiersz 1 - przesunięcie o 1 w prawo
        state[1]  = temp[13];
        state[5]  = temp[1];
        state[9]  = temp[5];
        state[13] = temp[9];

        // Wiersz 2 - przesunięcie o 2
        state[2]  = temp[10];
        state[6]  = temp[14];
        state[10] = temp[2];
        state[14] = temp[6];

        // Wiersz 3 - przesunięcie o 3 w prawo
        state[3]  = temp[7];
        state[7]  = temp[11];
        state[11] = temp[15];
        state[15] = temp[3];
    }

    // MixColumns – mieszanie kolumn stanu
    private static void mixColumns(byte[] state) {
        for (int c = 0; c < 4; c++) {
            int index = c * 4;
            int s0 = state[index] & 0xFF;
            int s1 = state[index + 1] & 0xFF;
            int s2 = state[index + 2] & 0xFF;
            int s3 = state[index + 3] & 0xFF;

            int r0 = multiply(0x02, s0) ^ multiply(0x03, s1) ^ s2 ^ s3;
            int r1 = s0 ^ multiply(0x02, s1) ^ multiply(0x03, s2) ^ s3;
            int r2 = s0 ^ s1 ^ multiply(0x02, s2) ^ multiply(0x03, s3);
            int r3 = multiply(0x03, s0) ^ s1 ^ s2 ^ multiply(0x02, s3);

            state[index]     = (byte) (r0 & 0xFF);
            state[index + 1] = (byte) (r1 & 0xFF);
            state[index + 2] = (byte) (r2 & 0xFF);
            state[index + 3] = (byte) (r3 & 0xFF);
        }
    }

    // Odwrotność MixColumns
    private static void invMixColumns(byte[] state) {
        for (int c = 0; c < 4; c++) {
            int index = c * 4;
            int s0 = state[index] & 0xFF;
            int s1 = state[index + 1] & 0xFF;
            int s2 = state[index + 2] & 0xFF;
            int s3 = state[index + 3] & 0xFF;

            int r0 = multiply(0x0e, s0) ^ multiply(0x0b, s1) ^ multiply(0x0d, s2) ^ multiply(0x09, s3);
            int r1 = multiply(0x09, s0) ^ multiply(0x0e, s1) ^ multiply(0x0b, s2) ^ multiply(0x0d, s3);
            int r2 = multiply(0x0d, s0) ^ multiply(0x09, s1) ^ multiply(0x0e, s2) ^ multiply(0x0b, s3);
            int r3 = multiply(0x0b, s0) ^ multiply(0x0d, s1) ^ multiply(0x09, s2) ^ multiply(0x0e, s3);

            state[index]     = (byte) (r0 & 0xFF);
            state[index + 1] = (byte) (r1 & 0xFF);
            state[index + 2] = (byte) (r2 & 0xFF);
            state[index + 3] = (byte) (r3 & 0xFF);
        }
    }

    // Rozbudowa klucza (Key Expansion)
    private static byte[] keyExpansion(byte[] key) {
        byte[] expandedKey = new byte[Nb * (Nr + 1) * 4]; // dla AES-128: 16*(10+1)=176 bajtów
        System.arraycopy(key, 0, expandedKey, 0, Nk * 4);

        int bytesGenerated = Nk * 4;
        int rconIteration = 1;
        byte[] temp = new byte[4];

        while (bytesGenerated < expandedKey.length) {
            for (int i = 0; i < 4; i++) {
                temp[i] = expandedKey[bytesGenerated - 4 + i];
            }
            if (bytesGenerated % (Nk * 4) == 0) {
                // RotWord: przesunięcie bajtów w temp o 1 w lewo
                byte t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;
                // SubWord: zastąpienie każdego bajtu przy użyciu S-boxa
                for (int i = 0; i < 4; i++) {
                    temp[i] = (byte) (sbox[temp[i] & 0xFF]);
                }
                // XOR pierwszego bajtu z wartością Rcon
                temp[0] = (byte) ((temp[0] & 0xFF) ^ Rcon[rconIteration]);
                rconIteration++;
            }
            for (int i = 0; i < 4; i++) {
                expandedKey[bytesGenerated] = (byte) (expandedKey[bytesGenerated - Nk * 4] ^ temp[i]);
                bytesGenerated++;
            }
        }
        return expandedKey;
    }

    // Szyfrowanie bloku 16-bajtowego (AES-128)
    public static byte[] encryptBlock(byte[] input, byte[] key) {
        if (input.length != 16) {
            throw new IllegalArgumentException("Blok wejściowy musi mieć 16 bajtów.");
        }
        byte[] state = new byte[16];
        System.arraycopy(input, 0, state, 0, 16);

        byte[] expandedKey = keyExpansion(key);

        // Początkowe dodanie klucza
        addRoundKey(state, Arrays.copyOfRange(expandedKey, 0, 16));

        // 9 rund głównych
        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, Arrays.copyOfRange(expandedKey, round * 16, (round + 1) * 16));
        }

        // Ostatnia runda – bez MixColumns
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Arrays.copyOfRange(expandedKey, Nr * 16, (Nr + 1) * 16));

        return state;
    }

    // Deszyfrowanie bloku 16-bajtowego (AES-128)
    public static byte[] decryptBlock(byte[] input, byte[] key) {
        if (input.length != 16) {
            throw new IllegalArgumentException("Blok wejściowy musi mieć 16 bajtów.");
        }
        byte[] state = new byte[16];
        System.arraycopy(input, 0, state, 0, 16);

        byte[] expandedKey = keyExpansion(key);

        // Początkowe dodanie ostatniego klucza rundy
        addRoundKey(state, Arrays.copyOfRange(expandedKey, Nr * 16, (Nr + 1) * 16));

        // 9 rund deszyfrowania
        for (int round = Nr - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, Arrays.copyOfRange(expandedKey, round * 16, (round + 1) * 16));
            invMixColumns(state);
        }

        // Ostatnia runda
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, Arrays.copyOfRange(expandedKey, 0, 16));

        return state;
    }

    // ----------------------------
    // NOWE METODY – obsługa paddingu oraz szyfrowanie/deszyfrowanie dłuższych komunikatów
    // ----------------------------

    // Dodanie paddingu PKCS#7
    public static byte[] pad(byte[] input) {
        int padLength = 16 - (input.length % 16);
        if (padLength == 0) {
            padLength = 16;
        }
        byte[] padded = new byte[input.length + padLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) padLength;
        }
        return padded;
    }

    // Usunięcie paddingu
    public static byte[] unpad(byte[] input) {
        int padLength = input[input.length - 1] & 0xFF;
        byte[] unpadded = new byte[input.length - padLength];
        System.arraycopy(input, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }

    // Szyfrowanie całego komunikatu (o dowolnej długości)
    public static byte[] encrypt(byte[] input, byte[] key) {
        byte[] padded = pad(input);
        byte[] cipher = new byte[padded.length];
        for (int i = 0; i < padded.length; i += 16) {
            byte[] block = Arrays.copyOfRange(padded, i, i + 16);
            byte[] encryptedBlock = encryptBlock(block, key);
            System.arraycopy(encryptedBlock, 0, cipher, i, 16);
        }
        return cipher;
    }

    // Deszyfrowanie całego komunikatu
    public static byte[] decrypt(byte[] input, byte[] key) {
        if (input.length % 16 != 0) {
            throw new IllegalArgumentException("Szyfrogram nie ma prawidłowej długości.");
        }
        byte[] decrypted = new byte[input.length];
        for (int i = 0; i < input.length; i += 16) {
            byte[] block = Arrays.copyOfRange(input, i, i + 16);
            byte[] decryptedBlock = decryptBlock(block, key);
            System.arraycopy(decryptedBlock, 0, decrypted, i, 16);
        }
        return unpad(decrypted);
    }

    // Metoda pomocnicza – konwersja tablicy bajtów na ciąg szesnastkowy
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // ----------------------------
    // GŁÓWNA METODA
    // ----------------------------
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Wczytanie tekstu jawnego z klawiatury
        System.out.print("Podaj tekst jawny: ");
        //String inputText = scanner.nextLine();
        //byte[] plaintext = inputText.getBytes(StandardCharsets.UTF_8);
        String inputText="hejka";
        byte[] plaintext = inputText.getBytes(StandardCharsets.UTF_8);

        // Główny klucz AES-128 (16 bajtów)
        byte[] key = new byte[] {
                (byte)0x2B, (byte)0x7E, (byte)0x15, (byte)0x16,
                (byte)0x28, (byte)0xAE, (byte)0xD2, (byte)0xA6,
                (byte)0xAB, (byte)0xF7, (byte)0x15, (byte)0x88,
                (byte)0x09, (byte)0xCF, (byte)0x4F, (byte)0x3C
        };

        // Wyświetlenie klucza głównego
        System.out.println("Klucz główny: " + bytesToHex(key));

        // Szyfrowanie
        byte[] ciphertext = encrypt(plaintext, key);
        System.out.println("Szyfrogram:  " + bytesToHex(ciphertext));

        System.out.println("Podklucze: ");
        System.out.println(bytesToHex(keyExpansion(key)));

        // Deszyfrowanie
        byte[] decrypted = decrypt(ciphertext, key);
        String decryptedText = new String(decrypted, StandardCharsets.UTF_8);
        System.out.println("Odszyfrowany tekst: " + decryptedText);

        scanner.close();
    }
}
