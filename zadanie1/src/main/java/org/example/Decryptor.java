package org.example;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;

public class Decryptor {
    public int keySize;
    public int rounds;
    public byte[][] roundKeys=new byte[rounds+1][];
    public byte[] cipherBytes;
    public ArrayList<byte[][]> cipherBlocksList;
    public Decryptor(String cipherText,int keySize, byte[][] roundKeys) {
        this.keySize=keySize;
        if (keySize == 128) {
            rounds = 10;
        }
        if (keySize == 192) {
            rounds = 12;
        }
        if (keySize == 256) {
            rounds = 14;
        }
        this.roundKeys=roundKeys;
        cipherBytes=cipherText.getBytes(StandardCharsets.UTF_8);
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
        int length = cipherBytes.length;

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
    //NA KONCU PAMIETAC ZEBY USUNAC PADDING PO WSZYSTKICH OPERACJACH CHYBA?
    


}
