/*
    AES Encryption and Decryption application
    Copyright (C) 2025  Weronika Kowalkowska 251561, Nadzeya Silchankava 253184

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.example;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

//https://www.youtube.com/watch?v=MtT3NBfpV5Q
// WAŻNE ->>  https://www.youtube.com/watch?v=0lt7yt-MbpM         !!!!!!!!!!!!!!!!!!!!!!!!

public class Encryptor {

    private int L; //długość klucza, 512<L<=1024 , podzielne przez 64 np. L={640,768,1024}
    private int N; // wartość modulo, dla przykładu 64? 8? - wg prezentacji 160?

    private BigInteger p; //duża liczba pierwsza (L-bitowa), (p-1) mod q = 0
    private BigInteger q; //mniejsza liczba pierwsza dzieląca p-1 (N-bitowa)
    private BigInteger h; // 0<h<p-1

    private BigInteger a; //klucz prywatny używany do tworzenia podpisów; a<q
    private BigInteger b; //klucz publiczy odpowiadający a; b = h^a mod p

    private final byte[] m; //wiadomość (dokument)  do zaszyfrowania
    private List<BigInteger> signature;

    public String getSignature() {
        return signature.toString();
    }

    // podzielone ":"
    public String getClenSignature() {
        return getSignature().replace("[", "").replace("]", "").replace(" ", "").replace(",", ":");
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getQ() {
        return q;
    }

    public BigInteger getH() {
        return h;
    }

    public BigInteger getB() {
        return b;
    }

    //konstrunktor
    public Encryptor(int L, byte[] message) {
        m = message;
        //skrót wiadomości liczony funkcją hashującą SHA 1 lub 2 - w naszym przypadku SHA 1
        BigInteger h2 = hash_message(m);
        generate_params(L);
        generate_signature();
    }

    private void generate_params(int L) {
        if (L > 512 && L <= 1024 && L % 64 == 0) {
            this.L = L;
        }
        N = 160;
        p = BigInteger.probablePrime(this.L, new Random());  //tworzenie losowej liczby pierwszej o długości L
        BigInteger pMinusOne = p.subtract(BigInteger.ONE); // p-1 jak BigInteger
//        BigInteger randomNumber = new BigInteger(N, new Random()); //tworzenie losowej liczby pierwszej o długości N
//        BigInteger remainder = randomNumber.mod(pMinusOne); // q mod (p-1)
//        q = randomNumber.divide(pMinusOne).multiply(pMinusOne); // część całkowita z dzielenia p-1
        do {
            q = BigInteger.probablePrime(N, new Random());
            BigInteger k = new BigInteger(L - N, new Random());
            p = q.multiply(k).add(BigInteger.ONE);
        } while (!p.isProbablePrime(100));
//        if (!remainder.equals(BigInteger.ZERO)) {
//            BigInteger k = new BigInteger(N, new Random()); // losowa liczba, przez którą będziemy mnożyć
//            q = k.multiply(pMinusOne);
//        }
        do {
            h = new BigInteger(N, new Random()); // losowanie h aż będzie mniejsze lub równe p-1
        } while (h.compareTo(BigInteger.ONE) < 0 || h.compareTo(pMinusOne) > 0); // wszystkie liczby w {1, 2, ..., p-1} są w Z*_p, gdy p - liczba pierwsza
        do {
            a = new BigInteger(N, new Random()); // losowanie a aż będzie mniejsze od q
        } while (a.compareTo(q) >= 0);
        b = bigIntegerPow(h, a, p).mod(p);
    }

    //tworzenie pary kluczy
    private void generate_signature() {
        //wartość losowa 0 < r <= q-1
        BigInteger r = null;
        BigInteger rPrim = null;
        boolean flaga = true;
        while (flaga){
            do {
                r = new BigInteger(N, new Random());
            } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q.subtract(BigInteger.ONE)) > 0);
            if (r.gcd(q).equals(BigInteger.ONE)) {
                rPrim = r.modInverse(q);
                flaga = false;
            }
        }
        BigInteger s1 = bigIntegerPow(h, r, p).mod(q);
        BigInteger f = hash_message(m);
        BigInteger s2 = rPrim.multiply(f.add(a.multiply(s1))).mod(q);
        signature = Arrays.asList(s1, s2);
        System.out.println("s2 = " + s2);
        System.out.println("q  = " + q);
    }

    //https://stackoverflow.com/questions/4895523/java-string-to-sha1
    // funkcja do haszowania wiadomości
    private BigInteger hash_message(byte[] bytes) {
        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = crypt.digest(bytes);
            return new BigInteger(1, hashBytes); // "1" oznacza liczbę dodatnią

        } catch (Exception e) {
            throw new RuntimeException("Nieznany algorytm hashujący: SHA-1");
        }
    }

    public static BigInteger bigIntegerPow(BigInteger base, BigInteger exponent, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);  // modulo dla podstawy (zapewnia, że nie będzie za dużej liczby)

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.testBit(0)) { // jeśli wykładnik nieparzysty
                result = result.multiply(base).mod(mod);  // mnożymy przez podstawę i robimy modulo
            }
            base = base.multiply(base).mod(mod);  // podnosimy podstawę do kwadratu i bierzemy modulo
            exponent = exponent.shiftRight(1); // dzielimy wykładnik przez 2
        }
        return result;
    }

}
