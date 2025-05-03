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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
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

    private static final Random random = new SecureRandom();

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
        generate_params(L);
        generate_signature();
    }

    private void generate_params(int L) {
        if (L > 512 && L <= 1024 && L % 64 == 0) {
            this.L = L;
        }
        N = 160;
        boolean flaga = true;
        while (flaga){
            q = BigInteger.probablePrime(N, random); //tworzenie losowej liczby pierwszej o długości N
            BigInteger k = BigInteger.ONE;
            do {
                k = new BigInteger(L - N, random);
            } while (k.equals(BigInteger.ZERO)); // k nie może być zerem, bo wtedy p = 1, a jedynka nie jest liczbą pierwszą
            this.p = q.multiply(k).add(BigInteger.ONE); // p - 1 = kq -> p = kq + 1
            if (p.isProbablePrime(40)) {
                flaga = false;
            }
        }
        BigInteger pMinusOne = p.subtract(BigInteger.ONE); // p-1 jak BigInteger
        do {
            h = new BigInteger(N, random); // losowanie h aż będzie mniejsze lub równe p-1
        } while (bigIntegerPow(h, (pMinusOne.divide(q)), p).equals(BigInteger.ONE)); // wszystkie liczby w {1, 2, ..., p-1} są w Z*_p, gdy p - liczba pierwsza
        do {
            a = new BigInteger(N, random); // losowanie a aż będzie mniejsze od q
        } while (a.compareTo(q) >= 0); // 0 < a < q
        b = bigIntegerPow(h, a, p);
    }

    //tworzenie pary kluczy
    private void generate_signature() {
        BigInteger r = null;
        BigInteger rPrim = null;
        boolean flaga = true;
        while (flaga){
            do {
                r = new BigInteger(N, random);
            } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0); // 0 < r ≤ q - 1
            if (r.gcd(q).equals(BigInteger.ONE)) {
                rPrim = r.modInverse(q);
                flaga = false;
            }
        }
        BigInteger s1 = bigIntegerPow(h, r, p).mod(q);
        BigInteger f = hash_message(m);
        BigInteger hashMultAs1 = f.add(a.multiply(s1));
        BigInteger s2 = rPrim.multiply(hashMultAs1).mod(q);
        signature = Arrays.asList(s1, s2);
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
