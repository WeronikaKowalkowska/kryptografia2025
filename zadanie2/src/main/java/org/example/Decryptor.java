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

public class Decryptor {
    private final BigInteger b; //klucz publiczy odpowiadający a; b = h^a mod p
    private BigInteger p; //duża liczba pierwsza (L-bitowa), (p-1) mod q = 0
    private BigInteger q; //mniejsza liczba pierwsza dzieląca p-1 (N-bitowa)
    private BigInteger h; // 0<h<p-1
    private BigInteger s1;
    private BigInteger s2;

    private final byte[] m; //wiadomość (dokument) do zaszyfrowania

    public Decryptor(String signature, byte[] message, BigInteger p, BigInteger q, BigInteger h, BigInteger b) {
        this.p = p;
        this.q = q;
        this.h = h;
        this.b = b;
        String[] parts = signature.split(":");
        s1 = new BigInteger(parts[0].trim());
        s2 = new BigInteger(parts[1].trim());
        m = message;
        System.out.println("s2 = " + s2);
        System.out.println("q  = " + q);
        check_signature();
    }

    public boolean check_signature() {
        BigInteger sPrim;
        if (s2.gcd(q).equals(BigInteger.ONE)) {
            sPrim = s2.modInverse(q);
            System.out.println("gcd(s2, q) = " + s2.gcd(q));
        } else {
            System.out.println("gcd(s2, q) = " + s2.gcd(q));
            throw new ArithmeticException("s2 i q nie są względnie pierwsze, brak odwrotności.");
        }
        BigInteger u1 = hash_message(m).multiply(sPrim).mod(q);
        BigInteger u2 = sPrim.multiply(s1).mod(q);
        BigInteger t = bigIntegerPow(h, u1, p).multiply(bigIntegerPow(b, u2, p)).mod(p).mod(q);
        return t.equals(s1);
    }

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

    private static BigInteger bigIntegerPow(BigInteger base, BigInteger exponent, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);  // Modulo dla podstawy (zapewnia, że nie będzie za dużej liczby)

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.testBit(0)) { // Jeśli wykładnik nieparzysty
                result = result.multiply(base).mod(mod);  // Mnożymy przez podstawę i robimy modulo
            }
            base = base.multiply(base).mod(mod);  // Podnosimy podstawę do kwadratu i bierzemy modulo
            exponent = exponent.shiftRight(1); // Dzielimy wykładnik przez 2
        }
        return result;
    }

}
