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
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

public class SignatureGenerator {

    private int L;
    private int N;

    private BigInteger p;
    private BigInteger q;
    private BigInteger h;

    private BigInteger a;
    private BigInteger b;

    private final byte[] m;
    private List<BigInteger> signature;

    private static final Random random = new SecureRandom();

    public String getSignature() {
        return signature.toString();
    }

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

    public SignatureGenerator(int L, byte[] message) {
        if (L > 512 && L <= 1024 && L % 64 == 0) {
            this.L = L;
        }
        m = message;
        generate_params();
        generate_signature();
    }

    private void generate_params() {
        N = 160;
        boolean flaga = true;
        while (flaga) {
            q = BigInteger.probablePrime(N, random);

            BigInteger k;
            do {
                k = new BigInteger(L - q.bitLength(), random);
            } while (k.equals(BigInteger.ZERO));

            p = q.multiply(k).add(BigInteger.ONE);
            if (p.isProbablePrime(64)) {
                flaga = false;
            }
        }
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        do {
            h = new BigInteger(p.bitLength(), random);
        } while (h.compareTo(BigInteger.ONE) <= 0 || h.compareTo(p) >= 0 || bigIntegerPow(h, (pMinusOne.divide(q)), p).equals(BigInteger.ONE));
        h = bigIntegerPow(h, p.subtract(BigInteger.ONE).divide(q), p);
        do {
            a = new BigInteger(N, random);
        } while (a.compareTo(q) >= 0);
        b = bigIntegerPow(h, a, p);
    }

    private void generate_signature() {
        BigInteger r = null;
        BigInteger rPrim = null;
        boolean flaga = true;
        while (flaga) {
            do {
                r = new BigInteger(N, random);
            } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q) >= 0);
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

    private BigInteger hash_message(byte[] bytes) {
        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = crypt.digest(bytes);
            return new BigInteger(1, hashBytes);

        } catch (Exception e) {
            throw new RuntimeException("Unknown algorithm: SHA-1");
        }
    }

    public static BigInteger bigIntegerPow(BigInteger base, BigInteger exponent, BigInteger mod) {
        BigInteger result = BigInteger.ONE;
        base = base.mod(mod);

        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.testBit(0)) {
                result = result.multiply(base).mod(mod);
            }
            base = base.multiply(base).mod(mod);
            exponent = exponent.shiftRight(1);
        }
        return result;
    }

}
