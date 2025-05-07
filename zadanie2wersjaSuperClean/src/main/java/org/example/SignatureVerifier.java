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

public class SignatureVerifier {
    private final BigInteger b;
    private BigInteger p;
    private BigInteger q;
    private BigInteger h;
    private BigInteger s1;
    private BigInteger s2;

    private final byte[] m;
    public boolean isSignatureValid;

    public SignatureVerifier(String signature, byte[] message, BigInteger p, BigInteger q, BigInteger h, BigInteger b) {
        this.p = p;
        this.q = q;
        this.h = h;
        this.b = b;
        String[] parts = signature.split(":");
        s1 = new BigInteger(parts[0].trim());
        s2 = new BigInteger(parts[1].trim());
        m = message;
        isSignatureValid = check_signature();
    }

    public boolean check_signature() {
        BigInteger sPrim;
        if (s2.gcd(q).equals(BigInteger.ONE)) {
            sPrim = s2.modInverse(q);
        } else {
            throw new ArithmeticException("s2 and  q are not relatively prime, the modular inverse of them does not exist.");
        }
        BigInteger f = hash_message(m);
        BigInteger u1 = (f.multiply(sPrim)).mod(q);
        BigInteger u2 = (sPrim.multiply(s1)).mod(q);
        BigInteger hu1 = bigIntegerPow(h, u1, p);
        BigInteger bu2 = bigIntegerPow(b, u2, p);
        BigInteger t = ((hu1.multiply(bu2)).mod(p)).mod(q);
        return t.equals(s1);
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

    private static BigInteger bigIntegerPow(BigInteger base, BigInteger exponent, BigInteger mod) {
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
