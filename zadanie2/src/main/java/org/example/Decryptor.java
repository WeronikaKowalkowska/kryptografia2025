package org.example;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.List;

public class Decryptor {
    private BigInteger b; //klucz publiczy odpowiadający a; b = h^a mod p
    private BigInteger p; //duża liczba pierwsza (L-bitowa), (p-1) mod q = 0
    private BigInteger q; //mniejsza liczba pierwsza dzieląca p-1 (N-bitowa)
    private BigInteger h; // 0<h<p-1
    private BigInteger s1;
    private BigInteger s2;

    private String m; //wiadomość (dokument)  do zaszyfrowania

    public Decryptor(String signature, String message, BigInteger p, BigInteger q, BigInteger h, BigInteger b) {
        this.p = p;
        this.q = q;
        this.h = h;
        this.b = b;
        signature = signature.replace("[", "").replace("]", "");
        String[] parts = signature.split(",");
        s1 = new BigInteger(parts[0].trim());
        s2 = new BigInteger(parts[1].trim());
        m = message;
        check_signature();
    }

    private void check_signature() {
        BigInteger sPrim;
        if (s2.gcd(q).equals(BigInteger.ONE)) {
            sPrim = s2.modInverse(q);
        } else {
            throw new ArithmeticException("s2 i q nie są względnie pierwsze, brak odwrotności.");
        }
        BigInteger u1 = hash_message(m).multiply(sPrim).mod(q);
        BigInteger u2 = sPrim.multiply(s1).mod(q);
        BigInteger t = bigIntegerPow(h, u1, p).multiply(bigIntegerPow(b, u2, p)).mod(p).mod(q);
        if (t.equals(s1)) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature not verified");
        }
    }

    // funkcja do haszowania wiadomości
    private BigInteger hash_message(String text) {
        System.out.println("Jestem w hash_message");
        try {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            byte[] hashBytes = crypt.digest(text.getBytes("UTF-8"));
            return new BigInteger(1, hashBytes); // "1" oznacza liczbę dodatnią

        } catch (Exception e) {
            throw new RuntimeException("Nieznany algorytm hashujący: SHA-1");
        }
    }

    public static BigInteger bigIntegerPow(BigInteger base, BigInteger exponent, BigInteger mod) {
        System.out.println("Jestem w bigIntegerPow");
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
