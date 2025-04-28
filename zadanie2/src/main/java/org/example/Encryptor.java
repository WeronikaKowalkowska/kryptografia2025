package org.example;

// import BigInteger

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

//https://www.youtube.com/watch?v=MtT3NBfpV5Q   // to sie nie zgadza troche z prezentacjami al eod kiedy mamy oczekiwania co do prezentacji wykladowych??
//niby pisane wg prezentacji wiec duze XD


// WAŻNE ->>  https://www.youtube.com/watch?v=0lt7yt-MbpM         !!!!!!!!!!!!!!!!!!!!!!!!

public class Encryptor {
    //Key Generation
    private int L; //długość klucza, 512<L<=1024 , podzielne przez 64 np. L={640,768,1024}
    //dodać choose key length
    private int N; // wartość modulo, dla przykładu 64? 8? - wg prezentacji 160?

    private BigInteger p; //duża liczba pierwsza (L-bitowa), (p-1) mod q = 0
    private BigInteger q; //mniejsza liczba pierwsza dzieląca p-1 (N-bitowa)
    private BigInteger h; // 0<h<p-1

    private BigInteger a; //klucz prywatny używany do tworzenia podpisów; a<q
    private BigInteger b; //klucz publiczy odpowiadający a; b = h^a mod p

    private BigInteger r; //wartość losowa ; 0<r<=q-1
    private BigInteger rPrim;
    private BigInteger s1;
    private BigInteger s2;
    private String m; //wiadomość (dokument)  do zaszyfrowania
    private BigInteger h2; //skrót wiadomości liczony funkcją hashującą SHA 1 lub 2 - w naszym przypadku SHA 1
    private List<BigInteger> signature;

    public String getSignature(){
        System.out.println(signature.toString());
        return signature.toString();
    }

    public BigInteger getP(){
        return p;
    }

    public BigInteger getQ(){
        return q;
    }

    public BigInteger getH(){
        return h;
    }

    public BigInteger getB(){
        return b;
    }

    //konstrunktor
    public Encryptor(int L, String message) {
        System.out.println("Jestem w konstruktorze");
        m=message;
        h2=hash_message(m);
        generate_params(L);
        generate_signature();
        System.out.println(bytesToHex(signature));
    }


    private void generate_params(int L) {
        System.out.println("Jestem w generate_params");
        if (L > 512 && L <= 1024 && L%64 == 0) {
            this.L = L; //640
        }
        N = 160;
        p = BigInteger.probablePrime(this.L, new Random());  //tworzenie losowej liczby pierwszej o długości L
        BigInteger pMinusOne = p.subtract(BigInteger.ONE); // p-1 jak BigInteger
        BigInteger randomNumber = new BigInteger(N, new Random()); //tworzenie losowej liczby pierwszej o długości N
        BigInteger remainder = randomNumber.mod(pMinusOne); // q mod (p-1)
        //q = randomNumber.subtract(remainder);  //chyba błąd
        q = randomNumber.divide(pMinusOne).multiply(pMinusOne); // część całkowita z dzielenia p-1
        if (!remainder.equals(BigInteger.ZERO)) {
            //q = q.add(pMinusOne);   //dlaczego tak ??????
            BigInteger k = new BigInteger(N, new Random()); // losowa liczba, przez którą będziemy mnożyć
            q = k.multiply(pMinusOne);
        }
        do {
            h = new BigInteger(N, new Random()); // losowanie h aż będzie mniejsze lub równe p-1
        } while (h.compareTo(BigInteger.ONE) < 0 || h.compareTo(pMinusOne) > 0); // wszystkie liczby w {1, 2, ..., p-1} są w Z*_p, gdy p - liczba pierwsza
        do {
            a = new BigInteger(N, new Random()); // losowanie a aż będzie mniejsze od q
        } while (a.compareTo(q) >= 0);
        b = bigIntegerPow(h, a, p).mod(p);
    }

    // funkcja podnosząca BigInteger do potęgi BigInteger
//    public static BigInteger bigIntegerPow(BigInteger base, BigInteger exponent) {
//        System.out.println("Jestem w bigIntegerPow");
//        BigInteger result = BigInteger.ONE;
//        while (exponent.compareTo(BigInteger.ZERO) > 0) { // jeśli najmłodszy bit jest ustawiony na 0, to liczba jest nieparzysta
//            if (exponent.testBit(0)) { // jeśli exponent nieparzysty
//                result = result.multiply(base);
//            }
//            base = base.multiply(base); // podnosimy podstawę do kwadratu
//            exponent = exponent.shiftRight(1); // dzielimy wykładnik przez 2
//        }
//        return result;
//    }

    //tworzenie pary kluczy
    private void generate_signature() {
        System.out.println("Jestem w generate_signature");
        do {
            r = new BigInteger(N, new Random());
        } while (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(q.subtract(BigInteger.ONE)) > 0);
        //rPrim = (r.pow(-1)).mod(q); - nie można użyć pow - będzie przekroczenie zakresu
        if (r.gcd(q).equals(BigInteger.ONE)) {
            rPrim = r.modInverse(q);
        } else {
            throw new ArithmeticException("r i q nie są względnie pierwsze, brak odwrotności");
        }
        //s1 = (bigIntegerPow(h, r).mod(p)).mod(q);
        s1 = bigIntegerPow(h, r, p).mod(q);
        BigInteger f = hash_message(m);
        s2 = rPrim.multiply(f.add(a.multiply(s1))).mod(q);
        signature = Arrays.asList(s1, s2);
    }


    //https://stackoverflow.com/questions/4895523/java-string-to-sha1
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

    public static String bytesToHex(List<BigInteger> bytes) {
        StringBuilder sb = new StringBuilder();
        for (BigInteger b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

}
