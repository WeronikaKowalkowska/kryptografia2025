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
    //private int g; //element wyliczony z p i g pełniący funckję generataora; g=h^(p-1/q)
    private BigInteger h; // 0<h<p-1

    private BigInteger a; //klucz prywatny używany do tworzenia podpisów; a<q
    private BigInteger b; //klucz publiczy odpowiadający a; b = h^a mod p

    private void generate_params(){
        L = 640;
        N=160;
        p=BigInteger.probablePrime(L,new Random());
        BigInteger pMinusOne = p.subtract(BigInteger.ONE);
        BigInteger randomNumber = new BigInteger(N, new Random());
        BigInteger remainder = randomNumber.mod(pMinusOne);
        q = randomNumber.subtract(remainder);
        if (!remainder.equals(BigInteger.ZERO)) {
            q = q.add(pMinusOne);
        }
        do {
            h = new BigInteger(N, new Random());
        } while (h.compareTo(pMinusOne) > 0);
        do {
            a = new BigInteger(N, new Random());
        } while (a.compareTo(q) >0);
        b=bigIntegerPow(h,a).mod(p);
    }

    // Funkcja podnosząca BigInteger do potęgi BigInteger
    public static BigInteger bigIntegerPow(BigInteger base, BigInteger exponent) {
        BigInteger result = BigInteger.ONE;
        while (exponent.compareTo(BigInteger.ZERO) > 0) {
            if (exponent.testBit(0)) { // jeśli exponent nieparzysty
                result = result.multiply(base);
            }
            base = base.multiply(base); // podnosimy podstawę do kwadratu
            exponent = exponent.shiftRight(1); // dzielimy wykładnik przez 2
        }
        return result;
    }

    private String M; //wiadomość (dokument)  do zaszyfrowania
    private BigInteger r; //wartość losowa ; 0<r<=q-1
    private BigInteger rPrim;
    private BigInteger s1;
    private BigInteger s2;
    private List<BigInteger> signature;

    //tworzenie pary kluczy
    private void generate_signature(){
        do{
            r = new BigInteger(N, new Random());
        } while(r.compareTo(q.subtract(BigInteger.ONE)) <= 0);
        rPrim = (r.pow(-1)).mod(q);
        s1=(bigIntegerPow(h,r).mod(p)).mod(q);
        BigInteger f=hash_message(M);
        s2=rPrim.multiply(f.add(a.multiply(s1))).mod(q);
        signature = Arrays.asList(s1,s2);
    }

    //private String m; //wiadomość (dokument)  do zaszyfrowania
    private String h2; //skrót wiadomości liczony funkcją hashującą SHA 1 lub 2 - w naszym przypadku SHA 1

    private int k; //losowa, tajna i unikalna wartosć z przedziału (0,q)

    //private int r; // r = [(g^k) mod p] mod q

    private int s; // s=[k^-1 (h+xr) ] mod q  ;  k^-1 - odwrotonośc k mod q ; jeśli s==0 trzeba wybrać nowe k

    //signature -> (r, s)

    private int keyLength;


    //konstrunktor
    public Encryptor(int private_key, String message) {
//        x=private_key;
//        m=message;
//        h2=hash_message(m);

    }

    //funkcja służąca generacji losowej wartosci z zakresu
//    private int rand_value(int min, int max){
//
//    }

    //H - funkcja hashująca
    //https://stackoverflow.com/questions/4895523/java-string-to-sha1
    private static BigInteger hash_message(String password)
    {
        //BigInteger sha1 = "";
        try
        {
            MessageDigest crypt = MessageDigest.getInstance("SHA-1");
            //crypt.reset();
            //crypt.update(password.getBytes("UTF-8"));
            byte[] hashBytes = crypt.digest(password.getBytes("UTF-8"));
            //sha1 = bytesToHex(crypt.digest());
            // Konwertujemy wynikowe bajty na BigInteger
            return new BigInteger(1, hashBytes); // "1" oznacza liczbę dodatnią

        }
        catch (Exception e)
        {
            throw new RuntimeException("Nieznany algorytm hashujący: SHA-1");
        }
        //return sha1;
    }

//    public static String bytesToHex(byte[] bytes) {
//        StringBuilder sb = new StringBuilder();
//        for (byte b : bytes) {
//            sb.append(String.format("%02X", b));
//        }
//        return sb.toString();
//    }

}
