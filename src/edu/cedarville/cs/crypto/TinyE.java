package edu.cedarville.cs.crypto;

public class TinyE {
    
    public static enum Mode { ECB, CBC, CTR };
    private final String DELTA = "9E3779B9";
    
    public Integer[] encrypt(Integer[] plaintext, Integer[] key, Mode mode, Integer[] iv) {
        return null;
    }
    
    public Integer[] decrypt(Integer[] ciphertext, Integer[] key, Mode mode, Integer[] iv) {
        return null;
    }
    
}
