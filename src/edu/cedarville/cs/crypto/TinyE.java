package edu.cedarville.cs.crypto;

public class TinyE {
    
    public static enum Mode { ECB, CBC, CTR };
    private final String DELTA = "9E3779B9";
    
    private Integer[] encryptECB(Integer[] plaintext, Integer[] key, int delta) {
        Integer[] cipher = new Integer[plaintext.length];
        
        for (int p = 0; p < plaintext.length; p += 2) {
            int sum = 0;
            cipher[p] = plaintext[p];
            cipher[p + 1] = plaintext[p + 1];
            for (int i = 0; i < 32; i++) {
                sum += delta;
            
                cipher[p] = cipher[p] + (((cipher[p + 1] << 4) + key[0]) ^ (cipher[p + 1] + sum) ^ ((cipher[p + 1] >> 5) + key[1]));
                cipher[p + 1] = cipher[p + 1] + (((cipher[p] << 4) + key[2]) ^ (cipher[p] + sum) ^ ((cipher[p] >> 5) + key[3]));
            }
        }
        
        return cipher;
    }
    
    private Integer[] decryptECB(Integer[] ciphertext, Integer[] key, int delta) {
        Integer[] plain = new Integer[ciphertext.length];
        
        for (int p = 0; p < ciphertext.length; p += 2) {
            int sum = delta << 5;
            
            plain[p] = ciphertext[p];
            plain[p + 1] = ciphertext[p + 1];
            
            for (int i = 0; i < 32; i++) {
                plain[p + 1] = plain[p + 1] - (((plain[p] << 4) + key[2]) ^ (plain[p] + sum) ^ ((plain[p] >> 5) + key[3]));
                plain[p] = plain[p] - (((plain[p + 1] << 4) + key[0]) ^ (plain[p + 1] + sum) ^ ((plain[p + 1] >> 5) + key[1]));
                sum -= delta;
            }
        }
        
        return plain;
    }
    
    public Integer[] encrypt(Integer[] plaintext, Integer[] key, Mode mode, Integer[] iv) {
        int delta = Tools.convertFromHexStringToInts(DELTA)[0];
        if (mode == Mode.ECB) {
            return encryptECB(plaintext, key, delta);
        }
        
        return null;
    }
    
    public Integer[] decrypt(Integer[] ciphertext, Integer[] key, Mode mode, Integer[] iv) {
        int delta = Tools.convertFromHexStringToInts(DELTA)[0];
        if (mode == Mode.ECB) {
            return decryptECB(ciphertext, key, delta);
        }
        
        return null;
    }
    
}
