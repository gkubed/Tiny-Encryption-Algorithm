package edu.cedarville.cs.crypto;

public class TinyE {
    public static enum Mode {ECB, CBC, CTR};
    private final String DELTA = "9E3779B9";
    
    /** ECB **/
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
    
    /** CBC **/
    private Integer[] encryptCBC(Integer[] plaintext, Integer[] key, int delta, Integer[] iv) {
        // XOR IV and plaintext[0], [1]
        byte[] plaintextBytes = Tools.convertFromIntsToBytes(plaintext);
        byte[] ivBytes        = Tools.convertFromIntsToBytes(iv);
        plaintextBytes[0] = (byte) (plaintextBytes[0] ^ ivBytes[0]);
        plaintextBytes[1] = (byte) (plaintextBytes[1] ^ ivBytes[1]);
        plaintext = Tools.convertFromBytesToInts(plaintextBytes);
        
        Integer[] cipher = new Integer[plaintext.length];
        
        for (int p = 0; p < plaintext.length; p += 2) {
            if (p != 0) {
                plaintextBytes[p] = (byte) (plaintextBytes[p] ^ cipher[p-2]);
                plaintextBytes[p+1] = (byte) (plaintextBytes[p+1] ^ cipher[p-1]);
                plaintext = Tools.convertFromBytesToInts(plaintextBytes);
            }
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
    
    private Integer[] decryptCBC(Integer[] ciphertext, Integer[] key, int delta, Integer[] iv) {
        Integer[] plain = new Integer[ciphertext.length];
        
        for (int p = 0; p < ciphertext.length; p += 2) {
            Integer cipher0 = ciphertext[p];
            Integer cipher1 = ciphertext[p+1];
            int sum = delta << 5;
            
            plain[p] = ciphertext[p];
            plain[p + 1] = ciphertext[p + 1];
            
            for (int i = 0; i < 32; i++) {
                plain[p + 1] = plain[p + 1] - (((plain[p] << 4) + key[2]) ^ (plain[p] + sum) ^ ((plain[p] >> 5) + key[3]));
                plain[p] = plain[p] - (((plain[p + 1] << 4) + key[0]) ^ (plain[p + 1] + sum) ^ ((plain[p + 1] >> 5) + key[1]));
                sum -= delta;
            }
            
            if (p == 0) {
                // XOR IV with plainBytes[0], [1]
                byte[] plainBytes = Tools.convertFromIntsToBytes(plain);
                byte[] ivBytes    = Tools.convertFromIntsToBytes(iv);
                plainBytes[0] = (byte) (plainBytes[0] ^ ivBytes[0]);
                plainBytes[1] = (byte) (plainBytes[1] ^ ivBytes[1]);
                plain = Tools.convertFromBytesToInts(plainBytes);
            } else {
                // XOR IV with ciphertext[0], [1]
                byte[] plainBytes = Tools.convertFromIntsToBytes(plain);
                byte[] ivBytes    = Tools.convertFromIntsToBytes(iv);
                plainBytes[0] = (byte) (plainBytes[0] ^ cipher0);
                plainBytes[1] = (byte) (plainBytes[1] ^ cipher1);
                plain = Tools.convertFromBytesToInts(plainBytes);
            }
        }        
        return plain;
    }
    
    /** CTR **/
    private Integer[] encryptCTR(Integer[] plaintext, Integer[] key, int delta, Integer[] iv) {
        Integer[] cipher = new Integer[plaintext.length];
        
        for (int p = 0; p < plaintext.length; p += 2) {
            // Ci = Pi XOR E(iv + i, K)
            // E(iv + i, K)
            int sum = 0;
            cipher[p] = iv[p];
            cipher[p + 1] = iv[p+1];
            for (int i = 0; i < 32; i++) {
                sum += delta;
                
                cipher[p] = cipher[p] + (((cipher[p + 1] << 4) + key[0]) ^ (cipher[p + 1] + sum) ^ ((cipher[p + 1] >> 5) + key[1]));
                cipher[p + 1] = cipher[p + 1] + (((cipher[p] << 4) + key[2]) ^ (cipher[p] + sum) ^ ((cipher[p] >> 5) + key[3]));
            }
            
            // Increment counter
            long longIV = (((long) iv[0] << 32) & 0xffffffff00000000l) | ((long)(iv[1] & 0x00000000ffffffffl));
            longIV++;
            
            // Truncate long back into two ints
            iv[0] = (int)(longIV >> 32);
            iv[1] = (int)(longIV);
                
            // XOR Plaintext with Ciphertext (Pi XOR E(iv + i, K))
            byte[] plainBytes  = Tools.convertFromIntsToBytes(plaintext);
            byte[] cipherBytes = Tools.convertFromIntsToBytes(cipher);
            cipherBytes[p]   = (byte) (plainBytes[p] ^ cipherBytes[p]);
            cipherBytes[p+1] = (byte) (plainBytes[p+1] ^ cipherBytes[p+1]);
            cipher = Tools.convertFromBytesToInts(cipherBytes);
            System.out.println(cipher[p]);
            System.out.println(cipher[p+1]);
        }
        return cipher;
    }
    
    public Integer[] encrypt(Integer[] plaintext, Integer[] key, Mode mode, Integer[] iv) {
        int delta = Tools.convertFromHexStringToInts(DELTA)[0];
        if (mode == Mode.ECB) {
            return encryptECB(plaintext, key, delta);
        } else if (mode == Mode.CBC) {
            return encryptCBC(plaintext, key, delta, iv);
        } else if (mode == Mode.CTR) {
            return encryptCTR(plaintext, key, delta, iv);
        }
        return null;
    }
    
    public Integer[] decrypt(Integer[] ciphertext, Integer[] key, Mode mode, Integer[] iv) {
        int delta = Tools.convertFromHexStringToInts(DELTA)[0];
        if (mode == Mode.ECB) {
            return decryptECB(ciphertext, key, delta);
        } else if (mode == Mode.CBC) {
            return decryptCBC(ciphertext, key, delta, iv);
        } else if (mode == Mode.CTR) {
            return encryptCTR(ciphertext, key, delta, iv);
        }
        return null;
    }
}
