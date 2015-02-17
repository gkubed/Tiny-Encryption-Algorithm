package edu.cedarville.cs.crypto;

import java.math.BigInteger;

public class Tools {
    
    public static Integer[] convertFromBytesToInts(byte[] bs) {
        int length = (int) Math.ceil(bs.length / 4.0);
        length += length % 2;
        Integer[] ints = new Integer[length];
        int index;
        for (int i = 0; i < ints.length; i++) {
            ints[i] = 0;
            for (int j = 0; j < 4; j++) {
                index = 4 * i + j;
                if (index < bs.length) {
                    ints[i] = (bs[4 * i + j] & 0xFF) + (ints[i] << 8);
                }
                
                else {
                    ints[i] = ints[i] << 8;
                }
            }
        }
        
        return ints;
    }
    
    public static Integer[] convertFromHexStringToInts(String s) {
        int len = (int) Math.ceil(s.length() / 8.0);
        Integer[] ints = new Integer[len];
        for (int i = 0; i < len; i++) {
            String part = s.substring(8 * i, 8 * i + 8);
            ints[i] = (new BigInteger(part, 16)).intValue();
        }
        
        return ints;
    }
    
    public static byte[] convertFromIntsToBytes(Integer[] ints) {
        byte[] bytes = new byte[ints.length * 4];
        
        for (int i = 0; i < ints.length; i++) {
            for (int j = 0; j < 4; j++) {
                bytes[4 * i + j] = (byte) ((ints[i] >> (24 - 8 * j)) & 0xFF);
            }
        }
        
        return bytes;
    }
    
    public static String convertFromIntsToHexString(Integer[] ints) {
        String hex = "";
        for (int i = 0; i < ints.length; i++) {
            String s = Integer.toHexString(ints[i]).toUpperCase();
            while (s.length() < 8) {
                s = "0" + s;
            }
            
            hex += s;
            
        }
        
        return hex;
    }
    
}
