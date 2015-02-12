package edu.cedarville.cs.crypto;

public class Tools {
    
    public static Integer[] convertFromBytesToInts(byte[] bs) {
        Integer[] ints = new Integer[bs.length / 4];
        
        for (int i = 0; i < ints.length; i++) {
            ints[i] = 0;
            for (int j = 0; j < 4; j++) {
                ints[i] = ints[i] << 8;
                ints[i] += bs[4 * i + j] & 0xFF;
            }
        }
        
        return ints;
    }
    
    public static Integer[] convertFromHexStringToInts(String s) {
        int len = s.length() / 8;
        Integer[] ints = new Integer[len];
        
        for (int i = 0; i < len; i++) {
            String part = s.substring(8 * i, 8 * i + 8);
            ints[i] = Integer.parseUnsignedInt(part, 16);            
        }
        
        return ints;
    }
    
    public static byte[] convertFromIntsToBytes(Integer[] ints) {
        byte[] bytes = new byte[ints.length * 4];
        
        for (int i = 0; i < ints.length; i++) {
            for (int j = 3; j >= 0; j--) {
                bytes[4 * i + j] = (byte) (ints[i] & 0xFF);
                ints[i] = ints[i] >> 8;
            }
        }
        
        return bytes;
    }
    
    public static String convertFromIntsToHexString(Integer[] ints) {
        String hex = "";
        
        for (int i = 0; i < ints.length; i++) {
            hex += Integer.toHexString(ints[i]).toUpperCase();
        }
        
        return hex;
    }
    
}
