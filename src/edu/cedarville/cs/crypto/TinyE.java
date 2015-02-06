package edu.cedarville.cs.crypto;

public class TinyE {
	
	public static enum Mode { ECB, CBC, CTR };
		
	public Integer[] encrypt(Integer[] plaintext, Integer[] key, Mode mode, Integer[] iv) {
		int len = plaintext.length;
		Integer[] ciphertext = new Integer[len];
		// do some stuff here
		return ciphertext;
	}
	
	public Integer[] decrypt(Integer[] ciphertext, Integer[] key, Mode mode, Integer[] iv) {
		int len = ciphertext.length;
		Integer[] plaintext = new Integer[len];
		// do some stuff here
		return plaintext;
	}
	
}
