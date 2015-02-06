import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;

import edu.cedarville.cs.crypto.TinyE;
import edu.cedarville.cs.crypto.Tools;

public class Main {

	private static Boolean isEncrypt;
	private static Boolean isHex;
	private static TinyE.Mode mode; 
	private static String inputFile;
	private static String outputFile;
	private static String keyFile;
	private static String ivFile;
	
	public static void main(String[] args) {
		parseArgs(args);
		Integer[] key = readInFile(keyFile, true);
		Integer[] input = readInFile(inputFile, isHex);
		validateLength(key, 4, "key");
		Integer[] iv = null;
		// IV only valid for CBC and CTR modes
		if (!mode.equals(TinyE.Mode.ECB)) {
			iv = readInFile(ivFile, true);
			validateLength(iv, 4, "IV");
		}
		// have all we need, now perform encyption / decryption
		TinyE cipher = new TinyE();
		Integer[] output = null;
		if (isEncrypt) {
			System.out.println("performing encryption");
			output = cipher.encrypt(input, key, mode, iv);
		} else {
			System.out.println("performing decryption");
			output = cipher.decrypt(input, key, mode, iv);
		}
		validateLength(output, input.length, "output");
		// done. now write the results
		writeOutputFile(output, outputFile, isHex);
	}
	
	private static void validateLength(Integer[] ints, int len, String id) {
		if (ints==null) {
			System.out.println(id + " is null");
			System.exit(1);
		} else if (ints.length != len) {
			System.out.println(id + " is wrong length: " + ints.length);
			System.exit(1);
		}
	}
	
	private static void parseArgs(String[] args) {
		try {
			if (args.length >= 6) {
				// handle 1st arg, which is either E(ncrypt) or D(ecrypt)
				if (args[0].equalsIgnoreCase("E")) {
					isEncrypt = true;
				} else if (args[0].equalsIgnoreCase("D")) {
					isEncrypt = false;
				} else { throw new Exception(); }
				// handle 2nd arg, which is either H(ex) or S(tring)
				if (args[1].equalsIgnoreCase("H")) {
					isHex = true;
				} else if (args[1].equalsIgnoreCase("S")) {
					isHex = false;
				} else { throw new Exception(); }
				// handle 3rd arg, which is either ECB, CBC or CTR
				if (args[2].equalsIgnoreCase("ECB")) {
					mode = TinyE.Mode.ECB;
				} else if (args[2].equalsIgnoreCase("CBC")) {
					mode = TinyE.Mode.CBC;
				} else if (args[2].equalsIgnoreCase("CTR")) {
					mode = TinyE.Mode.CTR;
				} else { throw new Exception(); }
				// 4th - 6th are filenames
				inputFile = args[3];
				outputFile = args[4];
				keyFile = args[5];
				// only in CBC and CTR modes do we have to check for IV file name
				if (!mode.equals(TinyE.Mode.ECB)) {
					if (args.length == 7) {
						ivFile = args[6];
					} else {
						throw new Exception();
					}
				}
			}
		} catch (Exception e) {
			System.out.println("Usage: E|D H|S ECB|CBC|CTR inputfile outputfile keyfile [ivfile]");
			System.out.println("-E = encrpypt, -D = decrypy");
			System.out.println("-H = read fileIn as hex values, -S = read fileIn as a string");
			System.out.println("-ECB = Electronic Code Book mode, -CBC = Cipher Block Chaining mode, -CTR = Counter mode");
			System.out.println("inputfile = input file name");
			System.out.println("outputfile = output file name. File will be written out same as read in, either hex or strings");
			System.out.println("keyfile = key file name. Must contain 32 hexadecimal characters");
			System.out.println("ivfile = applies only to CBC and CTR modes. Initialization vector file name. Must contain 32 hexadecimal characters");
			System.exit(1);
		}
	}
	
	private static Integer[] readInFile(String filename, Boolean isHex) {
		File file = openFile(filename);
		String s = "";
		try {
			int len = (int) file.length();
			byte[] fileData = new byte[len];
			DataInputStream in = new DataInputStream(new FileInputStream(filename));
			in.readFully(fileData);
			in.close();
			s = new String(fileData,"UTF8").trim();
		} catch (Exception e) {
			System.out.println("trouble reading file:" + filename);
			e.printStackTrace();
			System.exit(1);
		}
		// for debugging only
		System.out.println("read in from file: " + filename);
		System.out.println(isHex ? "is hex data" : "is string data");
		System.out.println("data read in:");
		System.out.println("|" + s + "|");
		if (isHex) {
			return Tools.convertFromHexStringToInts(s);
		} else {
			return Tools.convertFromStringToInts(s);
		}
	}
	
	private static File openFile(String filename) {
		File file = null;
		try {
			file = new File(filename);
		} catch (Exception e) {
			System.out.println("trouble opening file:" + filename);
			System.exit(1);
		}
		return file;
	}
		
	private static void writeOutputFile(Integer[] ints, String filename, Boolean isHex) {
		String s = "";
		if (isHex) {
			s = Tools.convertFromIntsToHexString(ints);
		} else {
			s = Tools.convertFromIntsToString(ints);
		}
		try {
			// assume s is padded with blank spaces, so can safely trim them now
			s = s.trim();
			// writing files out as UTF-8 so reading them back in will work
			OutputStreamWriter out = new OutputStreamWriter(new FileOutputStream(filename), "UTF8");
			out.write(s);
			out.flush();
			out.close();
			// for debugging only
			System.out.println("writing out to file: " + filename);
			System.out.println(isHex ? "is hex data" : "is string data");
			System.out.println("data written out:");
			System.out.println("|" + s + "|");
		} catch (Exception e) {
			System.out.println("trouble writing file:" + filename);
			e.printStackTrace();
			System.exit(1);
		}
	}
	
}
