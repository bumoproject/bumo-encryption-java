package io.bumo.encryption.utils.hash;

public class HashUtil {
	/**
	 * generate hex string of hash
	 * @param src
	 * @param type 0(SHA256) or 1(SM3)
	 * @return hex string of hash
	 * @throws Exception 
	 */
	public static String GenerateHashHex(byte[] src) throws Exception {
		Sha256 sha256 = new Sha256(src);
		byte[] hash = sha256.finish();
		return io.bumo.encryption.utils.hex.HexFormat.byteToHex(hash).toLowerCase();
	}
}
