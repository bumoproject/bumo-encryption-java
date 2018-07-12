package io.bumo.encryption.utils.hash;

public class HashUtil {
	/**
	 * generate hex string of hash
	 * @param src
	 * @return hex string of hash
	 */
	public static String GenerateHashHex(byte[] src) {
		Sha256 sha256 = new Sha256(src);
		byte[] hash = sha256.finish();
		return io.bumo.encryption.utils.hex.HexFormat.byteToHex(hash).toLowerCase();
	}
}
