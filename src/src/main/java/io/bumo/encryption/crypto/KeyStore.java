package io.bumo.encryption.crypto;

import java.security.SecureRandom;

import com.alibaba.fastjson.JSONObject;

import io.bumo.encryption.key.PrivateKey;
import io.bumo.encryption.model.KeyType;
import io.bumo.encryption.utils.aes.AesCtr;
import io.bumo.encryption.utils.hex.HexFormat;
import io.bumo.encryption.utils.scrypt.SCrypt;

public class KeyStore {
	/**
	 * @param encPrivateKey this is the encode private key to be stored
	 * @param password
	 * @param n CPU cost parameter, if n is null, the default value is 16384
	 * @param r Memory cost parameter, if r is null, the default value is 8
	 * @param p Parallelization parameter, if p is null, the default value is 1
	 * @return keyStore this is the store of encode private key, cannot be null
	 * @return encPrivateKey if encPrivateKey was null, return a new one, otherwise return itself
	 * @throws Exception
	 */
	public static String generateKeyStore(String encPrivateKey, String password, Integer n, Integer r, Integer p, JSONObject keyStore) throws Exception {
		if (keyStore == null) {
			throw new Exception("keyStore can not be null");
		}
		int N = (n == null ? 16384 : n.intValue());
		int R = (r == null ? 8 : r.intValue());
		int P = (p == null ? 1 : p.intValue());
		int dkLen = 32;

		byte[] salt = new byte[32];
		SecureRandom randomSalt = new SecureRandom();
		randomSalt.nextBytes(salt);

		byte[] aesIv = new byte[16];
		SecureRandom randomIv = new SecureRandom();
		randomIv.nextBytes(aesIv);

		byte[] dk = SCrypt.scrypt(password.getBytes(), salt, N, R, P, dkLen);

		String address = "";
		if (encPrivateKey == null || encPrivateKey.isEmpty()) {
			PrivateKey privateKey = new PrivateKey(KeyType.ED25519);
			encPrivateKey = privateKey.getEncPrivateKey();
			address = privateKey.getEncAddress();
		}
		else {
			PrivateKey privateKey = new PrivateKey(encPrivateKey);
			address = privateKey.getEncAddress();
		}
		byte[] cyperText = AesCtr.encrypt(encPrivateKey.getBytes(), dk, aesIv);

		keyStore.put("version", 2);
		JSONObject scryptParams = new JSONObject();
		scryptParams.put("n", N);
		scryptParams.put("r", R);
		scryptParams.put("p", P);
		scryptParams.put("salt", HexFormat.byteToHex(salt));
		keyStore.put("scrypt_params", scryptParams);
		keyStore.put("aesctr_iv", HexFormat.byteToHex(aesIv));
		keyStore.put("cypher_text", HexFormat.byteToHex(cyperText));
		keyStore.put("address", address);

		return encPrivateKey;
	}

	/**
	 * @param encPrivateKey this is the encode private key to be stored
	 * @param password
	 * @return keyStore this is the store of encode private key, cannot be null
	 * @return encPrivateKey if encPrivateKey was null, return a new one, otherwise return itself
	 * @throws Exception
	 */
	public static String generateKeyStore(String encPrivateKey, String password, JSONObject keyStore) throws Exception {
		return generateKeyStore(encPrivateKey, password, null, null, null, keyStore);
	}
	
	/**
	 * @param keyStore the store of encode private key to be decrypted
	 * @param password the password of the keyStore 
	 * @return encPrivateKey the encode private key 
	 * @throws Exception 
	 */
	public static String from(JSONObject keyStore, String password) throws Exception {
		String encPrivateKey = null;
		if (!keyStore.containsKey("version")) {
			throw new Exception("keyStore must contain version key");
		}
		if (!keyStore.containsKey("scrypt_params")) {
			throw new Exception("keyStore must contain scrypt_params key");
		}
		int version = keyStore.getIntValue("version");
		JSONObject scryptParams = keyStore.getJSONObject("scrypt_params");
		if (!scryptParams.containsKey("n") || !scryptParams.containsKey("r") ||
				!scryptParams.containsKey("p") || !scryptParams.containsKey("salt")
				) {
			throw new Exception("the scrypt_params of keyStore must contain n, r, p, salt key");
		}
		int n = scryptParams.getIntValue("n");
		int r = scryptParams.getIntValue("r");
		int p = scryptParams.getIntValue("p");
		byte[] salt = HexFormat.hexToByte(scryptParams.getString("salt"));
		
		int keyLen = 16;
		byte[] aesIv = null;
		if (version == 1) {
			if (!keyStore.containsKey("aes128ctr_iv")) {
				throw new Exception("when version was 1, keyStore must contain scrypt_params aes128ctr_iv key");
			}
			aesIv = HexFormat.hexToByte(keyStore.getString("aes128ctr_iv"));
			keyLen = 16;
		}
		else if (version == 2) {
			if (!keyStore.containsKey("aesctr_iv")) {
				throw new Exception("when version was 2, keyStore must contain scrypt_params aesctr_iv key");
			}
			aesIv = HexFormat.hexToByte(keyStore.getString("aesctr_iv"));
			keyLen = 32;
		}
		if (aesIv.length != 16) {
			throw new Exception("the length of the byte array that aesctr_iv was converted from 16 hexadecimal to must equals 16");
		}
		
		if (!keyStore.containsKey("cypher_text")) {
			throw new Exception("keyStore must contain cypher_text key");
		}
		if (!keyStore.containsKey("address")) {
			throw new Exception("keyStore must contain address key");
		}
		byte[] cypherText =  HexFormat.hexToByte(keyStore.getString("cypher_text"));
		String address = keyStore.getString("address");
		
		byte[] dk = SCrypt.scrypt(password.getBytes(), salt, n, r, p, keyLen);
		
		encPrivateKey = AesCtr.decrypt(cypherText, dk, aesIv);
		if (encPrivateKey == null) {
			throw new Exception("parsing from the keyStore failed, please check password and keyStore");
		}
		
		PrivateKey privateKey = new PrivateKey(encPrivateKey);
		if (!privateKey.getEncAddress().equals(address)) {
			throw new Exception("the address in the keyStore was wrong, please check");
		}
		
		return encPrivateKey;
	}
}
