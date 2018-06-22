package io.bumo.encryption.crypto;

import java.security.SecureRandom;

import io.bumo.encryption.crypto.entity.KeyStoreEty;
import io.bumo.encryption.crypto.entity.ScryptParamsEty;
import io.bumo.encryption.key.PrivateKey;
import io.bumo.encryption.model.KeyType;
import io.bumo.encryption.utils.aes.AesCtr;
import io.bumo.encryption.utils.hex.HexFormat;
import io.bumo.encryption.utils.scrypt.SCrypt;

public class KeyStore {
	
	public static KeyStoreEty generateKeyStore(String password,String privateKeyStr,int version) throws Exception{
		KeyStoreEty keyStoreEty = new KeyStoreEty();
		int n = 16384;
		int r = 8;
		int p = 1;
		int dkLen = 32;
		byte[] salt = new byte[32];
		SecureRandom randomSalt = new SecureRandom();
		randomSalt.nextBytes(salt);
		
		byte[] aesIv = new byte[16];
		SecureRandom randomIv = new SecureRandom();
		randomIv.nextBytes(aesIv);
		byte[] dk = SCrypt.scrypt(password.getBytes(), salt, n, r, p, dkLen);
		
		String address = "";
		if (privateKeyStr == null || privateKeyStr.isEmpty() || "".equals(privateKeyStr)) {
			PrivateKey privateKey = new PrivateKey(KeyType.ED25519);
			privateKeyStr = privateKey.getEncPrivateKey();
			address = privateKey.getEncAddress();
		}else {
			PrivateKey privateKey = new PrivateKey(privateKeyStr);
			address = privateKey.getEncAddress();
		}
		byte[] cyperText = AesCtr.encrypt(privateKeyStr.getBytes(), dk, aesIv);
		
		keyStoreEty.setAddress(address);
		keyStoreEty.setVersion(version);
		keyStoreEty.setAesctr_iv(HexFormat.byteToHex(aesIv));
		keyStoreEty.setCypher_text(HexFormat.byteToHex(cyperText));
		ScryptParamsEty scryptParams = new ScryptParamsEty();
		scryptParams.setN(n);
		scryptParams.setP(p);
		scryptParams.setR(r);
		scryptParams.setSalt(HexFormat.byteToHex(salt));
		keyStoreEty.setScrypt_params(scryptParams);
		return keyStoreEty;
	}
	
	public static KeyStoreEty generateKeyStore(String password,String privateKeyStr,int n,int r,int p,int version) throws Exception{
		KeyStoreEty keyStoreEty = new KeyStoreEty();
		int dkLen = 32;
		byte[] salt = new byte[32];
		SecureRandom randomSalt = new SecureRandom();
		randomSalt.nextBytes(salt);
		
		byte[] aesIv = new byte[16];
		SecureRandom randomIv = new SecureRandom();
		randomIv.nextBytes(aesIv);
		byte[] dk = SCrypt.scrypt(password.getBytes(), salt, n, r, p, dkLen);
		
		String address = "";
		if (privateKeyStr == null || privateKeyStr.isEmpty() || "".equals(privateKeyStr)) {
			PrivateKey privateKey = new PrivateKey(KeyType.ED25519);
			privateKeyStr = privateKey.getEncPrivateKey();
			address = privateKey.getEncAddress();
		}else {
			PrivateKey privateKey = new PrivateKey(privateKeyStr);
			address = privateKey.getEncAddress();
		}
		byte[] cyperText = AesCtr.encrypt(privateKeyStr.getBytes(), dk, aesIv);
		
		keyStoreEty.setAddress(address);
		keyStoreEty.setVersion(version);
		keyStoreEty.setAesctr_iv(HexFormat.byteToHex(aesIv));
		keyStoreEty.setCypher_text(HexFormat.byteToHex(cyperText));
		ScryptParamsEty scryptParams = new ScryptParamsEty();
		scryptParams.setN(n);
		scryptParams.setP(p);
		scryptParams.setR(r);
		scryptParams.setSalt(HexFormat.byteToHex(salt));
		keyStoreEty.setScrypt_params(scryptParams);
		return keyStoreEty;
	}
	
	public static String decipherKeyStore(String password,KeyStoreEty keyStoreEty) throws Exception{

		ScryptParamsEty scryptParams = keyStoreEty.getScrypt_params();
		int n = scryptParams.getN();
		int r = scryptParams.getR();
		int p = scryptParams.getP();
		byte[] salt = HexFormat.hexToByte(scryptParams.getSalt());
		
		int keyLen = 32;
		byte[] aesIv = HexFormat.hexToByte(keyStoreEty.getAesctr_iv());
		
		
		byte[] cypherText =  HexFormat.hexToByte(keyStoreEty.getCypher_text());
		String address = keyStoreEty.getAddress();
		
		byte[] dk = SCrypt.scrypt(password.getBytes(), salt, n, r, p, keyLen);	
		String encPrivateKey = AesCtr.decrypt(cypherText, dk, aesIv);
	
		PrivateKey privateKey = new PrivateKey(encPrivateKey);
		if (!privateKey.getEncAddress().equals(address)) {
			throw new Exception("the address in the keyStore was wrong, please check");
		}
		return encPrivateKey;
	}
}
