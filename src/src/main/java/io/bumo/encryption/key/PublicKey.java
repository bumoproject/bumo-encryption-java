package io.bumo.encryption.key;

import java.security.MessageDigest;
import java.security.Signature;

import io.bumo.encryption.common.CheckKey;
import io.bumo.encryption.model.KeyMember;
import io.bumo.encryption.model.KeyType;
import io.bumo.encryption.utils.base.Base58;
import io.bumo.encryption.utils.hex.HexFormat;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class PublicKey {
	private KeyMember keyMember = new KeyMember();
	
	PublicKey() {
	}
	
	/**
	 * structure with encrytion public key
	 */
	PublicKey(String encPublicKey) throws Exception {
		getPublicKey(encPublicKey, keyMember);
	}
	
	/**
	 * set enc public key
	 * @param encPublicKey encryption public key
	 * @throws Exception
	 */
	public void setEncPublicKey(String encPublicKey) throws Exception {
		getPublicKey(encPublicKey, keyMember);
	}
	
	/**
	 * set raw public key
	 * @param rawPKey raw public key
	 */
	public void setRawPublicKey(byte[] rawPKey) {
		keyMember.setRawPKey(rawPKey);
	}
	
	/**
	 * get raw public key
	 * @return raw public key
	 */
	public byte[] getRawPublicKey() {
		return keyMember.getRawPKey();
	}
	
	/**
	 * set key type
	 * @param KeyType key type
	 */
	public void setKeyType(KeyType keyType) {
		keyMember.setKeyType(keyType);
	}
	
	/**
	 * get key type
	 * @return key type
	 */
	public KeyType getKeyType() {
		return keyMember.getKeyType();
	}
	
	/**
	 * @return encode address
	 * @throws Exception 
	 */
	public String getEncAddress() throws Exception {
		byte[] raw_pkey = keyMember.getRawPKey();
		if (null == raw_pkey) {
			throw new Exception("public key is null");
		}
		
		return encAddress(keyMember.getKeyType(), raw_pkey);
	}
	
	/**
	 * @param pKey encode public key
	 * @return encode address
	 * @throws Exception 
	 */
	public static String getEncAddress(String pKey) throws Exception {
		KeyMember member = new KeyMember();
		getPublicKey(pKey, member);
		
		return encAddress(member.getKeyType(), member.getRawPKey());
	}
	
	/**
	 * check sign datas
	 * @param msg source message
	 * @param signMsg signed message
	 * @return true or false
	 * @throws Exception
	 */
	public boolean verify(byte[] msg, byte[] signMsg) throws Exception {
		boolean verifySuccess = false;
		verifySuccess = verifyMessage(msg, signMsg, keyMember);
		
		return verifySuccess;
	}
	
	/**
	 * check sign datas
	 * @param msg source message
	 * @param signMsg signed message
	 * @param encPublicKey enc public key
	 * @return true or false
	 * @throws Exception 
	 */
	public static boolean verify(byte[] msg, byte[] signMsg, String encPublicKey) throws Exception {
		boolean verifySuccess = false;
		KeyMember member = new KeyMember();
		getPublicKey(encPublicKey, member);
		verifySuccess = verifyMessage(msg, signMsg, member);
		
		return verifySuccess;
	}
	
	private static void getPublicKey(String bPkey, KeyMember member) throws Exception {
		if (null == bPkey) {
			throw new Exception("public key cannot be null");
		}
		
		KeyType type = null;
		byte[] buffPKey = HexFormat.hexToByte(bPkey);
		
		if (buffPKey.length < 6) {
			throw new Exception("public key (" + bPkey + ") is invalid, please check");
		}
		
		if (buffPKey[0] != (byte)0xB0) {
			throw new Exception("public key (" + bPkey + ") is invalid, please check");
		}
		
		if (buffPKey[1] > 4 || buffPKey[1] < 1) {
			throw new Exception("public key (" + bPkey + ") is invalid, please check");
		}
		type = KeyType.values()[buffPKey[1] - 1];
		
		// checksum
		if (!CheckKey.CheckSum(type, buffPKey)) {
			throw new Exception("public key (" + bPkey + ") is invalid, please check");
		}
		
		byte[] rawPKey = new byte[buffPKey.length - 6];
		System.arraycopy(buffPKey, 2, rawPKey, 0, rawPKey.length);
		member.setRawPKey(rawPKey);
		member.setKeyType(type);
	}
	
	private static String encAddress(KeyType type, byte[] raw_pkey) {
		byte[] buff = new byte[23];
		buff[0] = (byte) 0x01;
		buff[1] = (byte) 0x56;
		buff[2] = (byte) (type.ordinal() + 1);

		byte[] hashPkey = CheckKey.CalHash(type, raw_pkey);
		System.arraycopy(hashPkey, 12, buff, 3, 20);
		
		byte[] hash1 = CheckKey.CalHash(type, buff);
		byte[] hash2 = CheckKey.CalHash(type, hash1);
		byte[] tmp = new byte[27];
		
		System.arraycopy(buff, 0, tmp, 0, buff.length);
		System.arraycopy(hash2, 0, tmp, buff.length, 4);
		
		return Base58.encode(tmp);
	}
	
	private static boolean verifyMessage(byte[] msg, byte[] sign, KeyMember member) throws Exception {
		boolean verifySuccess = false;
		switch (member.getKeyType()) {
		case ED25519: {
			Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
			EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
			EdDSAPublicKeySpec eddsaPubKey = new EdDSAPublicKeySpec(member.getRawPKey(), spec);
			EdDSAPublicKey vKey = new EdDSAPublicKey(eddsaPubKey);
			sgr.initVerify(vKey);
			sgr.update(msg);
			verifySuccess = sgr.verify(sign);
			break;
		}
		default:
			throw new Exception("type does not exist");
		}
		return verifySuccess;
	}
}
