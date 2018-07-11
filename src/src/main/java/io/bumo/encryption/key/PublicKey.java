package io.bumo.encryption.key;

import java.security.*;
import java.util.Arrays;

import io.bumo.encryption.common.CheckKey;
import io.bumo.encryption.exception.EncException;
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
	
	public PublicKey() {
	}
	
	/**
	 * structure with encrytion public key
	 */
	public PublicKey(String encPublicKey) throws EncException {
		getPublicKey(encPublicKey, keyMember);
	}
	
	/**
	 * set enc public key
	 * @param encPublicKey encryption public key
	 * @throws EncException
	 */
	public void setEncPublicKey(String encPublicKey) throws EncException {
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
	 * @param keyType key type
	 */
	public void setKeyType(KeyType keyType) {
		keyMember.setKeyType(keyType);
	}
	
	/**
	 * get key type
	 * @return key type
	 */
	private KeyType getKeyType() {
		return keyMember.getKeyType();
	}
	
	/**
	 * @return encode address
	 * @throws EncException 
	 */
	public String getEncAddress() throws EncException {
		byte[] raw_pkey = keyMember.getRawPKey();
		if (null == raw_pkey) {
			throw new EncException("public key is null");
		}
		
		return encAddress(keyMember.getKeyType(), raw_pkey);
	}
	
	/**
	 * @param pKey encode public key
	 * @return encode address
	 * @throws EncException 
	 */
	public static String getEncAddress(String pKey) throws EncException {
		KeyMember member = new KeyMember();
		getPublicKey(pKey, member);
		
		return encAddress(member.getKeyType(), member.getRawPKey());
	}

	/**
	 * @param encAddress encode address
	 * @return true or false
	 */
	public static boolean isAddressValid(String encAddress) {
		return encAddressValid(encAddress);
	}

	/**
	 * @param encPublicKey encode public key
	 * @return true or false
	 */
	public static boolean isPublicKeyValid(String encPublicKey) {
		return encPublicKeyValid(encPublicKey);
	}

	/**
	 * check sign datas
	 * @param msg source message
	 * @param signMsg signed message
	 * @return true or false
	 * @throws EncException
	 */
	public boolean verify(byte[] msg, byte[] signMsg) throws EncException {
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
	 * @throws EncException 
	 */
	public static boolean verify(byte[] msg, byte[] signMsg, String encPublicKey) throws EncException {
		boolean verifySuccess = false;
		KeyMember member = new KeyMember();
		getPublicKey(encPublicKey, member);
		verifySuccess = verifyMessage(msg, signMsg, member);
		
		return verifySuccess;
	}
	
	private static void getPublicKey(String bPkey, KeyMember member) throws EncException {
		if (null == bPkey) {
			throw new EncException("public key cannot be null");
		}

		if (!HexFormat.isHexString(bPkey)) {
			throw new EncException("public key (" + bPkey + ") is invalid, please check");
		}

		KeyType type = null;
		byte[] buffPKey = HexFormat.hexToByte(bPkey);
		
		if (buffPKey.length < 6) {
			throw new EncException("public key (" + bPkey + ") is invalid, please check");
		}
		
		if (buffPKey[0] != (byte)0xB0) {
			throw new EncException("public key (" + bPkey + ") is invalid, please check");
		}
		
		if (buffPKey[1] != 1) {
			throw new EncException("public key (" + bPkey + ") is invalid, please check");
		}
		type = KeyType.values()[buffPKey[1] - 1];
		
		// checksum
		if (!CheckKey.CheckSum(type, buffPKey)) {
			throw new EncException("public key (" + bPkey + ") is invalid, please check");
		}
		
		byte[] rawPKey = new byte[buffPKey.length - 6];
		System.arraycopy(buffPKey, 2, rawPKey, 0, rawPKey.length);
		member.setRawPKey(rawPKey);
		member.setKeyType(type);
	}

	private static boolean encPublicKeyValid(String encPublicKey) throws EncException {
		boolean valid;
		try {
			if (null == encPublicKey) {
				throw new EncException("Invalid publicKey");
			}
			if (!HexFormat.isHexString(encPublicKey)) {
				throw new EncException("Invalid publicKey");
			}

			KeyType type = null;
			byte[] buffPKey = HexFormat.hexToByte(encPublicKey);
			if (buffPKey.length < 6 || buffPKey[0] != (byte)0xB0 || buffPKey[1] != (byte)0x01) {
				throw new EncException("Invalid publicKey");
			}

			int len = buffPKey.length;
			byte[] checkSum = new byte[4];
			System.arraycopy(buffPKey, len - 4, checkSum, 0, 4);

			byte[] buff = new byte[len - 4];
			System.arraycopy(buffPKey, 0, buff, 0, len - 4);

			byte[] hash1 = CheckKey.CalHash(KeyType.ED25519, buff);
			byte[] hash2 = CheckKey.CalHash(KeyType.ED25519, hash1);

			byte[] checkSumCol = new byte[4];
			System.arraycopy(hash2, 0, checkSumCol, 0, 4);
			if (!Arrays.equals(checkSum, checkSumCol)) {
				throw new EncException("Invalid publicKey");
			}

			valid = true;
		} catch (Exception exception) {
			throw new EncException("Invalid publicKey");
		}
		return valid;
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

	private static boolean encAddressValid(String encAddress) throws EncException {
		boolean valid = false;
		try {
			if (null == encAddress) {
				throw new EncException("Invalid address");
			}
			byte[] addressTemp = Base58.decode(encAddress);
			if (addressTemp.length != 27 || addressTemp[0] != (byte)0x01 || addressTemp[1] != (byte)0x56
					|| addressTemp[2] != (byte)0x01) {
				throw new EncException("Invalid address");
			}

			int len = addressTemp.length;
			byte[] checkSum = new byte[4];
			System.arraycopy(addressTemp, len - 4, checkSum, 0, 4);

			byte[] buff = new byte[len - 4];
			System.arraycopy(addressTemp, 0, buff, 0, len - 4);

			byte[] hash1 = CheckKey.CalHash(KeyType.ED25519, buff);
			byte[] hash2 = CheckKey.CalHash(KeyType.ED25519, hash1);

			byte[] checkSumCol = new byte[4];
			System.arraycopy(hash2, 0, checkSumCol, 0, 4);
			if (!Arrays.equals(checkSum, checkSumCol)) {
				throw new EncException("Invalid address");
			}

			valid = true;
		} catch (Exception e) {
			throw new EncException("Invalid address");
		}

		return valid;
	}
	
	private static boolean verifyMessage(byte[] msg, byte[] sign, KeyMember member) throws EncException {

		boolean verifySuccess = false;
		try {
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
					throw new EncException("type does not exist");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new EncException("System error");
		} catch (InvalidKeyException e) {
			throw new EncException("Invalid publicKey");
		} catch (SignatureException e) {
			throw new EncException("Verify signature failed");
		}

		return verifySuccess;
	}
}
