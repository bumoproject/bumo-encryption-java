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
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class PrivateKey {
	private PublicKey publicKey = new PublicKey();
	private KeyMember keyMember = new KeyMember();
	
	/**
	 * generate key pair (default: ed25519)
	 * @throws EncException 
	 */
	public PrivateKey() throws EncException {
		this(KeyType.ED25519);
	}
	
	/**
	 * generate key pair
	 * @param  type the type of key
	 * @throws EncException 
	 */
	public PrivateKey(KeyType type) throws EncException {
		switch (type) {
		case ED25519: {
			KeyPairGenerator keyPairGenerator = new KeyPairGenerator();
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			EdDSAPrivateKey priKey = (EdDSAPrivateKey) keyPair.getPrivate();
			EdDSAPublicKey pubKey = (EdDSAPublicKey) keyPair.getPublic();
			keyMember.setRawSKey(priKey.getSeed());
			publicKey.setRawPublicKey(pubKey.getAbyte());
			break;
		}
		default:
			throw new EncException("type does not exist");
		}
		setKeyType(type);
		publicKey.setKeyType(type);
	}

	/**
	 * generate key pair
	 * @param skey private key
	 * @throws EncException
	 */
	public PrivateKey(String skey) throws EncException {
		getPrivateKey(skey, keyMember);
		publicKey.setKeyType(keyMember.getKeyType());
		byte[] rawPKey = getPublicKey(keyMember);
		publicKey.setRawPublicKey(rawPKey);
		keyMember.setRawPKey(rawPKey);
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
	public KeyType getKeyType() {
		return keyMember.getKeyType();
	}
	
	/**
	 * set raw private key
	 * @param rawSKey private key
	 */
	public void setRawPrivateKey(byte[] rawSKey) {
		keyMember.setRawSKey(rawSKey);
	}
	
	/**
	 * get raw private key
	 * @return raw private key
	 */
	public byte[] getRawPrivateKey() {
		return keyMember.getRawSKey();
	}
	
	/**
	 * get public key
	 * @return public key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	/**
	 *
	 * @return encode private key
	 * @throws EncException 
	 */
	public String getEncPrivateKey() throws EncException {
		byte[] rawSKey = keyMember.getRawSKey();
		if (rawSKey == null) {
			throw new EncException("raw private key is null");
		}
		return EncPrivateKey(keyMember.getKeyType(), keyMember.getRawSKey());
	}

	/**
	 * @param encPrivateKey encode private key
	 * @return true or false
	 */
	public static boolean isPrivateKeyValid(String encPrivateKey) {
		return encPrivateKeyValid(encPrivateKey);
	}
	
	
	/**
	 *  
	 * @return encode public key
	 * @throws EncException 
	 */
	public String getEncPublicKey() throws EncException {
		byte[] rawPKey = publicKey.getRawPublicKey();
		if (rawPKey == null) {
			throw new EncException("raw public key is null");
		}
		return encPublicKey(keyMember.getKeyType(), rawPKey).toLowerCase();
	}

	/**
	 * @param skey encode private key
	 * @return encode public key
	 * @throws EncException 
	 */
	public static String getEncPublicKey(String skey) throws EncException {
		KeyMember member = new KeyMember();
		getPrivateKey(skey, member);
		byte[] rawPKey = getPublicKey(member);
		return encPublicKey(member.getKeyType(), rawPKey).toLowerCase();
	}

	/**
	 * @param encPublicKey encode public key
	 * @return true or false
	 */
	public static boolean isPublicKeyValid(String encPublicKey) {
		return PublicKey.isPublicKeyValid(encPublicKey);
	}

	/**
	 * @return encode address
	 * @throws EncException 
	 */
	public String getEncAddress() throws EncException {
		return publicKey.getEncAddress();
	}
	
	/**
	 * @param pKey encode public key
	 * @return encode address
	 * @throws EncException 
	 */
	public static String getEncAddress(String pKey) throws EncException {
		return PublicKey.getEncAddress(pKey);
	}

	/**
	 * @param encAddress encode address
	 * @return true or false
	 */
	public static boolean isAddressValid(String encAddress) {
		return PublicKey.isAddressValid(encAddress);
	}
	/**
	 * sign message
	 * @param msg message
	 * @return sign data
	 * @throws EncException
	 */
	public byte[] sign(byte[] msg) throws EncException {
		return signMessage(msg, keyMember);
	}
	
	/**
	 * sign message
	 * @param msg message
	 * @param skey private key
	 * @return sign data
	 * @throws EncException
	 */
	public static byte[] sign(byte[] msg, String skey) throws EncException {
		KeyMember member = new KeyMember();
		getPrivateKey(skey, member);
		byte[] rawPKey = getPublicKey(member);
		member.setRawPKey(rawPKey);
		return signMessage(msg, member);
	}
	
	private static void getPrivateKey(String bSkey, KeyMember member) throws EncException {
		try {
			if (null == bSkey) {
				throw new EncException("Private key cannot be null");
			}

			byte[] skeyTmp = Base58.decode(bSkey);
			if (skeyTmp.length <= 9) {
				throw new EncException("Private key (" + bSkey + ") is invalid");
			}

			if (skeyTmp[3] != 1) {
				throw new EncException("Private key (" + bSkey + ") is invalid");
			}
			KeyType type = KeyType.values()[skeyTmp[3] - 1];

			// checksum
			if (!CheckKey.CheckSum(type, skeyTmp)) {
				throw new EncException("Private key (" + bSkey + ") is invalid");
			}

			byte[] rawSKey = new byte[skeyTmp.length - 9];
			System.arraycopy(skeyTmp, 4, rawSKey, 0, rawSKey.length);

			member.setKeyType(type);
			member.setRawSKey(rawSKey);
		} catch (Exception e) {
			throw new EncException("Invalid privateKey");
		}

	}
	private static byte[] getPublicKey(KeyMember member) throws EncException {
		byte[] rawPKey = null;
		switch (member.getKeyType()) {
		case ED25519: {
	        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
	        EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(member.getRawSKey(), spec);
	        EdDSAPublicKeySpec spec2 = new EdDSAPublicKeySpec(privKey.getA(),spec);
	        EdDSAPublicKey pDsaPublicKey = new EdDSAPublicKey(spec2);
	        rawPKey = pDsaPublicKey.getAbyte();
			break;
		}
		default:
			throw new EncException("Type does not exist");
		}
		return rawPKey;
	}
	private static String EncPrivateKey(KeyType type, byte[] raw_skey) throws EncException {
		if (null == raw_skey) {
			throw new EncException("Private key is null");
		}
		byte[] buff = new byte[raw_skey.length + 5];
		buff[0] = (byte) 0xDA;
		buff[1] = (byte) 0x37;
		buff[2] = (byte) 0x9F;
		System.arraycopy(raw_skey, 0, buff, 4, raw_skey.length);
		
		buff[3] = (byte) (type.ordinal() + 1);
		
		byte[] hash1 = CheckKey.CalHash(type, buff);
		byte[] hash2 = CheckKey.CalHash(type, hash1);

		byte[] tmp = new byte[buff.length + 4];

		System.arraycopy(buff, 0, tmp, 0, buff.length);
		System.arraycopy(hash2, 0, tmp, buff.length, 4);
		
		return Base58.encode(tmp);
	}
	private static boolean encPrivateKeyValid(String encPrivateKey) {
		boolean valid;
		try {
			if (null == encPrivateKey) {
				throw new EncException("Invalid privateKey");
			}

			byte[] privateKeyTemp = Base58.decode(encPrivateKey);

			if (privateKeyTemp.length != 41 || privateKeyTemp[0] != (byte)0xDA || privateKeyTemp[1] != (byte)0x37 ||
					privateKeyTemp[2] != (byte)0x9F || privateKeyTemp[3] != (byte)0x01) {
				throw new EncException("Invalid privateKey");
			}

			int len = privateKeyTemp.length;

			byte[] checkSum = new byte[4];
			System.arraycopy(privateKeyTemp, len - 4, checkSum, 0, 4);

			byte[] buff = new byte[len - 4];
			System.arraycopy(privateKeyTemp, 0, buff, 0, len - 4);

			byte[] hash1 = CheckKey.CalHash(KeyType.ED25519, buff);
			byte[] hash2 = CheckKey.CalHash(KeyType.ED25519, hash1);

			byte[] checkSumCol = new byte[4];
			System.arraycopy(hash2, 0, checkSumCol, 0, 4);
			if (!Arrays.equals(checkSum, checkSumCol)) {
				throw new EncException("Invalid privateKey");
			}

			valid = true;
		} catch (Exception e) {
            valid = false;
		}
		return valid;
	}
	private static String encPublicKey(KeyType type, byte[] raw_pkey) throws EncException {
		if (null == raw_pkey) {
			throw new EncException("Public key is null");
		}
		int length = raw_pkey.length + 2;
		byte[] buff = new byte[length];
		buff[0] = (byte)0xB0;
		buff[1] = (byte) (type.ordinal() + 1);

		System.arraycopy(raw_pkey, 0, buff, 2, raw_pkey.length);
		
		byte[] hash1 = CheckKey.CalHash(type, buff);
		byte[] hash2 = CheckKey.CalHash(type, hash1);
		byte[] tmp = new byte[buff.length + 4];

		System.arraycopy(buff, 0, tmp, 0, buff.length);
		System.arraycopy(hash2, 0, tmp, buff.length, 4);
		
		return HexFormat.byteToHex(tmp);
	}
	private static byte[] signMessage(byte[] msg, KeyMember member) throws EncException {
		if (null == member.getRawSKey()) {
			throw new EncException("Raw private key is null");
		}
		byte[] signMsg = null;

		try {
			switch (member.getKeyType()) {
				case ED25519: {
					Signature sgr = new EdDSAEngine(MessageDigest.getInstance("SHA-512"));
					EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName("ed25519-sha-512");
					EdDSAPrivateKeySpec sKeySpec = new EdDSAPrivateKeySpec(member.getRawSKey(), spec);
					EdDSAPrivateKey sKey = new EdDSAPrivateKey(sKeySpec);
					sgr.initSign(sKey);
					sgr.update(msg);

					signMsg = sgr.sign();
					break;
				}
				default:
					throw new EncException("Type does not exist");
			}
		} catch (NoSuchAlgorithmException e) {
			throw new EncException("System error");
		} catch (InvalidKeyException e) {
			throw new EncException("Invalid privateKey");
		} catch (SignatureException e) {
			throw new EncException("Sign message failed");
		}
		
		return signMsg;
	}

}
