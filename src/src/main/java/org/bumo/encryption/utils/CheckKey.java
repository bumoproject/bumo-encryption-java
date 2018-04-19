package org.bumo.encryption.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import cfca.sadk.org.bouncycastle.util.Arrays;

public class CheckKey {
	/**
	 * 验证签名函数
	 * @param msg 消息内容
	 * @param pkey 公钥字符串
	 * @param sig 签名
	 * @return
	 * @throws Exception 
	 */
	public static boolean CheckSum(KeyType type, byte[] key) {
		return checkKey(type, key);
	}
	
	/**
	 * 哈希
	 * @param type 签名类型
	 * @param data 待哈希数据
	 * @return 哈希后的数据
	 */
	public static byte[] CalHash(KeyType type, byte[] data) {
		byte[] result = null;
		if (type == KeyType.ED25519) {
			MessageDigest sha256 = null;
			try {
				sha256 = MessageDigest.getInstance("SHA-256");

			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}

			sha256.update(data);
			result = sha256.digest();
		}
		else {
			result = SM3Digest.Hash(data);
		}
		return result;
	}
	
	private static boolean checkKey(KeyType type, byte[] key) {
		boolean SumIsRight = true;
		byte[] checkSrc = new byte[key.length - 4];
		byte[] checkSum = new byte[4];
		System.arraycopy(key, 0, checkSrc, 0, checkSrc.length);
		System.arraycopy(key, checkSrc.length, checkSum, 0, 4);
		
		byte[] hash1 = CalHash(type, checkSrc);
		byte[] hash2 = CalHash(type, hash1);
		
		byte[] HashSum = new byte[4];
		System.arraycopy(hash2, 0, HashSum, 0, 4);
		if (!Arrays.areEqual(HashSum, checkSum)) {
			SumIsRight = false;
		}
		return SumIsRight;
	}
	
}
