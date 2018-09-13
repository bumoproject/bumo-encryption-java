package io.bumo.encryption.example;

import com.alibaba.fastjson.JSON;

import io.bumo.encryption.crypto.keystore.KeyStore;
import io.bumo.encryption.crypto.keystore.entity.KeyStoreEty;

public class TestCrypto {
	public static void main(String argv[]) {
		String encPrivateKey = "privbtGQELqNswoyqgnQ9tcfpkuH8P1Q6quvoybqZ9oTVwWhS6Z2hi1B";
		String password = "test1234";
		TestKeyStoreWithPrivateKey(encPrivateKey, password);
		
	}
	
	public static void TestKeyStoreWithPrivateKey(String encPrivateKey, String password) {
		try {
			//KeyStoreEty keyStore = KeyStore.generateKeyStore(password, encPrivateKey);
			//难度
			int n = (int)Math.pow(2, 16);
			KeyStoreEty keyStore = KeyStore.generateKeyStore(password, encPrivateKey,n,8,1,2);
			System.out.println(JSON.toJSONString(keyStore));
			String privateKey = KeyStore.decipherKeyStore(password, keyStore);
			System.out.println(privateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
}
