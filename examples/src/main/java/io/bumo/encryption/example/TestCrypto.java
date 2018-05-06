package io.bumo.encryption.example;

import com.alibaba.fastjson.JSONObject;

import io.bumo.encryption.crypto.KeyStore;

public class TestCrypto {
	public static void main(String argv[]) {
		String encPrivateKey = "privbtGQELqNswoyqgnQ9tcfpkuH8P1Q6quvoybqZ9oTVwWhS6Z2hi1B";
		String password = "test1234";
		TestKeyStoreWithPrivateKey(encPrivateKey, password);
		TestKeyStoreWithNoPrivateKey(password);
	}
	
	public static void TestKeyStoreWithPrivateKey(String encPrivateKey, String password) {
		try {
			JSONObject keyStore = new JSONObject();
			encPrivateKey = KeyStore.generateKeyStore(encPrivateKey, password, 16384, 8, 1, keyStore);
			System.out.println(encPrivateKey);
			System.out.println(keyStore.toJSONString());

			JSONObject newKeyStore = JSONObject.parseObject("{\"cypher_text\":\"7E0892CAB60761CD8F73A21F0B040ACACAB694AF8C8CA25D4BE8549CCBD8E013AA4C2D338EA11F42596E0EEC05A158C20AE4B51E2B94D102\",\"aesctr_iv\":\"38C33D8E6E5911A0C3F715F5AC75A88A\",\"address\":\"buQdBdkvmAhnRrhLp4dmeCc2ft7RNE51c9EK\",\"scrypt_params\":{\"p\":1,\"r\":8,\"salt\":\"3070E64061711D39A382E23142B91DD9A6B3AB0B5AC1FD4D202191EAC2816661\",\"n\":16384},\"version\":2}");
			encPrivateKey = KeyStore.from(newKeyStore, password);
			System.out.println(encPrivateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void TestKeyStoreWithNoPrivateKey(String password) {
		JSONObject keyStore = new JSONObject();
		try {
			String encPrivateKey = KeyStore.generateKeyStore(null, password, 16384, 8, 1, keyStore);
			System.out.println(encPrivateKey);
			System.out.println(keyStore.toJSONString());
			
			encPrivateKey = KeyStore.from(keyStore, password);
			System.out.println(encPrivateKey);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
}
