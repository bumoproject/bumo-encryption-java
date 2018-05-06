package io.bumo.encryption.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;

import io.bumo.encryption.key.PrivateKey;
import io.bumo.encryption.key.PublicKey;
import io.bumo.encryption.model.KeyType;
import io.bumo.encryption.utils.hex.HexFormat;
import io.bumo.encryption.utils.http.HttpKit;

public class TestKey {
	
	class BumoAccount {
		public String address;
		public String privateKey;
		public String publicKey;
	}
	
	BumoAccount srcAccount = new BumoAccount();
	public static void main(String[] args) throws IllegalArgumentException, Exception {
		// test signature and verify
		test_ED25519();
		System.out.println();
		
		// test transaction
		System.out.println("\n\n================ teat create account ==================");
		String url = "http://127.0.0.1:36002";
		String privateKey = "privbtGQELqNswoyqgnQ9tcfpkuH8P1Q6quvoybqZ9oTVwWhS6Z2hi1B";
		String publicKey = "b001b6d3120599d19cae7adb6c5e2674ede8629c871cb8b93bd05bb34d203cd974c3f0bc07e5";
		String address = "buQdBdkvmAhnRrhLp4dmeCc2ft7RNE51c9EK";
		
		// create A
		System.out.println("create A: ");
		PrivateKey bumoKey_A = TestCreateAccount(url, address, privateKey, publicKey, address, privateKey, publicKey, KeyType.ED25519);
		System.out.println("A account: " + bumoKey_A.getEncAddress());
		Thread.sleep(5000);
		
		// A create D
		System.out.println("create B: ");
		PrivateKey bumoKey_B = TestCreateAccount(url, address, privateKey, publicKey, address, privateKey, publicKey, KeyType.ED25519);
		System.out.println("B account: " + bumoKey_B.getEncAddress());
		Thread.sleep(5000);
		
		System.out.println();
		System.out.println();
		System.out.println("B issue CNY 10000");
		// B issue CNY 10000
		TestIssueAsset(url, bumoKey_B.getEncAddress(), bumoKey_B.getEncPrivateKey(), bumoKey_B.getEncPublicKey(), "CNY", 10000);
		
		Thread.sleep(5000);
		
		// B pay 5000 CNY to A
		System.out.println("D pay B CNY 5000");
		TestPayAsset(url, bumoKey_B.getEncAddress(), bumoKey_B.getEncAddress(), bumoKey_B.getEncPrivateKey(),
				bumoKey_B.getEncPublicKey(), bumoKey_A.getEncAddress(), "CNY", 5000);
		
		// A pay 50000 BU to B
		TestPayCoin(url, bumoKey_A.getEncAddress(), bumoKey_A.getEncPrivateKey() , bumoKey_A.getEncPublicKey(), 
				bumoKey_B.getEncAddress(), 50000);
	}
	
	public static PrivateKey TestCreateAccount(String url, String srcAddress, String srcPrivate, String srcPublic, String signerAddress,
			String signerPrivate, String signerPublic, KeyType algorithm) {
		PrivateKey bumokey_new = null;
		try {
			// getAccount
			String getAccount = url + "/getAccount?address=" + srcAddress;
			String txSeq = HttpKit.post(getAccount, "");
			JSONObject tx = JSONObject.parseObject(txSeq);
			String seq_str = tx.getJSONObject("result").containsKey("nonce") ? tx.getJSONObject("result").getString("nonce") : "0";
			long nonce = Long.parseLong(seq_str);
			
			// generate new Account address, PrivateKey, publicKey
			bumokey_new = new PrivateKey(algorithm);
			String newAccountAddress = bumokey_new.getEncAddress();
			
			// use src account sign
			PrivateKey bumoKey_sign = new PrivateKey(signerPrivate);
			
			JSONObject transaction = new JSONObject();
			transaction.put("source_address", srcAddress);
			transaction.put("nonce", nonce + 1);
			transaction.put("fee_limit", 1000000);
			transaction.put("gas_price", 1000);
			JSONArray operations = new JSONArray();
			JSONObject operation = new JSONObject();
			operation.put("type", 1);
			JSONObject createAccount = new JSONObject();
			JSONObject priv = new JSONObject();
			priv.put("master_weight", 1);
			JSONObject thresholds = new JSONObject();
			thresholds.put("tx_threshold", 1);
			
			createAccount.put("dest_address", newAccountAddress);
			createAccount.put("init_balance", 1000000000000L);
			priv.put("thresholds", thresholds);
			createAccount.put("priv", priv);
			operation.put("create_account", createAccount);
			operations.add(operation);
			transaction.put("operations", operations);
			String getTransactionBlob = url + "/getTransactionBlob";
			String blob = HttpKit.post(getTransactionBlob, transaction.toJSONString());
			JSONObject transactionBlob = JSON.parseObject(blob);
			long error_code = transactionBlob.getLongValue("error_code");
			JSONObject blobResult = transactionBlob.getJSONObject("result");
			if (transactionBlob != null && error_code != 0) {
				String hash = blobResult.getString("hash");
				String desc = transactionBlob.getString("error_desc");
				System.out.println("create account blob (" + hash + ") error description: " + desc);
				return null;
			}
			String blob_hex = blobResult.getString("transaction_blob");
			
			// add transaction with signature
			JSONObject request = new JSONObject();
			JSONArray items = new JSONArray();
			JSONObject item = new JSONObject();
			item.put("transaction_blob", blob_hex);
			JSONArray signatures = new JSONArray();
			JSONObject signature = new JSONObject();
			signature.put("sign_data", HexFormat.byteToHex(bumoKey_sign.sign(HexFormat.hexToByte(blob_hex))));
			signature.put("public_key", signerPublic);
			signatures.add(signature);
			item.put("signatures", signatures);
			items.add(item);
			request.put("items", items);
			
			String submitTransaction = url + "/submitTransaction";
			String trans = HttpKit.post(submitTransaction, request.toJSONString());
			JSONObject transObj = JSONObject.parseObject(trans);
			JSONArray transResult = transObj.getJSONArray("results");
			String hash = transResult.getJSONObject(0).getString("hash");
			if (transResult.getJSONObject(0).getLongValue("error_code") != 0) {
				String desc = transResult.getJSONObject(0).getString("error_desc");
				System.out.println("create account transaction(" + hash + ") error description: " + desc);
				return null;
			}
			System.out.println("create account transaction hash (" + hash + ")");
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		return bumokey_new;
	}
	
	public static void TestIssueAsset(String url, String address, String privateKey, String publicKey,
			String code, long amount) {
		try {
			// getAccount
			String getAccount = url + "/getAccount?address=" + address;
			String txSeq = HttpKit.post(getAccount, "");
			JSONObject tx = JSONObject.parseObject(txSeq);
			String seq_str = tx.getJSONObject("result").containsKey("nonce") ? tx.getJSONObject("result").getString("nonce") : "0";
			long nonce = Long.parseLong(seq_str);
			
			// use src account sign
			PrivateKey bumoKey_sign = new PrivateKey(privateKey);
			
			JSONObject transaction = new JSONObject();
			transaction.put("source_address", address);
			transaction.put("nonce", nonce + 1);
			transaction.put("fee_limit", 6000000000L);
			transaction.put("gas_price", 1000);
			JSONArray operations = new JSONArray();
			JSONObject operation = new JSONObject();
			operation.put("type", 2);
			JSONObject issueAsset = new JSONObject();
			issueAsset.put("code", code);
			issueAsset.put("amount", amount);
			
			operation.put("issue_asset", issueAsset);
			operations.add(operation);
			transaction.put("operations", operations);
			String getTransactionBlob = url + "/getTransactionBlob";
			String blob = HttpKit.post(getTransactionBlob, transaction.toJSONString());
			JSONObject transactionBlob = JSON.parseObject(blob);
			long error_code = transactionBlob.getLongValue("error_code");
			JSONObject blobResult = transactionBlob.getJSONObject("result");
			if (transactionBlob != null && error_code != 0) {
				String hash = blobResult.getString("hash");
				String desc = transactionBlob.getString("error_desc");
				System.out.println("issue asset blob (" + hash + ") error description: " + desc);
				return;
			}
			String blob_hex = blobResult.getString("transaction_blob");
			
			// add transaction with signature
			JSONObject request = new JSONObject();
			JSONArray items = new JSONArray();
			JSONObject item = new JSONObject();
			item.put("transaction_blob", blob_hex);
			JSONArray signatures = new JSONArray();
			JSONObject signature = new JSONObject();
			signature.put("sign_data", HexFormat.byteToHex(bumoKey_sign.sign(HexFormat.hexToByte(blob_hex))));
			signature.put("public_key", publicKey);
			signatures.add(signature);
			item.put("signatures", signatures);
			items.add(item);
			request.put("items", items);
			
			String submitTransaction = url + "/submitTransaction";
			String trans = HttpKit.post(submitTransaction, request.toJSONString());
			JSONObject transObj = JSONObject.parseObject(trans);
			JSONArray transResult = transObj.getJSONArray("results");
			String hash = transResult.getJSONObject(0).getString("hash");
			if (transResult.getJSONObject(0).getLongValue("error_code") != 0) {
				String desc = transResult.getJSONObject(0).getString("error_desc");
				System.out.println("issue asset transaction(" + hash + ") error description: " + desc);
			}
			System.out.println("issue asset transaction hash (" + hash + ")");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void TestPayAsset(String url, String issueAddress, String srcAddress, String srcPrivate, String srcPublic,
									String destAddress, String code, long amount) {
		try {
			// getAccount
			String getAccount = url + "/getAccount?address=" + srcAddress;
			String txSeq = HttpKit.post(getAccount, "");
			JSONObject tx = JSONObject.parseObject(txSeq);
			String seq_str = tx.getJSONObject("result").containsKey("nonce") ? tx.getJSONObject("result").getString("nonce") : "0";
			long nonce = Long.parseLong(seq_str);
			
			// use src account sign
			PrivateKey bumoKey_sign = new PrivateKey(srcPrivate);
			
			JSONObject transaction = new JSONObject();
			transaction.put("source_address", srcAddress);
			transaction.put("nonce", nonce + 1);
			transaction.put("fee_limit", 1000000);
			transaction.put("gas_price", 1000);
			JSONArray operations = new JSONArray();
			JSONObject operation = new JSONObject();
			operation.put("type", 3);
			JSONObject payAsset = new JSONObject();
			payAsset.put("dest_address", destAddress);
			JSONObject asset = new JSONObject();
			JSONObject key = new JSONObject();
			key.put("issuer", issueAddress);
			key.put("code", code);
			key.put("type", 0);
			
			asset.put("key", key);
			asset.put("amount", amount);
			payAsset.put("asset", asset);
			operation.put("pay_asset", payAsset);
			operations.add(operation);
			transaction.put("operations", operations);
			String getTransactionBlob = url + "/getTransactionBlob";
			String blob = HttpKit.post(getTransactionBlob, transaction.toJSONString());
			JSONObject transactionBlob = JSON.parseObject(blob);
			long error_code = transactionBlob.getLongValue("error_code");
			JSONObject blobResult = transactionBlob.getJSONObject("result");
			if (transactionBlob != null && error_code != 0) {
				String hash = blobResult.getString("hash");
				String desc = transactionBlob.getString("error_desc");
				System.out.println("payAsset blob (" + hash + ") error description: " + desc);
				return;
			}
			String blob_hex = blobResult.getString("transaction_blob");
			
			// add transaction with signature
			JSONObject request = new JSONObject();
			JSONArray items = new JSONArray();
			JSONObject item = new JSONObject();
			item.put("transaction_blob", blob_hex);
			JSONArray signatures = new JSONArray();
			JSONObject signature = new JSONObject();
			signature.put("sign_data", HexFormat.byteToHex(bumoKey_sign.sign(HexFormat.hexToByte(blob_hex))));
			signature.put("public_key", srcPublic);
			signatures.add(signature);
			item.put("signatures", signatures);
			items.add(item);
			request.put("items", items);
			
			String submitTransaction = url + "/submitTransaction";
			String trans = HttpKit.post(submitTransaction, request.toJSONString());
			JSONObject transObj = JSONObject.parseObject(trans);
			JSONArray transResult = transObj.getJSONArray("results");
			String hash = transResult.getJSONObject(0).getString("hash");
			if (transResult.getJSONObject(0).getLongValue("error_code") != 0) {
				String desc = transResult.getJSONObject(0).getString("error_desc");
				System.out.println("payAsset transaction(" + hash + ") error description: " + desc);
			}
			System.out.println("payAsset transaction hash (" + hash + ")");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void TestPayCoin(String url, String srcAddress, String srcPrivate, String srcPublic,
			String destAddress, long amount) {
		try {
			// getAccount
			String getAccount = url + "/getAccount?address=" + srcAddress;
			String txSeq = HttpKit.post(getAccount, "");
			JSONObject tx = JSONObject.parseObject(txSeq);
			String seq_str = tx.getJSONObject("result").containsKey("nonce") ? tx.getJSONObject("result").getString("nonce") : "0";
			long nonce = Long.parseLong(seq_str);
			
			// use src account sign
			PrivateKey bumoKey_sign = new PrivateKey(srcPrivate);
			
			JSONObject transaction = new JSONObject();
			transaction.put("source_address", srcAddress);
			transaction.put("nonce", nonce + 1);
			transaction.put("fee_limit", 1000000);
			transaction.put("gas_price", 1000);
			JSONArray operations = new JSONArray();
			JSONObject operation = new JSONObject();
			operation.put("type", 7);
			JSONObject payCoin = new JSONObject();
			payCoin.put("dest_address", destAddress);
			payCoin.put("amount", amount);
			
			operation.put("pay_coin", payCoin);
			operations.add(operation);
			transaction.put("operations", operations);
			String getTransactionBlob = url + "/getTransactionBlob";
			String blob = HttpKit.post(getTransactionBlob, transaction.toJSONString());
			JSONObject transactionBlob = JSON.parseObject(blob);
			long error_code = transactionBlob.getLongValue("error_code");
			JSONObject blobResult = transactionBlob.getJSONObject("result");
			if (transactionBlob != null && error_code != 0) {
				String hash = blobResult.getString("hash");
				String desc = transactionBlob.getString("error_desc");
				System.out.println("pay coin blob (" + hash + ") error description: " + desc);
				return;
			}
			String blob_hex = blobResult.getString("transaction_blob");
			
			// add transaction with signature
			JSONObject request = new JSONObject();
			JSONArray items = new JSONArray();
			JSONObject item = new JSONObject();
			item.put("transaction_blob", blob_hex);
			JSONArray signatures = new JSONArray();
			JSONObject signature = new JSONObject();
			signature.put("sign_data", HexFormat.byteToHex(bumoKey_sign.sign(HexFormat.hexToByte(blob_hex))));
			signature.put("public_key", srcPublic);
			signatures.add(signature);
			item.put("signatures", signatures);
			items.add(item);
			request.put("items", items);
			
			String submitTransaction = url + "/submitTransaction";
			String trans = HttpKit.post(submitTransaction, request.toJSONString());
			JSONObject transObj = JSONObject.parseObject(trans);
			JSONArray transResult = transObj.getJSONArray("results");
			String hash = transResult.getJSONObject(0).getString("hash");
			if (transResult.getJSONObject(0).getLongValue("error_code") != 0) {
				String desc = transResult.getJSONObject(0).getString("error_desc");
				System.out.println("pay coin transaction(" + hash + ") error description: " + desc);
			}
			System.out.println("pay coin transaction hash (" + hash + ")");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void test_ED25519() {
		try {
			PrivateKey priKey = new PrivateKey(KeyType.ED25519);
			System.out.println("bubuKey1 private key: " + priKey.getEncPrivateKey());
			System.out.println("bubuKey1 public key: " + priKey.getEncPublicKey());
			System.out.println("bubuKey1 address: " + priKey.getEncAddress());
			
			System.out.println("bubuKey1 static public key: " + PrivateKey.getEncPublicKey(priKey.getEncPrivateKey()));
			System.out.println("bubuKey1 static address: " + PrivateKey.getEncAddress(priKey.getEncPublicKey()));
			
			PrivateKey priKey2 = new PrivateKey(priKey.getEncPrivateKey());
			System.out.println("bubuKey1 static public key: " + PrivateKey.getEncPublicKey(priKey.getEncPrivateKey()));
			System.out.println("bubuKey2 private key: " + priKey2.getEncPrivateKey());
			System.out.println("bubuKey2 public key: " + priKey2.getEncPublicKey());
			System.out.println("bubuKey2 address: " + priKey2.getEncAddress());
			
			String src = "test";
			byte[] sign = priKey2.sign(src.getBytes());
			byte[] sign_static = PrivateKey.sign(src.getBytes(),priKey.getEncPrivateKey());
			System.out.println("signature: " + io.bumo.encryption.utils.hex.HexFormat.byteToHex(sign));
			System.out.println("static signature: " + io.bumo.encryption.utils.hex.HexFormat.byteToHex(sign_static));
			System.out.println("verify: " + PublicKey.verify(src.getBytes(), sign, priKey.getEncPublicKey()));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
