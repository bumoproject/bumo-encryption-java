package io.bumo.encryption.utils.aes;

import io.bumo.encryption.exception.EncException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCtr {
	
    public static byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) throws EncException {
    	byte[] encrypted = null;
    	try {
    		byte[] clean = plainText;
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
            encrypted = cipher.doFinal(clean);
    	}
    	catch (Exception e) {
    		throw new EncException(e.getMessage());
    	}
        return encrypted;
    }

    public static byte[] decrypt(byte[] encryptedIvTextBytes, byte[] key, byte[] iv) throws EncException {
    	byte[] decrypted = null;
    	try {
    		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            Cipher cipherDecrypt = Cipher.getInstance("AES/CTR/NoPadding");
            cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
            decrypted = cipherDecrypt.doFinal(encryptedIvTextBytes);
    	}
    	catch (Exception e) {
            throw new EncException(e.getMessage());
    	}
        
        return decrypted;
    }
}