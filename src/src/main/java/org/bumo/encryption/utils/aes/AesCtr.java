package org.bumo.encryption.utils.aes;

import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCtr {

    public static void main(String[] args) throws Exception {
        
    }
    
    public static boolean init() {
    	
    	return true;
    }

    public static byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) throws Exception {
        byte[] clean = plainText;
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        // Encrypt.
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] encrypted = cipher.doFinal(clean);
        return encrypted;
    }

    public static String decrypt(byte[] encryptedIvTextBytes, byte[] key, byte[] iv) throws Exception {
        // Extract IV.
        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv); 
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        Cipher cipherDecrypt = Cipher.getInstance("AES/CTR/NoPadding");
        cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] decrypted = cipherDecrypt.doFinal(encryptedIvTextBytes);

        return new String(decrypted);
    }
}