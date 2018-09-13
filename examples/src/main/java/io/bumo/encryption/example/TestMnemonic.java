package io.bumo.encryption.example;

import io.bumo.encryption.crypto.mnemonic.Mnemonic;
import io.bumo.encryption.key.PrivateKey;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * @Author riven
 * @Date 2018/9/13 10:43
 */
public class TestMnemonic {
    public static void main(String[] argv) {
        byte[] aesIv = new byte[16];
        SecureRandom randomIv = new SecureRandom();
        randomIv.nextBytes(aesIv);

        List<String> mnemonicCodes = Mnemonic.generateMnemonicCode(aesIv);
        for (String mnemonicCode : mnemonicCodes) {
            System.out.print(mnemonicCode + " ");
        }
        System.out.println();


        List<String> hdPaths = new ArrayList<>();
        hdPaths.add("M/44/80/0/0/1");
        List<String> privateKeys = Mnemonic.generatePrivateKeys(mnemonicCodes, hdPaths);
        for (String privateKey : privateKeys) {
            if (!PrivateKey.isPrivateKeyValid(privateKey)) {
                System.out.println("private is invalid");
                return;
            }
            System.out.print(privateKey + " ");
        }
        System.out.println();
    }
}
