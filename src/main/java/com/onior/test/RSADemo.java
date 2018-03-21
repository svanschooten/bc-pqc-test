package com.onior.test;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.*;
import java.util.Scanner;

public class RSADemo {
    public static void run() {
        try {
            final int keySize = 2048;
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair =  keyPairGenerator.genKeyPair();
            PublicKey pubKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            System.out.println("public key: \n" + Base64.toBase64String(pubKey.getEncoded()));
            System.out.println("private key: \n" + Base64.toBase64String(privateKey.getEncoded()));

            System.out.println("enter encrypted string:");
            Scanner scanner = new Scanner(System.in);
            byte[] response = Base64.decode(scanner.nextLine());

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            System.out.println("decrypted: \n" + (new String(cipher.doFinal(response))));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
