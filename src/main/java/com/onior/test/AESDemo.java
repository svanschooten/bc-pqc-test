package com.onior.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.Console;

public class AESDemo {
    public static void run() {
        // Create console
        Console console = System.console();
        if (console == null) {
            System.out.println("Could not get console instance!");
        } else {
            // Input parameters
            console.printf("Testing password%n");
            char[] passwordArray = console.readPassword("Enter your secret password: ");
            console.printf("Password entered was: %s%n", new String(passwordArray));
            console.printf("Input plaintext%n");
            String plaintext = console.readLine("Enter your plaintext: ");
            try {
                // Key generation based on string input
                SecretKey secret = Util.createKey(new String(passwordArray));

                // Create cipher
                Cipher ecipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                ecipher.init(Cipher.ENCRYPT_MODE, secret);
                byte[] iv = ecipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();

                // Encryption
                byte[] ciphertext = ecipher.doFinal(plaintext.getBytes("UTF-8"));

                // Create cipher
                Cipher dcipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                dcipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));

                // Decryption
                byte[] deciphertext = dcipher.doFinal(ciphertext);

                // Print results
                console.printf("iv: %s\n", Util.bytes2hex(iv));
                console.printf("key: %s\n", Util.bytes2hex(secret.getEncoded()));
                console.printf("plaintext: %s\n", plaintext);
                console.printf("ciphertext: %s\n", Util.bytes2hex(ciphertext));
                console.printf("plaintext: %s\n\n", new String(deciphertext));

                // Testing key generation
                String staticPw = "a static password";
                SecretKey key1 = Util.createKey(staticPw);
                SecretKey key2 = Util.createKey(staticPw);
                SecretKey key3 = Util.createKey(staticPw + "aaaaa");
                console.printf("key1: %s\n", Util.bytes2hex(key1.getEncoded()));
                console.printf("key2: %s\n", Util.bytes2hex(key2.getEncoded()));
                console.printf("key3: %s\n", Util.bytes2hex(key3.getEncoded()));
                console.printf("1 and 2 are the same: %b\n", key1.equals(key2));
                console.printf("1 and 3 are not the same: %b\n", !key1.equals(key3));
                console.printf("2 and 3 are not the same: %b\n\n", !key2.equals(key3));

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
