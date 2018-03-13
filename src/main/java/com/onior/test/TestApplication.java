package com.onior.test;

import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

@SpringBootApplication
public class TestApplication {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
        // SpringApplication.run(TestApplication.class, args);

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        byte[] IV = "0000000000000000".getBytes();
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        PBEKeySpec spec = new PBEKeySpec("test".toCharArray(), IV, 1000, 256);
        byte[] keyBytes = skf.generateSecret(spec).getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
        byte[] encrypted = cipher.doFinal("hallo".getBytes());
        System.out.println("cipher: " + Util.bytes2hex(encrypted));
        System.out.println("key: " + Util.bytes2hex(secretKeySpec.getEncoded()));
        System.out.println("iv: " + Util.bytes2hex(cipher.getIV()));

        AESDemo.run();
        NTRUDemo.run();
        McElieceDemo.run();

        System.exit(0);
    }
}
