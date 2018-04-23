package com.onior.test;

import com.onior.test.NewHope.NHS;
import com.onior.test.NewHope.RAND;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.newhope.NHAgreement;
import org.bouncycastle.pqc.crypto.newhope.NHKeyPairGenerator;
import org.bouncycastle.pqc.crypto.newhope.NHPublicKeyParameters;

import java.security.SecureRandom;
import java.util.Scanner;

public class NewHopeDemo {

    public static void run() {
        // Using the BouncyCastle implementation
        try {
            NHKeyPairGenerator keyPairGenerator = new NHKeyPairGenerator();
            keyPairGenerator.init(new KeyGenerationParameters(new SecureRandom(), 1024));
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
            NHPublicKeyParameters publicKey = (NHPublicKeyParameters) keyPair.getPublic();

            System.out.println("public key:\n" + Util.bytes2hex(publicKey.getPubData()));
            System.out.println("Enter response value: ");
            Scanner scanner = new Scanner(System.in);
            String response = scanner.nextLine();

            byte[] bytes = Util.hex2bytes(response);
            NHPublicKeyParameters keyParameters = new NHPublicKeyParameters(bytes);

            NHAgreement agreement = new NHAgreement();
            agreement.init(keyPair.getPrivate());
            byte[] agreementValue = agreement.calculateAgreement(keyParameters);
            System.out.println("agreement value:\n" + Util.bytes2hex(agreementValue));
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Using my own implementation
        try {
            byte[] RAW = new byte[100];
            byte[] S = new byte[1792];
            byte[] SB = new byte[1824];
            byte[] UC;
            byte[] KEYA = new byte[32];

            RAND SRNG = new RAND();
            SRNG.clean();

            SecureRandom secureRandom = new SecureRandom();
            for (int i = 0; i < 100; i++) RAW[i] = (byte) secureRandom.nextInt();
            SRNG.seed(100, RAW);

            NHS nhs = new NHS();
            nhs.SERVER_1(SRNG, SB, S);
            for (int i = 0; i < SB.length; i++)  SB[i] = (byte) nhs.redc(SB[i]);

            System.out.println("SB:\n" + Util.bytes2hex(SB));
            System.out.println("Enter UC: ");
            Scanner scanner = new Scanner(System.in);
            String response = scanner.nextLine();
            UC = Util.hex2bytes(response);

            nhs.SERVER_2(S, UC, KEYA);
            System.out.println("Alice's key: " + Util.bytes2hex(KEYA));
        } catch (Exception e) {
            e.printStackTrace();
        }

    }
}
