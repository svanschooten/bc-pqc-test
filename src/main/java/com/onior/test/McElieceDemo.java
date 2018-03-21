package com.onior.test;

import org.bouncycastle.pqc.crypto.mceliece.McElieceCipher;
import org.bouncycastle.pqc.crypto.mceliece.McEliecePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKeysToParams;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Scanner;

public class McElieceDemo {

    public static void run() {
        try {
            File file = new File("key");
            X509EncodedKeySpec pubKeySpec;
            KeyFactory KF;
            PublicKey PK;
            McEliecePublicKeyParameters GPKP;
            McElieceCipher cipher;
            byte[] keyBytes;
            Scanner sc = new Scanner(file);
            String[] values = sc.next().split(",");
            keyBytes = new byte[values.length];
            for (int i = 0; i < values.length; i++) {
                keyBytes[i] = (byte) Integer.parseInt(values[i]);
            }
            sc.close();
            pubKeySpec = new X509EncodedKeySpec(keyBytes);
            KF = KeyFactory.getInstance("McEliece");
            PK = KF.generatePublic(pubKeySpec);
            GPKP = (McEliecePublicKeyParameters) McElieceKeysToParams.generatePublicKeyParameter(PK);
            cipher = new McElieceCipher();
            cipher.init(true, GPKP);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
