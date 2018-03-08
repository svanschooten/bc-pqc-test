package com.onior.test;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.Security;

@SpringBootApplication
public class TestApplication {

    public static void main(String[] args) {
        // SpringApplication.run(TestApplication.class, args);

        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastlePQCProvider());

        AESDemo.run();
        NTRUDemo.run();
//        McElieceDemo.run();

        System.exit(0);
    }
}
