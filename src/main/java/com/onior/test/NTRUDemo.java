package com.onior.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.ntru.*;
import org.bouncycastle.util.Arrays;

public class NTRUDemo {
    private static final String jsBase64Pub = "0103000610765f1cf1c78dfa3368a2e8e6f926e54c49a9bc17c201fbc4ce32903178e5bc48e506c0b33e7ee664acca66aad5d215fc4fbf2799187ed29961bae5ab105b7de9e586c7fd6f9201ab2e751dd3984eab90b4cc6c43313a000f5c4ed6fc6323a18716134f290cab4d6790a4a6bc7278868cf5158d063e8316ce61c558948fc85ea7b753225a2b04492390aad7b4ff4eaa7dc120f4504ac1b696594f78c03f94f3308a606de74c43f6ad09df80a8e345b1819b492738a77d1ea86b32b04fbd165f63efa6d0cd7a8592961fcc6be7328a3db98d413974a8dd5c92171eca4d5073269f88cb472284fbefbe336216b6207f31f0d729fb51c06290d01491cdb9ea9ffc3eaa3792fd1f0568bbfc02529c3ba7f2e3c7fcfe884dabc34740def6d457eb920bad0d2453d3f761dfb87c99b3f15a7e9fe0bb6c5d2855745a3cb3fcfc8750e81c5c00e682ab1baa7ff3731a29b18010c9fa9812323a3b05b9dffec570a7ef7e6acae431592e3633dc88787ccd57b7c11f1ad7da97f0ecd40d7f5d86f3ec7e272b3cfa007f2855a9f287d219bc802d25488eff0e88bee35235716b4a3d226121aa9668fe650a13ee75f98ef5d780f0f6e1dcf1ea5634b062b011e6078283ae8cc71f5f9ce3b7a7f1aa3d8a633544a18a45bd9be870045295c0c2dbecd155e57cd3e621bce6086a865e5c13a689e81c1c5ee2548d3305d4b4393238b260c5332affe0fd2a49a3dcd1b7889b24d4f45866aefbf1da73c2d12a83a1cd8272b66daf6bc01b749de186e2f3c6bb1a33cf5a259c886766c18ec9cfbedee94901b7f656a5c5d9217eb917dbcba09fe29f1f4b0b2b3ba28f05ef75fe7ec0b1bb1d70ab2a0e6cf42eb781eefed74ff71dd92c7ff039211347a4d19292892f55593c4d3bdddfd8c9500a21ff808f108f6c6293d216da5cce1af05a7dc69fd250b06a7209c53d83f4ba0f0365c8da0e46d9b213fb91e23f201dc62e3b6aa8f3cb40eb92c27ce549b7fc9fa220f1683f12e6443bd69a1ab1e4c3db2f5a8237381f13e8635ad853bc3177c388030124e9e9459add9df9dfa817fdf56eb318c431de07fd4ed925cd9b59c207a4123931457a26437007c11bfa29ee0e7eaa6f6c6f6f52e7e57bc522f0acc60d49c9ca4d1dc6ef470224b94da8cfc2ee51d9a7a2acf9e84d3f1a0323aab563964c5a0acc74ce47379de203e499c4dedbc3a2704bd797fcda205c8098cb1ca9ad4930a343af1acd12b0b7bd674f20ace3e94326dd58487e82ff4ad773207d492ed55a64bd2d621b167ccf8072347eb9b4eac85fec12a8d61edcb040ce219aecf8cb451ed944d62466af48ed0ac9d4f762333b5be58ec323dd96035d56c9cd802bfe5feba5eeb2b629d4ac7957008b7a8a4a52fb3800576bf7e3edc89b9aa1b682d3a465cbe3cc2f768fb25c34fe12f262948e593678f9f2a5b298";
    private static final String jsBase64Sec = "AgMABhDY0gfxxRCXCULoWygoBoNVjmEqDanMEp5ybz831C67iW0UQ9vjPGZ7MNGhR1RMEW6uian9VaYVyITgg3Jd+uE4uVW+wroLOiQd4ph4OLDiO5h5EicToQnSmJMoQkoyjtFPqS/PsCFEH/MgjATTs1rmUeaUKUpEDFg1SkbFPLnhHPsKDZFZlMne5y/tctnTIPh9W0LOoqAe0vzQ+Amw8189drAuAWIkR2aM/K8GEUb+tGIqYCzhIzWnRd8Chps7MTG7jC+MGN7zFI6tMePTVk8uMcRD8ikUh9UHMqWFl+BUtj8YkG/iYDOJzeG34M8orD84nJB8aLHB/Ol17m8ZBLwObTEbN/umI0vV8sEQ4perqMmaOGZcfGSKWdX5q8uUCBgHM3Zs7xfj2XXBSkniSgCcM0WKTlh/olFtGnUTGL/G1jyMJsTL8QtKqZOM0I++1I8q0ai9PZgoxVSuJBm7kgxR6mOp7dobqw5sOQakfpckfSLOcB9LBOJGrjs9Qsol0cvGgP9ASUpay0378KkGT2jAfzUYo+GUgrX69mkdneEOPZjTVHUh0YWFqNcRl8ComcRvA6v0Iy9jWvOr0y6hP80dJZ+S/qJna2EnYzmkU17Q23H8xxCBpnY1f5Yj2onkAMHleOhLItABu0+ZTMAL6ThstnAofiXza1f/yXXStP/HvfRz04AhO26ug8V4UQOKHdZLjfzyHbwy1b+IHNjCaivLj/gdEJDSEWHAY1bcEd0fUUmu5tXBWrS1/KKdhXEqBY3P9HtJbQraUgNRXMLerxq/my81S77ZF6Dt4/BwsLSV4qRemjdrmSQ+IjHqYG755vDgO/g48FKxWKaCZNAX38gmSFn5dXB28W4zbj8+zV4UL0v921fsE5aBmQRRXYkNmaDFgUh8n4+zPZLCJ0bK/mS/fim7bddmb2XKpykUJNdyV22zVtl1NCAvmnjY3xlIAuboU5dy6zNmVooFKADxA2KuwN0buAaXKeGSZumKAJdnvjte29n0SocEmu6Vxs/we93g8Yi+c4aJrW2KBvTyVGTquN0l4sJlA99YVVDrmn18O15EHYR3VM7zDualJstdRZCzkr0DxSvmRYJgdR7PfgkKMZQzmGD8L9JABdJrTuPyFzS0ViqUq4hXU5B3Pl7oQ8Eq0Bp4odGBSXLE6/UtSaV/XpuA4Zj+RG5FpocF9ZEEvX/DGLseHqrI3+lFL0kylJpNOHg6sHhTl1PO/i5u81aFZvkuI2CvT3yyesl1j5OfiCPGAmAPZO4oS4fSyNp0s66/pISdppPFsqC8Lksia9/PJmKwG9Q9nlWKqDeNJ2TetaApX+Q7mh5Kc9JsSou3k5kHAnMSVLYtt0RNQ6YBWIDmEQigiA2q+TaFk4DslVJXEsFhLxhYcpJRaFP58wyJGzqxSIxorAtV0bZIRI3IagZWUNCqTO1rA1LaAKSYIWGlcAmJ7XyQayVKp3zKGHGpU8GidFouEOG8jZLpgA==";


    public static void run() {
        try {
            // Testing NTRU key generation
            long start = System.nanoTime();
            NTRUEncryptionKeyPairGenerator ntruEncryptionKeyPairGenerator = new NTRUEncryptionKeyPairGenerator();
            NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters = NTRUEncryptionKeyGenerationParameters.EES1171EP1;  // EES1087EP2; //EES743EP1
            ntruEncryptionKeyPairGenerator.init(ntruEncryptionKeyGenerationParameters);
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = ntruEncryptionKeyPairGenerator.generateKeyPair();
            NTRUEncryptionPrivateKeyParameters nstruSecret = (NTRUEncryptionPrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
            NTRUEncryptionPublicKeyParameters ntruPublic = (NTRUEncryptionPublicKeyParameters) asymmetricCipherKeyPair.getPublic();
            long time = System.nanoTime() - start;

            System.out.println(String.format("NTRU key (hex, [0-64]): %s", Util.bytes2hex(nstruSecret.getEncoded()).substring(0, 64)));
            System.out.println(String.format("Generation time: %s", time));
            System.out.println(String.format("Max message length: %s", ntruEncryptionKeyGenerationParameters.getMaxMessageLength()));

            // Testing NTRU encryption
            NTRUEngine ntru = new NTRUEngine();
            byte[] plainText = "test".getBytes();
            ntru.init(true, asymmetricCipherKeyPair.getPublic());
            byte[] encrypted = ntru.processBlock(plainText, 0, plainText.length);
            ntru.init(false, asymmetricCipherKeyPair.getPrivate());
            byte[] decrypted = ntru.processBlock(encrypted, 0, encrypted.length);
            System.out.println(String.format("NTRU encryption test passes: %s", Arrays.areEqual(plainText, decrypted)));
            System.out.println(String.format("NTRU public key length: %s", ntruPublic.getEncoded().length));
            System.out.println(String.format("NTRU private key length: %s", nstruSecret.getEncoded().length));

            // Testing NTRU encryption with reconstructed keys
            NTRUEncryptionPublicKeyParameters ntruEncryptionPublicKeyParameters = new NTRUEncryptionPublicKeyParameters(Util.hex2bytes(Util.bytes2hex(ntruPublic.getEncoded())), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());
            NTRUEncryptionPrivateKeyParameters ntruEncryptionPrivateKeyParameters = new NTRUEncryptionPrivateKeyParameters(Util.hex2bytes(Util.bytes2hex(nstruSecret.getEncoded())), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());

            ntru.init(true, ntruEncryptionPublicKeyParameters);
            encrypted = ntru.processBlock(plainText, 0, plainText.length);
            ntru.init(false, ntruEncryptionPrivateKeyParameters);
            decrypted = ntru.processBlock(encrypted, 0, encrypted.length);
            System.out.println(String.format("NTRU encryption test passes (reconstructed): %s", Arrays.areEqual(plainText, decrypted)));


            // Testing NTRU encryption with JS pub key
            NTRUEncryptionPublicKeyParameters ntruEncryptionPublicKeyParameters2 = new NTRUEncryptionPublicKeyParameters(Util.hex2bytes(jsBase64Pub), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());
////            NTRUEncryptionPrivateKeyParameters ntruEncryptionPrivateKeyParameters2 = new NTRUEncryptionPrivateKeyParameters(Util.base64ToBytes(jsBase64Sec), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());

            ntru.init(true, ntruEncryptionPublicKeyParameters2);
            encrypted = ntru.processBlock(plainText, 0, plainText.length);
            System.out.println(Util.bytes2hex(encrypted));
//            ntru.init(false, ntruEncryptionPrivateKeyParameters2);
//            decrypted = ntru.processBlock(encrypted, 0, encrypted.length);
//            System.out.println(String.format("NTRU encryption test passes (JS): %s", Arrays.areEqual(plainText, decrypted)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
