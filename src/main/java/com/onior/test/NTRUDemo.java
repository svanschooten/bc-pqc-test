package com.onior.test;

import ntru.NTRU;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.crypto.ntru.*;
import org.bouncycastle.util.Arrays;

public class NTRUDemo {
    private static final String jsHexPubKey = "01030006049447b60d417fabad2d1d3f0b1d2512c4e9fcb7140a85bf85359559619cb64b4817572666d9764e54c0b10ded277742d917d405a5c7736fa8567a4ef30fa75ca2ecb441a574c07f8a34e6287949d0f90ccbed946d69909128fe2489ee4c814210ef5d8a554d4bd27d38180d9263b88057c804274865ac3c99a18fe3496b85f955d0f9677bbc1afee2c644df95bffd99f36d925e39e2050646e435c9ea5e14f76fb6f9977a1b1ae7c847b48f0846677d56dff85cb3bb73d1d1d77c89c99104e6cca30557c85423d5487eeaa4242e65378b26d9a3609a581d4c72d478c0719e3d3bf0076c17686d917204678b9726ae5922b378428559bb87820425ec012832f413bcd8dc1c2f30456d6b63228cd0f7ffa9634e917ef1ccd8ad5d30f0af229c64320dde450e0c5d1471e2242d5d98c4002e41efd7cf98dd4d0ffa83727ae73f51ad19bb0862d4eb80ad82ff26b6f5257e503896fcb159fc427fa1b4f8251264e4dfd8e79e687fdf0081592efb1d98a42d2cccb3755f156b236b8ea2d0c0b986f978f6744f6fff7dda61af2937cbeeb9d6b40044fb4f4f73280a4bb266fd873c081a76316a3bc1575ad18c656c2a3b5326ddfe23e72c0b80e192e207f3a81af383184335ad21ab08641117751607764048111c7b25945d7ca90979fafcdec96ab5c2d038e06194910b7213c3e8099b62895f7320e08ac3a5c8ee7d1c459e805b2302234946a438ff4ac2fb2e203a1a891471069689a1ab5a21f24e084a0cc264cfcc89d4ef45bd5da37323fa2488aa91b0b2b56bf3569ad519dc62a984a523d95754e2c05621b08634d48882e79d6fd14b6abf12c05c94f178c73b527bc50cef95eca3922af16c2a60da664aa25e5865b5b40d2de6c559cfef27b5be8aed54f336cd0633efa582c5043f1bcececf6d29af64fa9c23df58024fef169911c2040c660ecbe1ab6e78718aabc43f6ec3b4b45ce5329b902b81d8b4fe1384310defcab42d3fd1679ea9386d3a57a81277a1c4f50142eed205154d51bb053882963d2bd9b0b62f2a986316a9decfc62ebec8246c9b6f0ade89f00ff96a23ee06d779ac32d09fe0ac9b99ee2029acfec601f79a7ae12e77bd81feae6088415bd68f308283bf7344d9bd8ead9d2f59598352e56570c37982b13359fa0f0aa10f47c8679c8d558ffdee5c902438819ff76a5f72cd15c023f89de906bd80cf64e9cf70e18cec031cf764ae5ffacd14f8cf6553f13874e5a4debcca5f58cea7803b27da1cd730dc13755efa48f103eed95ff6a4644908c5da4c7c36be00939819922af43fed5ae552e28e49ecb501000a17f27076705472f66aac919c22913d804db1f8b862d6e5d556b4108e86312db71b3c766acfb63dbde7d102c56e953d43aafc05b404eff9098478a2d450c8a51eb4814d62ba95d872e599159c1a84ddd799a524171343e9b2c340ced4d98b4de1ddbf5e5d692b6332a0e51f30f53b6e37e856aec0e2b7390704b7319b25487c880f85eae673f879437f56408359894e61fad8a56a045cb62589c0eb0b065681eedb0372d7d4d6b1ab6042a85a09cdb7050054dab7df153431eaab77e0e2a2b9cb0d4e7da2ec53295c59717daafca3a0f042fba3b5fbdbc86c60c69c65d8befc7f09ab9bb0ff7e38015631197f291700c902814a560f62847905027891aee37bdc8e3d66181785b2e1ea8f82c108a96455ab5156926e71ff9353bee8ea68da4b6c21aaab2af8774c50ddc4f7964f1879cf576e08a562949413f1663b1fad40f224fc8865a70348f818f52954ea016552fcee59c783c4882af628f8dcc8063005b4d0a3072a6e743de9d839d9a1b13dac00b90c05a1cd90f967d1b11ae16072ea57f250e43f0785b3fad49559b4bddf5ec0b33576223970f99b01153e238c18abed103372d64e50bdc7680adfcb3b6e383f17658b16cdb1f5a4432714d01d1bd4b213e7d8ed532046a37afbb8db654bf1b67604aa1f73a1fdb6326b095b78584616603fc81d75a106ce42a2d41655f0630be95a69d5bdd5bf5d9fcce19deb1739bcba769be5df4887293eed92db76fc26cc2b35f490f67d1f8fdd39ff4d1e57bd7c4344144aa5d7b5da31d14c3b4c7de9d9ec51bf62b5713c23b6b55076b57125171901cfd408579575c74028c8228da93a1fbf8896e295ccf7ddf9d082102fec724c737a8511e30fd1db492fbde8276aa83b0ba1b67a0f170e1be8c8f1382c71d639713ca282dbc4d325fe3e2286b207f93ff1854d6615170ab75c401170ab9ceca480";
    private static final int[] intJsPub = {1,3,0,6,4,148,71,182,13,65,127,171,173,45,29,63,11,29,37,18,196,233,252,183,20,10,133,191,133,53,149,89,97,156,182,75,72,23,87,38,102,217,118,78,84,192,177,13,237,39,119,66,217,23,212,5,165,199,115,111,168,86,122,78,243,15,167,92,162,236,180,65,165,116,192,127,138,52,230,40,121,73,208,249,12,203,237,148,109,105,144,145,40,254,36,137,238,76,129,66,16,239,93,138,85,77,75,210,125,56,24,13,146,99,184,128,87,200,4,39,72,101,172,60,153,161,143,227,73,107,133,249,85,208,249,103,123,188,26,254,226,198,68,223,149,191,253,153,243,109,146,94,57,226,5,6,70,228,53,201,234,94,20,247,111,182,249,151,122,27,26,231,200,71,180,143,8,70,103,125,86,223,248,92,179,187,115,209,209,215,124,137,201,145,4,230,204,163,5,87,200,84,35,213,72,126,234,164,36,46,101,55,139,38,217,163,96,154,88,29,76,114,212,120,192,113,158,61,59,240,7,108,23,104,109,145,114,4,103,139,151,38,174,89,34,179,120,66,133,89,187,135,130,4,37,236,1,40,50,244,19,188,216,220,28,47,48,69,109,107,99,34,140,208,247,255,169,99,78,145,126,241,204,216,173,93,48,240,175,34,156,100,50,13,222,69,14,12,93,20,113,226,36,45,93,152,196,0,46,65,239,215,207,152,221,77,15,250,131,114,122,231,63,81,173,25,187,8,98,212,235,128,173,130,255,38,182,245,37,126,80,56,150,252,177,89,252,66,127,161,180,248,37,18,100,228,223,216,231,158,104,127,223,0,129,89,46,251,29,152,164,45,44,204,179,117,95,21,107,35,107,142,162,208,192,185,134,249,120,246,116,79,111,255,125,218,97,175,41,55,203,238,185,214,180,0,68,251,79,79,115,40,10,75,178,102,253,135,60,8,26,118,49,106,59,193,87,90,209,140,101,108,42,59,83,38,221,254,35,231,44,11,128,225,146,226,7,243,168,26,243,131,24,67,53,173,33,171,8,100,17,23,117,22,7,118,64,72,17,28,123,37,148,93,124,169,9,121,250,252,222,201,106,181,194,208,56,224,97,148,145,11,114,19,195,232,9,155,98,137,95,115,32,224,138,195,165,200,238,125,28,69,158,128,91,35,2,35,73,70,164,56,255,74,194,251,46,32,58,26,137,20,113,6,150,137,161,171,90,33,242,78,8,74,12,194,100,207,204,137,212,239,69,189,93,163,115,35,250,36,136,170,145,176,178,181,107,243,86,154,213,25,220,98,169,132,165,35,217,87,84,226,192,86,33,176,134,52,212,136,130,231,157,111,209,75,106,191,18,192,92,148,241,120,199,59,82,123,197,12,239,149,236,163,146,42,241,108,42,96,218,102,74,162,94,88,101,181,180,13,45,230,197,89,207,239,39,181,190,138,237,84,243,54,205,6,51,239,165,130,197,4,63,27,206,206,207,109,41,175,100,250,156,35,223,88,2,79,239,22,153,17,194,4,12,102,14,203,225,171,110,120,113,138,171,196,63,110,195,180,180,92,229,50,155,144,43,129,216,180,254,19,132,49,13,239,202,180,45,63,209,103,158,169,56,109,58,87,168,18,119,161,196,245,1,66,238,210,5,21,77,81,187,5,56,130,150,61,43,217,176,182,47,42,152,99,22,169,222,207,198,46,190,200,36,108,155,111,10,222,137,240,15,249,106,35,238,6,215,121,172,50,208,159,224,172,155,153,238,32,41,172,254,198,1,247,154,122,225,46,119,189,129,254,174,96,136,65,91,214,143,48,130,131,191,115,68,217,189,142,173,157,47,89,89,131,82,229,101,112,195,121,130,177,51,89,250,15,10,161,15,71,200,103,156,141,85,143,253,238,92,144,36,56,129,159,247,106,95,114,205,21,192,35,248,157,233,6,189,128,207,100,233,207,112,225,140,236,3,28,247,100,174,95,250,205,20,248,207,101,83,241,56,116,229,164,222,188,202,95,88,206,167,128,59,39,218,28,215,48,220,19,117,94,250,72,241,3,238,217,95,246,164,100,73,8,197,218,76,124,54,190,0,147,152,25,146,42,244,63,237,90,229,82,226,142,73,236,181,1,0,10,23,242,112,118,112,84,114,246,106,172,145,156,34,145,61,128,77,177,248,184,98,214,229,213,86,180,16,142,134,49,45,183,27,60,118,106,207,182,61,189,231,209,2,197,110,149,61,67,170,252,5,180,4,239,249,9,132,120,162,212,80,200,165,30,180,129,77,98,186,149,216,114,229,153,21,156,26,132,221,215,153,165,36,23,19,67,233,178,195,64,206,212,217,139,77,225,221,191,94,93,105,43,99,50,160,229,31,48,245,59,110,55,232,86,174,192,226,183,57,7,4,183,49,155,37,72,124,136,15,133,234,230,115,248,121,67,127,86,64,131,89,137,78,97,250,216,165,106,4,92,182,37,137,192,235,11,6,86,129,238,219,3,114,215,212,214,177,171,96,66,168,90,9,205,183,5,0,84,218,183,223,21,52,49,234,171,119,224,226,162,185,203,13,78,125,162,236,83,41,92,89,113,125,170,252,163,160,240,66,251,163,181,251,219,200,108,96,198,156,101,216,190,252,127,9,171,155,176,255,126,56,1,86,49,25,127,41,23,0,201,2,129,74,86,15,98,132,121,5,2,120,145,174,227,123,220,142,61,102,24,23,133,178,225,234,143,130,193,8,169,100,85,171,81,86,146,110,113,255,147,83,190,232,234,104,218,75,108,33,170,171,42,248,119,76,80,221,196,247,150,79,24,121,207,87,110,8,165,98,148,148,19,241,102,59,31,173,64,242,36,252,136,101,167,3,72,248,24,245,41,84,234,1,101,82,252,238,89,199,131,196,136,42,246,40,248,220,200,6,48,5,180,208,163,7,42,110,116,61,233,216,57,217,161,177,61,172,0,185,12,5,161,205,144,249,103,209,177,26,225,96,114,234,87,242,80,228,63,7,133,179,250,212,149,89,180,189,223,94,192,179,53,118,34,57,112,249,155,1,21,62,35,140,24,171,237,16,51,114,214,78,80,189,199,104,10,223,203,59,110,56,63,23,101,139,22,205,177,245,164,67,39,20,208,29,27,212,178,19,231,216,237,83,32,70,163,122,251,184,219,101,75,241,182,118,4,170,31,115,161,253,182,50,107,9,91,120,88,70,22,96,63,200,29,117,161,6,206,66,162,212,22,85,240,99,11,233,90,105,213,189,213,191,93,159,204,225,157,235,23,57,188,186,118,155,229,223,72,135,41,62,237,146,219,118,252,38,204,43,53,244,144,246,125,31,143,221,57,255,77,30,87,189,124,67,68,20,74,165,215,181,218,49,209,76,59,76,125,233,217,236,81,191,98,181,113,60,35,182,181,80,118,181,113,37,23,25,1,207,212,8,87,149,117,199,64,40,200,34,141,169,58,31,191,136,150,226,149,204,247,221,249,208,130,16,47,236,114,76,115,122,133,17,227,15,209,219,73,47,189,232,39,106,168,59,11,161,182,122,15,23,14,27,232,200,241,56,44,113,214,57,113,60,162,130,219,196,211,37,254,62,34,134,178,7,249,63,241,133,77,102,21,23,10,183,92,64,17,112,171,156,236,164,128};


    public static void run() {
        try {
            // Testing NTRU key generation
            long start = System.nanoTime();
            NTRUEncryptionKeyPairGenerator ntruEncryptionKeyPairGenerator = new NTRUEncryptionKeyPairGenerator();
            NTRUEncryptionKeyGenerationParameters ntruEncryptionKeyGenerationParameters = NTRUEncryptionKeyGenerationParameters.EES1171EP1; //EES1171EP1;  // EES1087EP2; //EES743EP1
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

            byte[] otherBytes = new byte[intJsPub.length];
            for (int i = 0; i < intJsPub.length; i++) {
                otherBytes[i] = (byte) intJsPub[i];
            }

            // Testing NTRU encryption with JS pub key
            NTRUEncryptionPublicKeyParameters ntruEncryptionPublicKeyParameters2 = new NTRUEncryptionPublicKeyParameters(Util.hex2bytes(jsHexPubKey), ntruEncryptionKeyGenerationParameters.getEncryptionParameters());
            NTRUEncryptionPublicKeyParameters ntruEncryptionPublicKeyParameters3 = new NTRUEncryptionPublicKeyParameters(otherBytes, NTRUEncryptionKeyGenerationParameters.EES1087EP2.getEncryptionParameters());

            boolean eqBytes0 = Arrays.areEqual(otherBytes, Util.hex2bytes(jsHexPubKey));
            boolean eqBytes1 = Arrays.areEqual(otherBytes, ntruEncryptionPublicKeyParameters2.getEncoded());
            boolean eqBytes2 = Arrays.areEqual(otherBytes, ntruEncryptionPublicKeyParameters3.getEncoded());
            boolean eqBytes3 = Arrays.areEqual(ntruEncryptionPublicKeyParameters2.getEncoded(), ntruEncryptionPublicKeyParameters3.getEncoded());
            System.out.println("imported bytes equal to hex bytes: " + eqBytes0);
            System.out.println("imported bytes equal to hex generated key: " + eqBytes1);
            System.out.println("imported bytes equal to byte generated key: " + eqBytes2);
            System.out.println("hex generated key equal to byte generated key: " + eqBytes3);

            ntru = new NTRUEngine();
            ntru.init(true, ntruEncryptionPublicKeyParameters2);
            encrypted = ntru.processBlock(plainText, 0, plainText.length);
            System.out.println("Hex based key used:");
            System.out.println(Util.bytes2hex(encrypted));

            ntru = new NTRUEngine();
            ntru.init(true, ntruEncryptionPublicKeyParameters3);
            encrypted = ntru.processBlock(plainText, 0, plainText.length);
            System.out.println("Byte based key used:");
            System.out.println(Util.bytes2hex(encrypted));
        } catch (Exception e) {
            e.printStackTrace();
        }

//        try {
//            NTRU.keyPair();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
    }
}
