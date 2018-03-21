package ntru;

import java.io.File;

public class NTRU {
    static {
        File ntru_test = new File("lib/" + System.mapLibraryName("ntru_test"));
        System.load(ntru_test.getAbsolutePath());
        File ntruencrypt = new File("lib/" + System.mapLibraryName("ntruencrypt"));
        System.load(ntruencrypt.getAbsolutePath());
    }

    /** Decrypts cyphertext with privateKey. */
    public static native byte[] decrypt(byte[] encrypted, byte[] privateKey);

    /** Encrypts plaintext with publicKey. */
    public static native byte[] encrypt(byte[] message, byte[] publicKey);

    /** Generates key pair. */
    public static native void keyPair();

    /** Retrieve public key*/
    public static native byte[] publicKey();

    /** Retrieve private key*/
    public static native byte[] privateKey();
}
