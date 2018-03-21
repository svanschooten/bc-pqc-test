package ntru;

public class KeyPair {

    public byte[] publicKey;
    public byte[] privateKey;

    public KeyPair(byte[] a, byte[] b) {
        this.publicKey = a;
        this.privateKey = b;
    }
}
