package com.onior.test.NewHope;

public class RAND {

    private static final int NK = 21;
    private static final int NJ = 6;
    private static final int NV = 8;
    private int[] ira = new int[NK];
    private int rndptr;
    private int borrow;
    private int pool_ptr;
    private byte[] pool = new byte[32];

    public RAND() {
        clean();
    }

    private int sbrand() {
        int i, k;
        long pdiff, t;

        rndptr++;
        if (rndptr < NK) return ira[rndptr];
        rndptr = 0;
        for (i = 0, k = NK - NJ; i < NK; i++, k++) {
            if (k == NK) k = 0;
            t = ((long) ira[k]) & 0xffffffffL;
            pdiff = (t - (((long) ira[i]) & 0xffffffffL) - (long) borrow) & 0xffffffffL;
            if (pdiff < t) borrow = 0;
            if (pdiff > t) borrow = 1;
            ira[i] = (int) (pdiff & 0xffffffffL);
        }

        return ira[0];
    }

    public void sirand(int seed) {
        int i, in;
        int t, m = 1;
        borrow = 0;
        rndptr = 0;
        ira[0] ^= seed;
        for (i = 1; i < NK; i++) {
            in = (NV * i) % NK;
            ira[in] ^= m;
            t = m;
            m = seed - m;
            seed = t;
        }
        for (i = 0; i < 10000; i++) sbrand();
    }

    private void fill_pool() {
        HASH256 sh = new HASH256();
        for (int i = 0; i < 128; i++) sh.process(sbrand());
        pool = sh.hash();
        pool_ptr = 0;
    }

    private static int pack(byte[] b) {
        return ((((int) b[3]) & 0xff) << 24) | (((int) b[2] & 0xff) << 16) | (((int) b[1] & 0xff) << 8) | ((int) b[0] & 0xff);
    }

    public void seed(int rawlen, byte[] raw) {
        int i;
        byte[] digest;
        byte[] b = new byte[4];
        HASH256 sh = new HASH256();
        pool_ptr = 0;
        for (i = 0; i < NK; i++) ira[i] = 0;
        if (rawlen > 0) {
            for (i = 0; i < rawlen; i++)
                sh.process(raw[i]);
            digest = sh.hash();

            for (i = 0; i < 8; i++) {
                b[0] = digest[4 * i];
                b[1] = digest[4 * i + 1];
                b[2] = digest[4 * i + 2];
                b[3] = digest[4 * i + 3];
                sirand(pack(b));
            }
        }
        fill_pool();
    }

    public void clean() {
        int i;
        pool_ptr = rndptr = 0;
        for (i = 0; i < 32; i++) pool[i] = 0;
        for (i = 0; i < NK; i++) ira[i] = 0;
        borrow = 0;
    }

    public int getByte() {
        int r;
        r = pool[pool_ptr++];
        if (pool_ptr >= 32) fill_pool();
        return (r & 0xff);
    }
}
