package com.onior.test.NewHope;

public class SHA3 {
    private long length;
    private int rate, len;
    private long[][] S = new long[5][5];

    public SHA3(int olen) {
        init(olen);
    }

    public static final int HASH224 = 28;
    public static final int HASH256 = 32;
    public static final int HASH384 = 48;
    public static final int HASH512 = 64;

    public static final int SHAKE128 = 16;
    public static final int SHAKE256 = 32;

    public static final long[] RC = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808AL, 0x8000000080008000L,
            0x000000000000808BL, 0x0000000080000001L, 0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008AL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL, 0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L, 0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L};

    private static final int ROUNDS = 24;


    private static long rotl(long x, int n) {
        return (((x) << n) | ((x) >>> (64 - n)));
    }

    private void transform() {
        int i, j, k;
        long[] C = new long[5];
        long[] D = new long[5];
        long[][] B = new long[5][5];

        for (k = 0; k < ROUNDS; k++) {
            C[0] = S[0][0] ^ S[0][1] ^ S[0][2] ^ S[0][3] ^ S[0][4];
            C[1] = S[1][0] ^ S[1][1] ^ S[1][2] ^ S[1][3] ^ S[1][4];
            C[2] = S[2][0] ^ S[2][1] ^ S[2][2] ^ S[2][3] ^ S[2][4];
            C[3] = S[3][0] ^ S[3][1] ^ S[3][2] ^ S[3][3] ^ S[3][4];
            C[4] = S[4][0] ^ S[4][1] ^ S[4][2] ^ S[4][3] ^ S[4][4];

            D[0] = C[4] ^ rotl(C[1], 1);
            D[1] = C[0] ^ rotl(C[2], 1);
            D[2] = C[1] ^ rotl(C[3], 1);
            D[3] = C[2] ^ rotl(C[4], 1);
            D[4] = C[3] ^ rotl(C[0], 1);

            for (i = 0; i < 5; i++)
                for (j = 0; j < 5; j++)
                    S[i][j] ^= D[i];

            B[0][0] = S[0][0];
            B[1][3] = rotl(S[0][1], 36);
            B[2][1] = rotl(S[0][2], 3);
            B[3][4] = rotl(S[0][3], 41);
            B[4][2] = rotl(S[0][4], 18);

            B[0][2] = rotl(S[1][0], 1);
            B[1][0] = rotl(S[1][1], 44);
            B[2][3] = rotl(S[1][2], 10);
            B[3][1] = rotl(S[1][3], 45);
            B[4][4] = rotl(S[1][4], 2);

            B[0][4] = rotl(S[2][0], 62);
            B[1][2] = rotl(S[2][1], 6);
            B[2][0] = rotl(S[2][2], 43);
            B[3][3] = rotl(S[2][3], 15);
            B[4][1] = rotl(S[2][4], 61);

            B[0][1] = rotl(S[3][0], 28);
            B[1][4] = rotl(S[3][1], 55);
            B[2][2] = rotl(S[3][2], 25);
            B[3][0] = rotl(S[3][3], 21);
            B[4][3] = rotl(S[3][4], 56);

            B[0][3] = rotl(S[4][0], 27);
            B[1][1] = rotl(S[4][1], 20);
            B[2][4] = rotl(S[4][2], 39);
            B[3][2] = rotl(S[4][3], 8);
            B[4][0] = rotl(S[4][4], 14);

            for (i = 0; i < 5; i++)
                for (j = 0; j < 5; j++)
                    S[i][j] = B[i][j] ^ (~B[(i + 1) % 5][j] & B[(i + 2) % 5][j]);

            S[0][0] ^= RC[k];
        }
    }

    public void init(int olen) {
        int i, j;
        for (i = 0; i < 5; i++)
            for (j = 0; j < 5; j++)
                S[i][j] = 0;
        length = 0;
        len = olen;
        rate = 200 - 2 * olen;
    }

    public void process(int byt) {
        int i, j, b, cnt;
        cnt = (int) (length % rate);
        b = cnt % 8;
        cnt /= 8;
        i = cnt % 5;
        j = cnt / 5;
        S[i][j] ^= ((long) (byt & 0xff) << (8 * b));
        length++;
        if ((length % rate) == 0) transform();
    }

    public byte[] squeeze(byte[] buff, int olen) {
        boolean done;
        int i, j, k, m = 0;
        long el;
        done = false;
        for (; ; ) {
            for (j = 0; j < 5; j++) {
                for (i = 0; i < 5; i++) {
                    el = S[i][j];
                    for (k = 0; k < 8; k++) {
                        buff[m++] = (byte) (el & 0xff);
                        if (m >= olen || (m % rate) == 0) {
                            done = true;
                            break;
                        }
                        el >>>= 8;
                    }
                    if (done) break;
                }
                if (done) break;
            }
            if (m >= olen) break;
            done = false;
            transform();
        }
        return buff;
    }

    public void hash(byte[] digest) {
        int q = rate - (int) (length % rate);
        if (q == 1) process(0x86);
        else {
            process(0x06);
            while (length % rate != rate - 1) process(0x00);
            process(0x80);
        }
        squeeze(digest, len);
    }

    public void shake(byte[] digest, int olen) {
        int q = rate - (int) (length % rate);
        if (q == 1) process(0x9f);
        else {
            process(0x1f);
            while (length % rate != rate - 1) process(0x00);
            process(0x80);
        }
        squeeze(digest, olen);
    }
}