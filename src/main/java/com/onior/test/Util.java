package com.onior.test;

import org.bouncycastle.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Formatter;
import java.util.stream.Collectors;

public class Util {
    public static final byte[] salt = new byte[] { 22, 11 };

    public static String bytes2hex(byte[] bytes) {
        Formatter formatter = new Formatter();
        for (byte b : bytes) {
            formatter.format("%02x", b);
        }
        String string = formatter.toString();
        formatter.close();
        return string;
    }

    public static byte[] byteString2bytes(String s) {
        ArrayList<Integer> ints = new ArrayList<>();
        for (String c : s.split(",")) {
            ints.add(Integer.parseInt(c));
        }
        byte[] bytes = new byte[ints.size()];
        for (int i = 0; i < ints.size(); i++) {
            int tmp = ints.get(i) & 0xff;
            bytes[i] = (byte)((tmp & 0x80) == 0 ? tmp : tmp - 256);
        }
        return bytes;
    }

    public static byte[] hex2bytes(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    public static SecretKey createKey(String input) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(input.toCharArray(), salt, 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    public static String key2hex(SecretKey key) {
        return Util.bytes2hex(key.getEncoded());
    }

    public static byte[] base64ToBytes(String b64) throws UnsupportedEncodingException {
        return Base64.getDecoder().decode(b64.getBytes("UTF-8"));
    }

    public static String bytestoBase64(byte[] bytes) {
        return new String(Base64.getEncoder().encode(bytes));
    }

    public static byte[] base64ToBytes(String[] b64) throws UnsupportedEncodingException {
        byte[] result = new byte[0];
        for (String s : b64) {
            result = Arrays.concatenate(result, Base64.getDecoder().decode(s.getBytes("UTF-8")));
        }
        return result;
    }
}
