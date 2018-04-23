package io.bumo.encryption.utils.hash;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Sha256 {
    MessageDigest messageDigest;

    public Sha256() {
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public Sha256(byte[] start) {
        this();
        add(start);
    }

    public Sha256 add(byte[] bytes) {
        messageDigest.update(bytes);
        return this;
    }

    public Sha256 add32(int i) {
        messageDigest.update((byte) ((i >>> 24) & 0xFF));
        messageDigest.update((byte) ((i >>> 16) & 0xFF));
        messageDigest.update((byte) ((i >>> 8)  & 0xFF));
        messageDigest.update((byte) ((i)        & 0xFF));
        return this;
    }

    private byte[] finishTaking(int size) {
        byte[] hash = new byte[size];
        System.arraycopy(messageDigest.digest(), 0, hash, 0, size);
        return hash;
    }

    public byte[] finish128() {
        return finishTaking(16);
    }

    public byte[] finish256() {
        return finishTaking(32);
    }

    public byte[] finish() {
        return messageDigest.digest();
    }
}
