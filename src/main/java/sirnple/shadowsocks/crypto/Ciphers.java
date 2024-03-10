package sirnple.shadowsocks.crypto;

public enum Ciphers {
    AES_128_CFB("aes-128-cfb", 16, 16),
    AES_192_CFB("aes-192-cfb", 24, 16),
    AES_256_CFB("aes-256-cfb", 32, 16),
    AES_128_CFB8("aes-128-cfb8", 16, 16),
    AES_192_CFB8("aes-192-cfb8", 24, 16),
    AES_256_CFB8("aes-256-cfb8", 32, 16),
    AES_128_CFB1("aes-128-cfb1", 16, 16),
    AES_192_CFB1("aes-192-cfb1", 24, 16),
    AES_256_CFB1("aes-256-cfb1", 32, 16),
    AES_128_OFB("aes-128-ofb", 16, 16),
    AES_192_OFB("aes-192-ofb", 24, 16),
    AES_256_OFB("aes-256-ofb", 32, 16),
    AES_128_CTR("aes-128-ctr", 16, 16),
    AES_192_CTR("aes-192-ctr", 24, 16),
    AES_256_CTR("aes-256-ctr", 32, 16),
    AES_128_GCM("aes-128-gcm", 16, 16),
    AES_192_GCM("aes-192-gcm", 24, 16),
    AES_256_GCM("aes-256-gcm", 32, 16),
    AES_128_OCB("aes-128-ocb", 16, 16),
    AES_192_OCB("aes-192-ocb", 24, 16),
    AES_256_OCB("aes-256-ocb", 32, 16),
    BF_CFB("bf-cfb", 16, 8),
    CAMELLIA_128_CFB("camellia-128-cfb", 16, 16),
    CAMELLIA_192_CFB("camellia-192-cfb", 24, 16),
    CAMELLIA_256_CFB("camellia-256-cfb", 32, 16),
    CAST5_CFB("cast5-cfb", 16, 8),
    DES_CFB("des-cfb", 8, 8),
    IDEA_CFB("idea-cfb", 16, 8),
    RC2_CFB("rc2-cfb", 16, 8),
    RC4("rc4", 16, 0),
    SEED_CFB("seed-cfb", 16, 16);

    private final String method;
    private final int keyLenInByte;
    private final int ivLenInByte;

    Ciphers(String method, int keyLenInByte, int ivLenInByte) {
        this.method = method;
        this.keyLenInByte = keyLenInByte;
        this.ivLenInByte = ivLenInByte;
    }

    public static Ciphers fromString(String method) {
        for (Ciphers c : Ciphers.values()) {
            if (c.method.equals(method.toLowerCase())) {
                return c;
            }
        }
        throw new IllegalArgumentException("Unsupported method: " + method);
    }

    public String getMethod() {
        return method;
    }

    public int getKeyLenInByte() {
        return keyLenInByte;
    }

    public int getIvLenInByte() {
        return ivLenInByte;
    }
}
