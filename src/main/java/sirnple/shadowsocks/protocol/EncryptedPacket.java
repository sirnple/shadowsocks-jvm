package sirnple.shadowsocks.protocol;

import sirnple.shadowsocks.util.CheckUtils;

/**
 * <pre>
 *     +--------+----------+---------------------------------------+
 *     | IV.LEN |    IV    |   Decrypted Payload                   |
 *     +------------+-------+--------------------------------------+
 *     |  1     | Variable |   Variable                            |
 *     +--------+----------+---------------------------------------+
 *                         |       ShadowSocksPacket               |
 *                         +------+----------+----------+----------+
 *                         | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *                         +------+----------+----------+----------+
 *                         |  1   | Variable |    2     | Variable |
 *                         +------+----------+----------+----------+
 *     ATYP     地址类型，0x01表示IPv4，0x03表示域名，0x04表示IPv6，1字节
 *     DST.ADDR 目标地址，IPv4地址4字节，IPv6地址16字节
 *     DST.PORT 目标端口，2字节
 *     DATA     数据，长度不定
 * </pre>
 */
public record EncryptedPacket(int ivLen, byte[] iv, byte[] encryptedPayload) {
    public static final int MAX_SIZE = 4096;

    public static EncryptedPacket of(int ivLen, byte[] iv, byte[] encryptedPayload) {
        CheckUtils.checkRange(ivLen, 1, 255);
        return new EncryptedPacket(ivLen, iv, encryptedPayload);
    }
    public static EncryptedPacket of(byte[] data) {
        assert data.length == MAX_SIZE;
        byte ivLen = data[0];
        byte[] iv = new byte[ivLen];
        System.arraycopy(data, 1, iv, 0, ivLen);
        byte[] encryptedPayload = new byte[data.length - 1 - ivLen];
        System.arraycopy(data, 1 + ivLen, encryptedPayload, 0, encryptedPayload.length);
        return new EncryptedPacket(ivLen, iv, encryptedPayload);
    }

    public byte[] toByteArray() {
        byte[] result = new byte[1 + iv.length + encryptedPayload.length];
        if (ivLen >= 1 && ivLen <= 127) {
            result[0] = (byte) ivLen;
        }
        if (ivLen >= 128 && ivLen <= 255) {
            result[0] = (byte) (ivLen - 128);
        }
        System.arraycopy(iv, 0, result, 1, iv.length);
        System.arraycopy(encryptedPayload, 0, result, 1 + iv.length, encryptedPayload.length);
        return result;
    }
}
