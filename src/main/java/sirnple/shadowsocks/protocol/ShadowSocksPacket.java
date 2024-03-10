package sirnple.shadowsocks.protocol;

import java.nio.ByteBuffer;

/**
 * <pre>
 *     ShadowSocks协议:
 *     +------+----------+----------+----------+
 *     | ATYP | DST.ADDR | DST.PORT |   DATA   |
 *     +------+----------+----------+----------+
 *     |  1   | Variable |    2     | Variable |
 *     +------+----------+----------+----------+
 *     ATYP     地址类型，0x01表示IPv4，0x03表示域名，0x04表示IPv6，1字节
 *     DST.ADDR 目标地址，IPv4地址4字节，IPv6地址16字节
 *     DST.PORT 目标端口，2字节
 *     DATA     数据，长度不定
 * </pre>
 */
public record ShadowSocksPacket(ATYP atyp, byte[] dstAddr, int dstPort, byte[] data) {
    public static final int MAX_SIZE = 65535;

    public static ShadowSocksPacket ipv4(byte[] dstAddr, byte[] dstPort, byte[] data) {
        assert dstPort.length == 2;
        return new ShadowSocksPacket(ATYP.IPV4, dstAddr, (dstPort[0] << 8) | (dstPort[1] & 0xff), data);
    }

    public static ShadowSocksPacket ipv6(byte[] dstAddr, byte[] dstPort, byte[] data) {
        assert dstPort.length == 2;
        return new ShadowSocksPacket(ATYP.IPV6, dstAddr, (dstPort[0] << 8) | (dstPort[1] & 0xff), data);
    }

    public static ShadowSocksPacket domain(byte[] dstAddr, byte[] dstPort, byte[] data) {
        assert dstPort.length == 2;
        return new ShadowSocksPacket(ATYP.DOMAIN, dstAddr, (dstPort[0] << 8) | (dstPort[1] & 0xff), data);
    }
    public static ShadowSocksPacket of(byte[] data) {
        assert data.length == MAX_SIZE;
        switch (ATYP.of(data[0])) {
            case IPV4 -> {
                byte[] dstAddr = new byte[4];
                System.arraycopy(data, 1, dstAddr, 0, 4);
                byte[] dstPort = new byte[2];
                System.arraycopy(data, 5, dstPort, 0, 2);
                byte[] payload = new byte[data.length - 7];
                System.arraycopy(data, 7, payload, 0, payload.length);
                return ipv4(dstAddr, dstPort, payload);
            }
            case DOMAIN -> {
                int domainLen = data[1];
                byte[] domain = new byte[domainLen];
                System.arraycopy(data, 2, domain, 0, domainLen);
                byte[] dstPort = new byte[2];
                System.arraycopy(data, 2 + domainLen, dstPort, 0, 2);
                byte[] payload = new byte[data.length - 4 - domainLen];
                System.arraycopy(data, 4 + domainLen, payload, 0, payload.length);
                return domain(domain, dstPort, payload);
            }
            case IPV6 -> {
                byte[] dstAddr = new byte[16];
                System.arraycopy(data, 1, dstAddr, 0, 16);
                byte[] dstPort = new byte[2];
                System.arraycopy(data, 17, dstPort, 0, 2);
                byte[] payload = new byte[data.length - 19];
                System.arraycopy(data, 19, payload, 0, payload.length);
                return ipv6(dstAddr, dstPort, payload);
            }
            case null, default -> throw new IllegalArgumentException("unsupported atyp: " + data[0]);
        }
    }

    public byte[] toByteArray() {
        byte[] result = new byte[1 + dstAddr.length + 2 + data.length];
        result[0] = atyp.getValue();
        final var buf = ByteBuffer.allocate(Short.BYTES);
        buf.putShort((short) dstPort);
        byte[] dstPort = buf.array();
        switch (atyp) {
            case IPV4 -> {
                System.arraycopy(dstAddr, 0, result, 1, 4);
                System.arraycopy(dstPort, 0, result, 5, 2);
                System.arraycopy(data, 0, result, 7, data.length);
            }
            case DOMAIN -> {
                result[1] = (byte) dstAddr.length;
                System.arraycopy(dstAddr, 0, result, 2, dstAddr.length);
                System.arraycopy(dstPort, 0, result, 2 + dstAddr.length, 2);
                System.arraycopy(data, 0, result, 4 + dstAddr.length, data.length);
            }
            case IPV6 -> {
                System.arraycopy(dstAddr, 0, result, 1, 16);
                System.arraycopy(dstPort, 0, result, 17, 2);
                System.arraycopy(data, 0, result, 19, data.length);
            }
        }
        return result;
    }
}
