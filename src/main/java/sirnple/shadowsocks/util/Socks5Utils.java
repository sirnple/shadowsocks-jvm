package sirnple.shadowsocks.util;

import java.util.Arrays;

/**
 * Socket5 工具类
 *
 * @see <a href="https://tools.ietf.org/html/rfc1928">SOCKS Protocol Version 5</a>
 */
public interface Socks5Utils {
    /**
     * Socks5 UDP datagram
     * <pre>
     *  +----+------+------+----------+----------+----------+
     *  |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
     *  +----+------+------+----------+----------+----------+
     *  | 2  |  1   |  1   | Variable |    2     | Variable |
     *  +----+------+------+----------+----------+----------+
     * </pre>
     *
     * @param data
     * @return
     */
    static boolean isStandaloneUdpDatagram(byte[] data) {
        return data.length > 3 && data[2] == 0x00;
    }

    static byte[] removeUdpDatagramHeader(byte[] udpDatagram) {
        return Arrays.copyOfRange(udpDatagram, 3, udpDatagram.length);
    }

    static boolean isSocks5(byte[] data) {
        return data.length > 2 && data[0] == 0x05;
    }

    static boolean isFirstRequest(byte[] data) {
        return isSocks5(data) && data[1] == 0x01;
    }
}
