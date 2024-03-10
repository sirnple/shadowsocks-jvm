package sirnple.shadowsocks.util;

import sirnple.shadowsocks.protocol.ShadowSocksUdpPack;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetSocketAddress;

/**
 * shadowsocks5协议格式。
 *
 * <pre>
 * IPv4
 * +-------+---------+-------+-----+
 * | 1byte |  4byte  | 2byte |     |
 * +-------+---------+-------+-----+
 * | 0x01  | IPv4地址 |  端口  | 数据 |
 * +-------+---------+-------+-----+
 * ---
 * IPv6
 * +-------+---------+-------+-----+
 * | 1byte | 16byte  | 2byte |     |
 * +-------+---------+-------+-----+
 * | 0x04  | IPv6地址 |  端口  | 数据 |
 * +-------+---------+-------+-----+
 * ---
 * 不知道具体IP时，直接传输目标服务器域名
 * +-------+---------+-----+-------+-----+
 * | 1byte | 1byte   |     | 2byte |     |
 * +-------+---------+-----+-------+-----+
 * | 0x03  | 域名长度 | 域名 |  端口  | 数据 |
 * +-------+---------+-----+-------+-----+
 * </pre>
 *
 * @see <a href="https://www.ichenxiaoyu.com/ss/">ss</a>
 */
public interface ShadowSocksUtils {
    static byte[] packIpv4SS(byte[] ipv4Addr, byte[] port, byte[] data) {
        // 打包成ss的数据格式
        final var result = new byte[1 + 4 + 2 + data.length];
        result[0] = 0x01;
        System.arraycopy(result, 1, ipv4Addr, 0, 4);
        System.arraycopy(result, 5, port, 0, 2);
        System.arraycopy(result, 7, data, 0, data.length);
        return result;
    }

    static byte[] packSS(byte[] data, InetSocketAddress targetAddr) {
        // 打包成ss的数据格式
        final var address = targetAddr.getAddress();
        final var port = targetAddr.getPort();
        if (address instanceof Inet4Address) {
            final var ipv4Addr = address.getAddress();
            // ipv4
            final var result = new byte[1 + 4 + 2 + data.length];
            result[0] = 0x01;
            System.arraycopy(result, 1, ipv4Addr, 0, 4);
            result[5] = (byte) (port >> 8); // 高位
            result[6] = (byte) port; // 低位
            System.arraycopy(result, 7, data, 0, data.length);
            return result;
        }
        if (address instanceof Inet6Address) {
            final var ipv6Addr = address.getAddress();
            // ipv6
            final var result = new byte[1 + 16 + 2 + data.length];
            result[0] = 0x04;
            System.arraycopy(result, 1, ipv6Addr, 0, 16);
            result[17] = (byte) (port >> 8); // 高位
            result[18] = (byte) port; // 低位
            System.arraycopy(result, 19, data, 0, data.length);
            return result;
        }
        // 域名
        final var domain = address.getHostName().getBytes();
        final var result = new byte[1 + 1 + domain.length + 2 + data.length];
        result[0] = 0x03;
        result[1] = (byte) domain.length;
        System.arraycopy(result, 2, domain, 0, domain.length);
        result[2 + domain.length] = (byte) (port >> 8); // 高位
        result[3 + domain.length] = (byte) port; // 低位
        System.arraycopy(result, 4 + domain.length, data, 0, data.length);
        return result;
    }

    static byte[] extractDataFromSsUdpDatagram(byte[] ssUdpDatagram, InetSocketAddress targetAddr) {
        // 解包ss的数据格式
        final var atyp = ssUdpDatagram[0];
        if (atyp == 0x01) {
            // ipv4
            final var ipv4Addr = new byte[4];
            System.arraycopy(ssUdpDatagram, 1, ipv4Addr, 0, 4);
            final var port = (ssUdpDatagram[5] << 8) | (ssUdpDatagram[6] & 0xff);
            final var result = new byte[ssUdpDatagram.length - 7];
            System.arraycopy(ssUdpDatagram, 7, result, 0, result.length);
            return result;
        }
        if (atyp == 0x04) {
            // ipv6
            final var ipv6Addr = new byte[16];
            System.arraycopy(ssUdpDatagram, 1, ipv6Addr, 0, 16);
            final var port = (ssUdpDatagram[17] << 8) | (ssUdpDatagram[18] & 0xff);
            final var result = new byte[ssUdpDatagram.length - 19];
            System.arraycopy(ssUdpDatagram, 19, result, 0, result.length);
            return result;
        }
        // 域名
        final var domainLen = ssUdpDatagram[1];
        final var domain = new byte[domainLen];
        System.arraycopy(ssUdpDatagram, 2, domain, 0, domainLen);
        final var port = (ssUdpDatagram[2 + domainLen] << 8) | (ssUdpDatagram[3 + domainLen] & 0xff);
        final var result = new byte[ssUdpDatagram.length - 4 - domainLen];
        System.arraycopy(ssUdpDatagram, 4 + domainLen, result, 0, result.length);
        return result;
    }

    /**
     * 将ss的udp datagram打包成{@link ShadowSocksUdpPack}对象<br/>
     *
     * ss的udp datagram格式如下：
     * <pre>
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
     *
     * @param ssUdpDatagram
     * @return
     */
    static ShadowSocksUdpPack packFromDatagram(byte[] ssUdpDatagram) {
        // 解包ss的udp数据格式
        final var atyp = ssUdpDatagram[0];
        if (atyp == 0x01) {
            // ipv4
            final var dstAddr = new byte[4];
            System.arraycopy(ssUdpDatagram, 1, dstAddr, 0, 4);
            final var dstPort = (ssUdpDatagram[5] << 8) | (ssUdpDatagram[6] & 0xff);
            final var data = new byte[ssUdpDatagram.length - 7];
            System.arraycopy(ssUdpDatagram, 7, data, 0, data.length);
            return new ShadowSocksUdpPack(atyp, dstAddr, dstPort, data);
        }
        if (atyp == 0x04) {
            // ipv6
            final var dstAddr = new byte[16];
            System.arraycopy(ssUdpDatagram, 1, dstAddr, 0, 16);
            final var dstPort = (ssUdpDatagram[17] << 8) | (ssUdpDatagram[18] & 0xff);
            final var data = new byte[ssUdpDatagram.length - 19];
            System.arraycopy(ssUdpDatagram, 19, data, 0, data.length);
            return new ShadowSocksUdpPack(atyp, dstAddr, dstPort, data);
        }
        // 域名
        throw new UnsupportedOperationException("不支持的地址类型: " + atyp);
    }
}
