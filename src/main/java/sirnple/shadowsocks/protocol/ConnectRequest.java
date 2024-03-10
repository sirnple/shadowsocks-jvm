package sirnple.shadowsocks.protocol;

import java.util.Arrays;
import java.util.logging.Logger;

/**
 * <pre>
 * The SOCKS request is formed as follows:
 *
 *      +----+-----+-------+------+----------+----------+
 *      |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
 *      +----+-----+-------+------+----------+----------+
 *      | 1  |  1  | X'00' |  1   | Variable |    2     |
 *      +----+-----+-------+------+----------+----------+
 *
 *   Where:
 *
 *        o  VER    protocol version: X'05'
 *        o  CMD
 *           o  CONNECT X'01'
 *           o  BIND X'02'
 *           o  UDP ASSOCIATE X'03'
 *        o  RSV    RESERVED
 *        o  ATYP   address type of following address
 *           o  IP V4 address: X'01'
 *           o  DOMAINNAME: X'03'
 *           o  IP V6 address: X'04'
 *        o  DST.ADDR       desired destination address
 *        o  DST.PORT desired destination port in network octet
 *           order
 * </pre>
 */
public record ConnectRequest(byte ver, byte cmd, byte rsv, byte atyp, byte[] dstAddr, byte[] dstPort) {
    private static final Logger LOG = Logger.getLogger(ConnectRequest.class.getName());
    public static final int CONNECT_REQ_SIZE = 263; // 1 + 1 + 1 + 1 + 1 + 256 + 2

    public static ConnectRequest of(byte[] data) {
        LOG.fine("data: " + Arrays.toString(data));
        assert data.length == CONNECT_REQ_SIZE;
        final var ver = data[0];
        final var cmd = data[1];
        final var rsv = data[2];
        final var atyp = data[3];
        byte[] dstAddr;
        byte[] dstPort;
        if (atyp == 0x01) {
            assert data.length == 10;
            dstAddr = Arrays.copyOfRange(data, 4, 8);
            dstPort = Arrays.copyOfRange(data, 8, 10);
        } else if (atyp == 0x03) {
            assert data.length == 7 + data[4];
            dstAddr = Arrays.copyOfRange(data, 5, 5 + data[4]);
            dstPort = Arrays.copyOfRange(data, 5 + data[4], 7 + data[4]);
        } else if (atyp == 0x04) {
            assert data.length == 22;
            dstAddr = Arrays.copyOfRange(data, 4, 20);
            dstPort = Arrays.copyOfRange(data, 20, 22);
        } else {
            throw new IllegalArgumentException("unsupported atyp: " + atyp);
        }
        final var addrLen = data[4];
        return new ConnectRequest(ver, cmd, rsv, atyp, dstAddr, dstPort);
    }

    public ATYP getAtyp() {
        return ATYP.of(atyp);
    }
}
