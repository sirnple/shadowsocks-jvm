package sirnple.shadowsocks.protocol;

/**
 * <pre>
 *    The client connects to the server, and sends a version
 *    identifier/method selection message:
 *
 *                    +----+----------+----------+
 *                    |VER | NMETHODS | METHODS  |
 *                    +----+----------+----------+
 *                    | 1  |    1     | 1 to 255 |
 *                    +----+----------+----------+
 *    If the selected METHOD is X'FF', none of the methods listed by the
 *    client are acceptable, and the client MUST close the connection.
 *
 *    The values currently defined for METHOD are:
 *
 *           o  X'00' NO AUTHENTICATION REQUIRED
 *           o  X'01' GSSAPI
 *           o  X'02' USERNAME/PASSWORD
 *           o  X'03' to X'7F' IANA ASSIGNED
 *           o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
 *           o  X'FF' NO ACCEPTABLE METHODS
 * </pre>
 */
public record AuthRequest(byte version, byte nmethods, byte[] methods) {
    public static AuthRequest of(byte[] data) {
        assert data.length >= 3;
        final var version = data[0];
        final var nmethods = data[1];
        final var methods = new byte[nmethods];
        System.arraycopy(data, 2, methods, 0, nmethods);
        return new AuthRequest(version, nmethods, methods);
    }
    public boolean isSocks5() {
        return version == 0x05;
    }

    public boolean isSupportNoAuth() {
        for (byte i = 0; i < nmethods; i++) {
            if (methods[i] == 0x00) {
                return true;
            }
        }
        return false;
    }

    public static final int AUTH_REQ_SIZE = 257; // 1 + 1 + 255
}