package sirnple.shadowsocks.protocol;

/**
 * <pre>
 *    The server selects from one of the methods given in METHODS, and
 *    sends a METHOD selection message:
 *
 *                          +----+--------+
 *                          |VER | METHOD |
 *                          +----+--------+
 *                          | 1  |   1    |
 *                          +----+--------+
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
public record AuthResponse(byte version, byte method) {
    public static AuthResponse noAuth() {
        return new AuthResponse((byte) 0x05, (byte) 0x00);
    }

    public boolean isSocks5() {
        return version == 0x05;
    }

    public byte[] toBytes() {
        return new byte[]{version, method};
    }
}
