package sirnple.shadowsocks.protocol;

public enum ATYP {
    IPV4(0x01),
    DOMAIN(0x03),
    IPV6(0x04);

    private final byte value;

    ATYP(int value) {
        this.value = (byte) value;
    }

    public byte getValue() {
        return value;
    }

    public static ATYP of(byte value) {
        return switch (value) {
            case 0x01 -> IPV4;
            case 0x03 -> DOMAIN;
            case 0x04 -> IPV6;
            default -> throw new IllegalArgumentException("unsupported atyp: " + value);
        };
    }
}
