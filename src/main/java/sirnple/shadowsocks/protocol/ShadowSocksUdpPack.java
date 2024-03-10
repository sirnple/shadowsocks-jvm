package sirnple.shadowsocks.protocol;

public record ShadowSocksUdpPack(int atyp, byte[] dstAddr, int dstPort, byte[] data) {
    public static final int ATYP_IPV4 = 1;
    public static final int ATYP_DOMAIN = 3;
    public static final int ATYP_IPV6 = 4;
}
