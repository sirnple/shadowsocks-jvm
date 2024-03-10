package sirnple.shadowsocks;

/**
 * 处理上下行的数据。
 */
public interface UdpRelayHandler {
    int BUF_SIZE = 2048;
    /**
     * 上行数据，也就是作为服务端，接收未加密的数据，加密后转发数据。
     */
    void relayToServer();

    /**
     * 下行数据，也就是作为客户端，接收加密的数据，解密后转发数据。
     * @param datagramChannel 下行时的udp channel
     */
    void relayToClient();
}
