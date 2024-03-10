package sirnple.shadowsocks.remote;

import sirnple.shadowsocks.Config;
import sirnple.shadowsocks.crypto.JavaCrypto;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.logging.Logger;

public class UdpRelayHandler implements sirnple.shadowsocks.UdpRelayHandler {
    private static final Logger LOG = Logger.getLogger(UdpRelayHandler.class.getName());
    private final Config config;
    private final DatagramChannel listenSocket;
    private final JavaCrypto crypto;

    public UdpRelayHandler(Config config) {
        this.config = config;
        this.crypto = new JavaCrypto(config.getPassword(), config.getMethod());
        try {
            this.listenSocket = DatagramChannel.open();
            this.listenSocket.bind(new InetSocketAddress(config.getServer(), config.getServerPort()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void relayToServer() {
        try {
            final var recvBytes = ByteBuffer.allocate(BUF_SIZE);
            final var receive = listenSocket.receive(recvBytes);
            if (receive == null) {
                LOG.fine("UDP has no data");
                return;
            }

            final var array = recvBytes.array();
            final var iv = recvBytes.slice(0, crypto.getIvLength()).array();
            final var encryptedData = recvBytes.slice(crypto.getIvLength(), recvBytes.remaining());
            final var packedData = crypto.decrypt(encryptedData.array(), iv);
            final var remoteAddress = (InetSocketAddress) listenSocket.getRemoteAddress();
//            ShadowSocksUtils.extractDataFromSsUdpDatagram(packedData)


            // 解密时，需要知道iv，故这里需要将iv和加密后的数据一起发送
//            final var sendBytes = ByteBuffer.wrap(ArrayUtils.merge(iv, encryptBytes));
//            listenSocket.send(sendBytes, remoteAddress);
        } catch (IOException e) {
            LOG.severe("Drop the packet because of " + e.getMessage());
            LOG.throwing(UdpRelayHandler.class.getName(), "handleUpStream", e);
        }

    }

    @Override
    public void relayToClient() {

    }
}
