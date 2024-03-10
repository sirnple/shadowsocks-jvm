package sirnple.shadowsocks.local;

import sirnple.shadowsocks.Config;
import sirnple.shadowsocks.UdpRelayHandler;
import sirnple.shadowsocks.crypto.Crypto;
import sirnple.shadowsocks.crypto.JavaCrypto;
import sirnple.shadowsocks.util.ArrayUtils;
import sirnple.shadowsocks.util.ShadowSocksUtils;
import sirnple.shadowsocks.util.Socks5Utils;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * 转发Udp包，两个方向 server <-> client。
 */
public class LocalUdpRelayHandler implements UdpRelayHandler {
    private static final Logger LOG = Logger.getLogger(LocalUdpRelayHandler.class.getName());
    private final DatagramChannel local; // 接收方
    private final Config config;
    private final String serverAddr;
    private final int serverPort;
    private final Crypto crypto;
    // 用于缓存源地址和对应的转发channel，后面用来接收response
    private final Map<InetSocketAddress, DatagramChannel> clientCache = new HashMap<>();

    public LocalUdpRelayHandler(Config config) {
        try {
            local = DatagramChannel.open();
            local.configureBlocking(false);
            local.socket().bind(new InetSocketAddress(config.getLocalAddress(), config.getLocalPort()));
            this.config = config;
            this.serverAddr = config.getServer();
            this.serverPort = config.getServerPort();
            this.crypto = new JavaCrypto(config.getPassword(), config.getMethod());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void relayToServer() {
        try {
            final var selector = Selector.open();
            local.register(selector, SelectionKey.OP_READ);
            while (true) {
                selector.select();
                final var selectionKeys = selector.selectedKeys();
                for (var iterator = selectionKeys.iterator(); iterator.hasNext(); ) {
                    final var next = iterator.next();
                    if (next.isReadable()) {
                        final var allocate = ByteBuffer.allocate(BUF_SIZE);
                        final var sourceSockAddr = (InetSocketAddress) local.receive(allocate);
                        if (!Socks5Utils.isStandaloneUdpDatagram(allocate.array())) {
                            LOG.warning("Drop the datagram since not a standalone UDP datagram");
                            return;
                        }
                        final var ssUdpDatagram = Socks5Utils.removeUdpDatagramHeader(allocate.array());
                        final var ssUdpPack = ShadowSocksUtils.packFromDatagram(ssUdpDatagram);
                        // 加密转发
                        final var iv = crypto.generateIv();
                        final var merge = ArrayUtils.merge(iv, crypto.encrypt(ssUdpDatagram, iv));
                        final var sendBytes = ByteBuffer.wrap(merge);

                        final var client = DatagramChannel.open().bind(new InetSocketAddress(serverAddr, serverPort));
                        clientCache.put(sourceSockAddr, client);
                        client.write(sendBytes);
                    }
                    iterator.remove();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void relayToClient() {

    }
}
