package sirnple.shadowsocks;

import sirnple.shadowsocks.local.LocalUdpRelayHandler;
import sirnple.shadowsocks.crypto.Crypto;
import sirnple.shadowsocks.crypto.JavaCrypto;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Iterator;

public class Server {
    private static final int BUFFER_SIZE = 65535;
    private final Config config;

    private final Crypto crypto;

    public Server(Config config) {
        this.config = config;
        this.crypto = new JavaCrypto(config.getPassword(), config.getMethod());
    }

    public void start() throws IOException {
        final var open = ServerSocketChannel.open();
        open.configureBlocking(false);
        open.bind(new InetSocketAddress(config.getLocalAddress(), config.getLocalPort()));
        final var selector = Selector.open();
        open.register(selector, SelectionKey.OP_ACCEPT);
        while (true) {
            selector.select();
            final var selectionKeys = selector.selectedKeys();
            for (Iterator<SelectionKey> iterator = selectionKeys.iterator(); iterator.hasNext(); ) {
                SelectionKey next = iterator.next();
                if (next.isAcceptable()) {
                    final var serverSocketChannel = (ServerSocketChannel) next.channel();
                    final var socketChannel = serverSocketChannel.accept();
                    socketChannel.configureBlocking(false);
                    socketChannel.register(selector, SelectionKey.OP_READ);
                }
                if (next.isReadable()) {
                    final var socketChannel = (SocketChannel) next.channel();
                    socketChannel.configureBlocking(false);
                    final var buffer = ByteBuffer.allocate(BUFFER_SIZE); // client发过来的数据由于加上了iv，故会超过buffer_size，这里需要处理
                    socketChannel.read(buffer);
                    socketChannel.write(buffer);
//                    final var udpRelayHandler = new LocalUdpRelayHandler(config.getServer(), config.getServerPort());
//                    udpRelayHandler.relay(crypto.decrypt(buffer.array()));
                }
                iterator.remove();
            }
        }
    }
}
