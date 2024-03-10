package sirnple.shadowsocks.local;

import sirnple.shadowsocks.Config;
import sirnple.shadowsocks.crypto.Crypto;
import sirnple.shadowsocks.crypto.JavaCrypto;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

public class LocalTcpProxy implements Runnable {
    private static final Logger LOG = Logger.getLogger(LocalTcpProxy.class.getName());
    private final ServerSocketChannel local;
    private final Crypto crypto;
    private final Map<InetSocketAddress, TcpHandler> cache = new HashMap<>();
    private final Map<InetSocketAddress, TcpHandler> cache1 = new HashMap<>();
    private final Config config;

    public LocalTcpProxy(Config config) {
        this.config = config;
        this.crypto = new JavaCrypto(config.getPassword(), config.getMethod());
        try {
            local = ServerSocketChannel.open();
            local.configureBlocking(false);
            local.bind(new InetSocketAddress(config.getLocalAddress(), config.getLocalPort()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    private void start() throws IOException {
        final var selector = Selector.open();
        local.register(selector, SelectionKey.OP_ACCEPT);
        while (true) {
            selector.select();
            final var selectionKeys = selector.selectedKeys();
            for (var iterator = selectionKeys.iterator(); iterator.hasNext(); ) {
                final var next = iterator.next();
                if (next.isAcceptable()) {
                    final var serverSocketChannel = (ServerSocketChannel) next.channel();
                    final var socketChannel = serverSocketChannel.accept();
                    if (socketChannel == null) {
                        continue;
                    }
                    socketChannel.configureBlocking(false);
//                    socketChannel.register(selector, SelectionKey.OP_READ);
                    final var remoteAddr = new InetSocketAddress(config.getServer(), config.getServerPort());
                    final var clientAddr = (InetSocketAddress) socketChannel.getRemoteAddress();
                    var tcpHandler = cache.computeIfAbsent(clientAddr, k -> new TcpHandler(remoteAddr, socketChannel, crypto));
                    try {
                        tcpHandler.doHandle();
                    } catch (Exception e) {
                        LOG.log(Level.WARNING, "doHandle error for client " + clientAddr, e);
                        continue;
                    }
                }
//                if (next.isReadable()) {
//                    final var socketChannel = (java.nio.channels.SocketChannel) next.channel();
//                    final var clientAddr = (InetSocketAddress) socketChannel.getRemoteAddress();
//                    final var tcpHandler = cache.get(clientAddr);
//                    try {
//                        Objects.requireNonNull(tcpHandler).doHandle();
//                    } catch (Exception e) {
//                        LOG.log(Level.WARNING, "doHandle error for client " + clientAddr, e);
//                        continue;
//                    }
//                }
                iterator.remove();
            }
        }
    }

    @Override
    public void run() {
        try {
            start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
