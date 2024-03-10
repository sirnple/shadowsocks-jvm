package sirnple.shadowsocks.remote;

import sirnple.shadowsocks.Config;
import sirnple.shadowsocks.crypto.Crypto;
import sirnple.shadowsocks.crypto.JavaCrypto;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;

public class RemoteTcpProxy implements Runnable {
    private final Config config;
    private final ServerSocketChannel remote;
    private final Crypto crypto;

    public RemoteTcpProxy(Config config) {
        this.config = config;
        try {
            remote = ServerSocketChannel.open();
            remote.configureBlocking(false);
            remote.bind(new InetSocketAddress(config.getServer(), config.getServerPort()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        crypto = new JavaCrypto(config.getPassword(), config.getMethod());
    }

    private void start() throws IOException {
        final var selector = Selector.open();
        remote.register(selector, SelectionKey.OP_ACCEPT);
        while (true) {
            selector.select();
            final var selectionKeys = selector.selectedKeys();
            for (var iterator = selectionKeys.iterator(); iterator.hasNext(); ) {
                final var next = iterator.next();
                if (next.isAcceptable()) {
                    final var serverSocketChannel = (ServerSocketChannel) next.channel();
                    final var socketChannel = serverSocketChannel.accept();
                    socketChannel.configureBlocking(false);
                    socketChannel.register(selector, SelectionKey.OP_READ);
                    new TcpHandler(crypto).doHandle(socketChannel);
                }
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
