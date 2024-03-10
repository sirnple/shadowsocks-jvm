package sirnple.shadowsocks.remote;

import sirnple.shadowsocks.crypto.Crypto;
import sirnple.shadowsocks.protocol.EncryptedPacket;
import sirnple.shadowsocks.protocol.ShadowSocksPacket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.logging.Logger;

public class TcpHandler {
    private static final Logger LOG = Logger.getLogger(TcpHandler.class.getName());
    private final Crypto crypto;

    public TcpHandler(Crypto crypto) {
        this.crypto = crypto;
    }

    public void doHandle(SocketChannel tunnelChannel) {
        try {
            final var selector = Selector.open();
            tunnelChannel.register(selector, SelectionKey.OP_READ);
            SocketChannel serverChannel = null;
            final var buf = ByteBuffer.allocate(EncryptedPacket.MAX_SIZE);
            loopWhile:
            while (true) {
                selector.select();
                final var selectionKeys = selector.selectedKeys();
                for (var iterator = selectionKeys.iterator(); iterator.hasNext(); ) {
                    final var next = iterator.next();
                    if (next.isReadable()) {
                        final var channel = (SocketChannel) next.channel();
                        buf.clear();
                        final var readCount = channel.read(buf);
                        if (readCount == -1) {
                            if (channel == tunnelChannel) {
                                LOG.fine("tunnelChannel closed");
                                serverChannel.close();
                                break;
                            } else {
                                LOG.fine("serverChannel closed");
                                tunnelChannel.close();
                                break loopWhile;
                            }
                        }
                        final var slice = buf.slice(0, readCount);
                        final var bytes = new byte[readCount];
                        slice.get(bytes);
                        if (tunnelChannel == channel) {
                            final var encryptedPacket = EncryptedPacket.of(bytes);
                            final var decryptedPayload = crypto.decrypt(encryptedPacket.encryptedPayload(), encryptedPacket.iv());
                            final var shadowSocksPacket = ShadowSocksPacket.of(decryptedPayload);
                            if (serverChannel == null) {
                                serverChannel = SocketChannel.open();
                                serverChannel.configureBlocking(false);
                                serverChannel.connect(new InetSocketAddress(InetAddress.getByAddress(shadowSocksPacket.dstAddr()), shadowSocksPacket.dstPort()));
                                serverChannel.register(selector, SelectionKey.OP_READ);
                            }
                            while (!serverChannel.finishConnect()) {
                                Thread.onSpinWait();
                            }
                            serverChannel.write(ByteBuffer.wrap(shadowSocksPacket.data()));
                        } else {
                            final var iv = crypto.generateIv();
                            final var encryptedPayload = crypto.encrypt(bytes, iv);
                            final var encryptedPacket = EncryptedPacket.of(iv.length, iv, encryptedPayload);
                            tunnelChannel.write(ByteBuffer.wrap(encryptedPacket.toByteArray()));
                        }
                    }
                    iterator.remove();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
