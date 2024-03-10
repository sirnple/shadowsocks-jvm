package sirnple.shadowsocks.local;

import sirnple.shadowsocks.crypto.Crypto;
import sirnple.shadowsocks.protocol.ATYP;
import sirnple.shadowsocks.protocol.AuthRequest;
import sirnple.shadowsocks.protocol.AuthResponse;
import sirnple.shadowsocks.protocol.ConnectRequest;
import sirnple.shadowsocks.protocol.ConnectResponse;
import sirnple.shadowsocks.protocol.EncryptedPacket;
import sirnple.shadowsocks.protocol.SessionState;
import sirnple.shadowsocks.protocol.ShadowSocksPacket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TcpHandler {
    private static final Logger LOG = Logger.getLogger(TcpHandler.class.getName());
    private final SocketChannel clientChannel;
    private SocketChannel tunnelChannel;
    private final boolean allowNoAuth = true;
    private Selector selector;
    private ATYP atyp;
    private byte[] dstAddr;
    private byte[] dstPort;
    private final Crypto crypto;

    private final InetSocketAddress remoteAddr;
    private SessionState sessionState = SessionState.INIT;
    private byte[] byteArray;
    private final InetSocketAddress clientAddr;

    public TcpHandler(InetSocketAddress remoteAddr, SocketChannel clientChannel, Crypto crypto) {
        this.remoteAddr = remoteAddr;
        try {
            this.clientAddr = (InetSocketAddress) clientChannel.getRemoteAddress();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        this.clientChannel = clientChannel;
        this.crypto = crypto;
    }
    public void doHandle() {
        if (sessionState == SessionState.INIT) {
            this.sessionState = SessionState.AUTH_REQUEST;
        }
        try {
            handle();
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "handle error for client " + clientAddr, e);
        }
    }

    private byte[] resolveDstAddr() {
        return dstAddr; // todo 这里好像应该是解析域名
    }

    private byte[] resolveDstPort() {
        return dstPort;
    }

    private void handle() {
        final var buf = ByteBuffer.allocate(ShadowSocksPacket.MAX_SIZE);
        try {
            selector = Selector.open();
            clientChannel.register(selector, SelectionKey.OP_READ);
            loopWhile:
            while (true) {
                selector.select();
                final var selectionKeys = selector.selectedKeys();
                for (var iterator = selectionKeys.iterator(); iterator.hasNext(); ) {
                    final var next = iterator.next();
                    if (!next.isValid()) {
                        continue;
                    }
                    if (next.isReadable()) {
                        buf.clear();
                        if (next.channel() == clientChannel) {
                            final var readCount = clientChannel.read(buf);
                            if (readCount == -1) {
                                tunnelChannel.close();
                                continue;
                            }
                            if (readCount == 0) {
                                LOG.warning("receive from client, readCount is 0, clientAddr: " + clientAddr);
                                continue;
                            }
                            switch (this.sessionState) {
                                case INIT -> throw new IllegalStateException("session state has not been initialized");
                                case AUTH_REQUEST -> {
                                    handleAuthRequest(buf);
                                    this.sessionState = SessionState.CONNECT_REQUEST;
                                    continue;
                                }
                                case CONNECT_REQUEST -> {
                                    handleConnectRequest(buf, readCount);
                                    this.sessionState = SessionState.FORWARDING;
                                    continue;
                                }
                                case FORWARDING -> {
                                    handleForwarding(buf, readCount);
                                    this.sessionState = SessionState.FORWARDING;
                                    continue;
                                }
                            }
                        }
                        if (next.channel() == tunnelChannel) {
                            final var readCount = tunnelChannel.read(buf);
                            if (readCount == -1) {
                                clientChannel.close();
                                this.sessionState = SessionState.INIT;
                                break loopWhile;
                            }
                            if (readCount == 0) {
                                LOG.warning("receive from remote, readCount is 0");
                                continue;
                            }
                            switch (this.atyp) {
                                case IPV4 -> {
                                    final var slice = buf.slice(0, readCount);
                                    final var bytes = new byte[readCount];
                                    slice.get(bytes);
                                    final var encryptedPacket = EncryptedPacket.of(bytes);
                                    final var decrypt = crypto.decrypt(encryptedPacket.encryptedPayload(), encryptedPacket.iv());
                                    clientChannel.write(ByteBuffer.wrap(decrypt));
                                    continue;
                                }
                                case DOMAIN -> throw new UnsupportedOperationException("not support domain");
                                case IPV6 -> throw new UnsupportedOperationException("not support ipv6");
                            }
                        }
                    }
                    iterator.remove();
                }
            }
        } catch (IOException e) {
            if (e.getMessage().equals("Connection reset")) {
                LOG.fine("Connection reset");
                try {
                    clientChannel.close();
                    if (tunnelChannel != null) {
                        tunnelChannel.close();
                    }
                } catch (IOException ex) {
                    LOG.log(Level.SEVERE, "close channel error", ex);
                }
                this.sessionState = SessionState.INIT;
            }
        }
    }

    private void handleForwarding(ByteBuffer buf, int readCount) throws IOException {
        switch (this.atyp) {
            case IPV4 -> {
                final var slice = buf.slice(0, readCount);
                final var bytes = new byte[readCount];
                slice.get(bytes);
                final var packet = ShadowSocksPacket.ipv4(this.dstAddr, this.dstPort, bytes);
                if (tunnelChannel == null) {
                    tunnelChannel = SocketChannel.open();
                    tunnelChannel.configureBlocking(false);
                    tunnelChannel.register(selector, SelectionKey.OP_READ);
                    tunnelChannel.connect(remoteAddr);
                    while (!tunnelChannel.finishConnect()) {
                        Thread.onSpinWait();
                    }
                }
                final var iv = crypto.generateIv();
                final var encrypt = crypto.encrypt(packet.toByteArray(), iv);
                byteArray = EncryptedPacket.of(iv.length, iv, encrypt).toByteArray();
                tunnelChannel.write(ByteBuffer.wrap(byteArray));
            }
            case DOMAIN -> throw new UnsupportedOperationException("not support domain");
            case IPV6 -> throw new UnsupportedOperationException("not support ipv6");
        }
    }

    private void handleConnectRequest(ByteBuffer buf, int readCount) {
        try {
            final var slice = buf.slice(0, readCount);
            final var bytes = new byte[readCount];
            slice.get(bytes);
            final var connectRequest = ConnectRequest.of(bytes);
            this.atyp = connectRequest.getAtyp();
            this.dstAddr = connectRequest.dstAddr();
            this.dstPort = connectRequest.dstPort();
            clientChannel.write(ByteBuffer.wrap(ConnectResponse.success(resolveDstAddr(), resolveDstPort()).toBytes()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private void handleAuthRequest(ByteBuffer buf) throws IOException {
        final var slice = buf.slice(2, buf.get(1));
        final var bytes = new byte[buf.get(1)];
        slice.get(bytes);
        final var authRequest = new AuthRequest(buf.get(0), buf.get(1), bytes);
        if (!authRequest.isSocks5()) {
            LOG.fine("not socks5");
            throw new UnsupportedOperationException("not socks5");
        }
        if (allowNoAuth && authRequest.isSupportNoAuth()) {
            LOG.fine("support no auth");
            clientChannel.write(ByteBuffer.wrap(AuthResponse.noAuth().toBytes()));
        }
    }
}
