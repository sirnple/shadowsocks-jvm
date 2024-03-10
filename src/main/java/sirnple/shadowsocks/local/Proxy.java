package sirnple.shadowsocks.local;

import sirnple.shadowsocks.Config;
import sirnple.shadowsocks.crypto.Ciphers;
import sirnple.shadowsocks.crypto.Crypto;
import sirnple.shadowsocks.crypto.JavaCrypto;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class Proxy {
    private static final int BUFFER_SIZE = 65535;
    private final Config config;
    private final Crypto crypto;
    private final Ciphers cipherConfig;

    public Proxy(Config config) {
        this.config = config;
        this.crypto = new JavaCrypto(config.getPassword(), config.getMethod());
        this.cipherConfig = Ciphers.fromString(config.getMethod());
    }

    public void start() throws IOException {
        new Thread(new LocalTcpProxy(config)).start();
        new Thread(this::startUdp).start();
    }


    private void startUdp() {
        final var relay = new LocalUdpRelayHandler(config);
        new Thread(relay::relayToServer).start();
        new Thread(relay::relayToClient).start();
    }

    private byte[] packData(byte[] data, byte[] iv) {
        // pack format: [1字节标识iv长度] [4字节标识数据长度] [iv] [数据]
        // 因为pack format的规定，iv长度最大为1字节，即小于256
        if (iv.length > 255) {
            throw new IllegalArgumentException("iv length must less than " + 256);
        }
        // 因为pack format的规定，data最大长度为4字节，即小于65536
        if (data.length > 65535) {
            throw new IllegalArgumentException("data length must less than " + 65536);
        }
        final var result = new byte[1 + 4 + iv.length + data.length];
        result[0] = (byte) iv.length;
        final var dataLenInByteArray = ByteBuffer.allocate(Integer.BYTES).putInt(data.length).array();
        assert dataLenInByteArray.length == 4;
        System.arraycopy(dataLenInByteArray, 0, result, 1, 4);
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(data, 0, result, iv.length, data.length);
        return result;
    }


    private byte[] randomIv() {
        final var bytes = new byte[cipherConfig.getIvLenInByte()];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
