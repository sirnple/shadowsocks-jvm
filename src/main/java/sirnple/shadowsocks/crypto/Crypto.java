package sirnple.shadowsocks.crypto;

public interface Crypto {
    byte[] encrypt(byte[] data, byte[] iv);

    byte[] decrypt(byte[] data, byte[] iv);

    byte[] generateIv();
}
