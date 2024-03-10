package sirnple.shadowsocks.crypto;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.*;

class JavaCryptoTest {
    private Crypto crypto = new JavaCrypto("pass", "aes-256-cfb");

    @Test
    void testEncryptAndDecrypt_Successfully() {
        final var data = randomBytes();
        final var iv = crypto.generateIv();
        final var encryptedData = crypto.encrypt(data, iv);
        final var decryptData = crypto.decrypt(encryptedData, iv);
        assertEquals(Arrays.toString(data), Arrays.toString(decryptData));
    }

    private byte[] randomBytes() {
        final var random = new Random();
        final var bytes = new byte[random.nextInt(1000)];
        random.nextBytes(bytes);
        return bytes;
    }
}