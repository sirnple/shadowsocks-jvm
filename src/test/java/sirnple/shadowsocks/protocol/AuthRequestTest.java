package sirnple.shadowsocks.protocol;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthRequestTest {

    @Test
    void isSocks5_withSocks5Version_returnsTrue() {
        AuthRequest authRequest = new AuthRequest((byte) 0x05, (byte) 1, new byte[]{0x00});
        assertTrue(authRequest.isSocks5());
    }

    @Test
    void isSocks5_withNonSocks5Version_returnsFalse() {
        AuthRequest authRequest = new AuthRequest((byte) 0x04, (byte) 1, new byte[]{0x00});
        assertFalse(authRequest.isSocks5());
    }

    @Test
    void isSupportNoAuth_withNoAuthMethod_returnsTrue() {
        AuthRequest authRequest = new AuthRequest((byte) 0x05, (byte) 1, new byte[]{0x00});
        assertTrue(authRequest.isSupportNoAuth());
    }

    @Test
    void isSupportNoAuth_withNonNoAuthMethod_returnsFalse() {
        AuthRequest authRequest = new AuthRequest((byte) 0x05, (byte) 1, new byte[]{0x01});
        assertFalse(authRequest.isSupportNoAuth());
    }

    @Test
    void isSupportNoAuth_withMultipleMethods_returnsTrue() {
        AuthRequest authRequest = new AuthRequest((byte) 0x05, (byte) 2, new byte[]{0x00, 0x01});
        assertTrue(authRequest.isSupportNoAuth());
    }

    @Test
    void isSupportNoAuth_withMultipleMethodsNoAuth_returnsFalse() {
        AuthRequest authRequest = new AuthRequest((byte) 0x05, (byte) 2, new byte[]{0x01, 0x02});
        assertFalse(authRequest.isSupportNoAuth());
    }
}