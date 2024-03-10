package sirnple.shadowsocks.protocol;

public enum SessionState {
    INIT,
    AUTH_REQUEST,
    AUTH_RESPONSE,
    CONNECT_REQUEST,
    CONNECT_RESPONSE,
    FORWARDING,
    DESTROY
}
