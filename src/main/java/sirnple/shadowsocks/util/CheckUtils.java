package sirnple.shadowsocks.util;

public interface CheckUtils {
    static void checkRange(int value, int min, int max) {
        if (value <= min || value > max) {
            throw new IllegalArgumentException("value " + value + " not in range [" + min + ", " + max + ")");
        }
    }
}
