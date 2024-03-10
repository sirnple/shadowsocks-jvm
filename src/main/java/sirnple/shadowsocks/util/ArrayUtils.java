package sirnple.shadowsocks.util;

public interface ArrayUtils {
    public static byte[] merge(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }
        byte[] result = new byte[length];
        int index = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, index, array.length);
            index += array.length;
        }
        return result;
    }

    public static void checkRange(int value, int min, int max) {
        if (value < min || value > max) {
            throw new IllegalArgumentException("value " + value + " not in range [" + min + ", " + max + "]");
        }
    }
}
