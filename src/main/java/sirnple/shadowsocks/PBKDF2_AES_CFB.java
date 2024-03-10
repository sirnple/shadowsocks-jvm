package sirnple.shadowsocks;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class PBKDF2_AES_CFB {

    public static void main(String[] args) throws Exception {
        // 待加密或解密的数据
        String data = "Hello World";
        // 密码
        String password = "123456";
        // 盐值，可以是随机数或者数据，长度必须是 8 字节
        String salt = "abcdef12";
        String salt1 = "abcdef13";
        // 迭代次数，越大越安全，但是速度越慢
        int iterationCount = 1000;
        // 密钥长度，必须是 128、192 或 256
        int keyLength = 256;
        // 初始向量，可以是随机数或者数据，长度必须是 16 字节
        final var iv1 = randomSalt();

        // 生成密钥
        final var aes = getSecretKeySpec(password, salt, iterationCount, keyLength);

        // 创建 Cipher 对象，指定算法为 AES/CFB/NoPadding
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");

        // 使用密钥和 IV 初始化加密模式
        cipher.init(Cipher.ENCRYPT_MODE, aes, new IvParameterSpec(iv1));

        // 使用 Cipher 对象的 doFinal 方法，传入明文的字节数组，得到加密后的字节数组
        byte[] encryptedData = cipher.doFinal(data.getBytes());

        // 输出加密结果（Base64）
        System.out.println("加密结果（Base64）：" + Base64.getEncoder().encodeToString(encryptedData));
        System.out.printf("加密结果长度：%s%n", encryptedData.length);

        // 使用密钥和 IV 初始化解密模式
        final var aes1 = getSecretKeySpec(password, salt1, iterationCount, keyLength);
        cipher.init(Cipher.DECRYPT_MODE, aes1, new IvParameterSpec(iv1));

        // 使用 Cipher 对象的 doFinal 方法，传入密文的字节数组，得到解密后的字节数组
        byte[] decryptedData = cipher.doFinal(encryptedData);

        // 输出解密结果
        System.out.println("解密结果：" + new String(decryptedData));
    }

    private static SecretKeySpec getSecretKeySpec(String password, String salt, int iterationCount, int keyLength) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterationCount, keyLength);
        SecretKey secretKey = factory.generateSecret(spec);
        final var aes = new SecretKeySpec(secretKey.getEncoded(), "AES");
        return aes;
    }

    private static byte[] randomSalt() {
        final var bytes = new byte[16];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }
}
