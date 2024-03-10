package sirnple.shadowsocks.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class JavaCrypto implements Crypto {
    private final String password;
    private final Ciphers cipherConfig;
    private final Cipher cipher;

    public int getIvLength() {
        return ivLength;
    }

    private final int ivLength;

    @Override
    public String toString() {
        return "JavaCrypto{" +
            "password='" + password + '\'' +
            ", cipherConfig=" + cipherConfig +
            '}';
    }

    public JavaCrypto(String password, String method) {
        this.password = password;
        this.cipherConfig = Ciphers.fromString(method);
        this.cipher = getCipher();
        this.ivLength = this.cipherConfig.getIvLenInByte();
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] iv) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, generateKey(), new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException |
                 InvalidKeyException e) {
            throw new RuntimeException(e);
        }

    }

    @Override
    public byte[] decrypt(byte[] data, byte[] iv) {
        try {
            cipher.init(Cipher.DECRYPT_MODE, generateKey(), new IvParameterSpec(iv));
            return cipher.doFinal(data);
        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException |
                 BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] generateIv() {
        return randomIv();
    }

    private SecretKey generateKey() {
        final var pbeKeySpec = new PBEKeySpec(password.toCharArray(), fixedSalt(), 1000, cipherConfig.getKeyLenInByte() * 8);
        final SecretKeyFactory keyFactory;
        try {
            keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final var derivedKey = keyFactory.generateSecret(pbeKeySpec);
            return new SecretKeySpec(derivedKey.getEncoded(), getAlgorithm());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] fixedSalt() {
        // todo use a random salt for security
        return new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    }

    private byte[] randomIv() {
        final var bytes = new byte[cipherConfig.getIvLenInByte()];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private String getAlgorithm() {
        return switch (this.cipherConfig) {
            case AES_128_CFB8, AES_256_CFB1, AES_192_CFB1, AES_128_CFB1, AES_256_CFB8, AES_192_CFB8, AES_192_CFB, AES_192_OFB, AES_192_CTR, AES_192_GCM, AES_192_OCB, AES_256_CFB, AES_256_OFB, AES_256_CTR, AES_256_GCM, AES_256_OCB, AES_128_CFB, AES_128_OFB, AES_128_CTR, AES_128_GCM, AES_128_OCB ->
                "AES";
            case BF_CFB -> "Blowfish";
            case CAMELLIA_128_CFB, CAMELLIA_192_CFB, CAMELLIA_256_CFB -> "Camellia";
            case CAST5_CFB -> "CAST5";
            case DES_CFB -> "DES";
            case IDEA_CFB -> "IDEA";
            case RC2_CFB -> "RC2";
            case RC4 -> "RC4";
            case SEED_CFB -> "SEED";
        };
    }

    private Cipher getCipher() {
        return switch (this.cipherConfig) {
            case AES_128_CFB, AES_192_CFB, AES_256_CFB, AES_128_CFB1, AES_192_CFB1, AES_256_CFB1, AES_128_CFB8, AES_192_CFB8, AES_256_CFB8 -> {
                try {
                    yield Cipher.getInstance("AES/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case AES_128_OFB, AES_192_OFB, AES_256_OFB -> {
                try {
                    yield Cipher.getInstance("AES/OFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case AES_128_CTR, AES_192_CTR, AES_256_CTR -> {
                try {
                    yield Cipher.getInstance("AES/CTR/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case AES_128_GCM, AES_192_GCM, AES_256_GCM -> {
                try {
                    yield Cipher.getInstance("AES/GCM/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case AES_128_OCB, AES_192_OCB, AES_256_OCB -> {
                try {
                    yield Cipher.getInstance("AES/OCB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case BF_CFB -> {
                try {
                    yield Cipher.getInstance("Blowfish/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case CAMELLIA_128_CFB, CAMELLIA_192_CFB, CAMELLIA_256_CFB -> {
                try {
                    yield Cipher.getInstance("Camellia/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case CAST5_CFB -> {
                try {
                    yield Cipher.getInstance("CAST5/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case DES_CFB -> {
                try {
                    yield Cipher.getInstance("DES/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case IDEA_CFB -> {
                try {
                    yield Cipher.getInstance("IDEA/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case RC2_CFB -> {
                try {
                    yield Cipher.getInstance("RC2/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case RC4 -> {
                try {
                    yield Cipher.getInstance("RC4");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
            case SEED_CFB -> {
                try {
                    yield Cipher.getInstance("SEED/CFB/NoPadding");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                }
            }
        };
    }
}
