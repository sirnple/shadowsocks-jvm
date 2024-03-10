package sirnple.shadowsocks;

import java.io.File;
import java.util.Objects;
import java.util.Properties;

public final class Config {
    private final Properties config;

    private Config(String configFile) {
        config = new Properties();
        try {
            config.load(new File(configFile).toURI().toURL().openStream());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Config create(String configFile) {
        final var config = new Config(configFile);
        Objects.requireNonNull(config.getPassword());
        Objects.requireNonNull(config.getMethod());
        return config;
    }

    public String getServer() {
        return config.getProperty("server", "localhost");
    }

    public int getServerPort() {
        return Integer.parseInt(config.getProperty("server_port", "8388"));
    }

    public String getPassword() {
        return config.getProperty("password");
    }

    public String getMethod() {
        return config.getProperty("method");
    }

    public String getLocalAddress() {
        return config.getProperty("local_address", "0.0.0.0");
    }

    public int getLocalPort() {
        return Integer.parseInt(config.getProperty("local_port", "1080"));
    }
}
