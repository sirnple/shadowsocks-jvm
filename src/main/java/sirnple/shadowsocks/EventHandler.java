package sirnple.shadowsocks;

import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;

public interface EventHandler {
    void handle(SelectionKey key);
}
