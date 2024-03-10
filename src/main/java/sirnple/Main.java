package sirnple;

import sirnple.shadowsocks.Config;
import sirnple.shadowsocks.local.LocalTcpProxy;
import sirnple.shadowsocks.remote.RemoteTcpProxy;

public class Main {
    public static void main(String[] args) {
        new Thread(new RemoteTcpProxy(Config.create("shadowsocks.properties"))).start();
        new Thread(new LocalTcpProxy(Config.create("shadowsocks.properties"))).start();
    }
}