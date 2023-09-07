import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

public class Tls {
    public static SSLContext getSslContext() {
        try {
            return SSLContext.getInstance("TLS");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void initialize(SSLContext sslContext, KeyManager[] keyManagers, TrustManager[] trustManagers) {
        try {
            sslContext.init(keyManagers, trustManagers, null);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        }
    }
}
