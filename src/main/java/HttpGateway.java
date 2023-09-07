import javax.net.ssl.*;

public class HttpGateway {

    public HttpsURLConnection getConnection(String destination, KeyStorePassPair configuration) {
        SSLContext sslContext = Tls.getSslContext();

        KeyManagerFactory keyManagerFactory = Keys.getKeyManagerFactory();
        Keys.initialize(keyManagerFactory, configuration.getKeyStore(), configuration.getKeyStorePass().toCharArray());
        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

        //TrustManager[] trustManagers = new TrustManager[]{new TrustAllTrustManager()};

        Tls.initialize(sslContext, keyManagers, null);

        HttpsURLConnection connection = (HttpsURLConnection) Channel.getUrlConnection(destination);
        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        Channel.setRequestMethod(connection, "GET");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        return connection;
    }
}
