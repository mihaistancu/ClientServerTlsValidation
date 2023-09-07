import javax.net.ssl.HttpsURLConnection;

public class HttpGateway {

    public HttpsURLConnection getConnection(String destination, KeyStorePassPair configuration) {
//        SSLContext sslContext = Tls.getSslContext();
//
//        KeyManagerFactory keyManagerFactory = Keys.getKeyManagerFactory();
//        Keys.initialize(keyManagerFactory, configuration.getKeyStore(), configuration.getKeyStorePass().toCharArray());
//        KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
//        Tls.initialize(sslContext, keyManagers, new TrustManager[]{new TrustAllTrustManager()});
//
        HttpsURLConnection connection = (HttpsURLConnection) Channel.getUrlConnection(destination);
//        connection.setSSLSocketFactory(sslContext.getSocketFactory());
        Channel.setRequestMethod(connection, "POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        return connection;
    }
}
