import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class App {
    public static void main(String[] args) throws Exception {
        String path = System.getProperty("javax.net.ssl.keyStore");
        String password = System.getProperty("javax.net.ssl.keyStorePassword");
        KeyStorePassPair keyStorePassPair = getKeyStorePassPair(path, password);
        System.out.println("worked");

        if (args[0].equals("server")) {
            var builder = new JettyServerBuilder();
            builder.secure(keyStorePassPair);
            builder.host("localhost", 8888);

            builder.use("/*", new HttpServlet() {
                @Override protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
                    res.getOutputStream()
                       .write("hello".getBytes());
                }
            });
            Server server = builder.build();
            server.start();
        }
        else if (args[0].equals("client")){

            var gateway= new HttpGateway();
            HttpsURLConnection connection  = gateway.getConnection("https://localhost:8888/test", keyStorePassPair);
            byte[] bytes = connection.getInputStream().readAllBytes();
            System.out.println(new String(bytes));
        }
    }

    private static KeyStorePassPair getKeyStorePassPair(String path, String password)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStorePassPair keyStorePassPair = new KeyStorePassPair();
        KeyStore jks = KeyStore.getInstance("JKS");
        try (InputStream inputStream = FileSystem.getFileInputStream(path)) {
            jks.load(inputStream, password.toCharArray());
        }
        keyStorePassPair.setKeyStore(jks);
        keyStorePassPair.setKeyStorePass(password);
        return keyStorePassPair;
    }

}
