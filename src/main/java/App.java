import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

public class App {
    public static void main(String[] args) throws Exception {

        if (args[0].equals("server")) {

            KeyPair rootKeyPair = CertificateFactory.generateKeyPair();
            X509Certificate root = CertificateFactory.generateCertificate(rootKeyPair);
            FileSystem.write("root.cer", root.getEncoded());

            KeyPair intermediateKeyPair = CertificateFactory.generateKeyPair();
            X509Certificate intermediate = CertificateChainFactory.generateCertificate("CN=intermediate", intermediateKeyPair, root, rootKeyPair.getPrivate(), true);
            FileSystem.write("intermediate.cer", intermediate.getEncoded());

            KeyPair leafKeyPair = CertificateFactory.generateKeyPair();
            X509Certificate leaf = CertificateChainFactory.generateCertificate(
                    "CN=localhost",
                    leafKeyPair,
                    intermediate,
                    intermediateKeyPair.getPrivate(),
                    false,
                    CertificateChainFactory.createExtendedKeyUsage());
            FileSystem.write("leaf.cer", leaf.getEncoded());

            var keyStorePassPair = new KeyStorePassPair();
            KeyStore keyStore = CertificateFactory.generateKeyStore(leafKeyPair.getPrivate(), leaf, "password");
            keyStorePassPair.setKeyStore(keyStore);
            keyStorePassPair.setKeyStorePass("password");

            KeyStore trustedRoot = createJks(root, intermediate);
            try(OutputStream outputStream = FileSystem.getFileOutputStream("trusted.jks")) {
                trustedRoot.store(outputStream, "password".toCharArray());
            }

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
            HttpsURLConnection connection  = gateway.getConnection("https://localhost:8888/test", null);
            byte[] bytes = connection.getInputStream().readAllBytes();
            System.out.println(new String(bytes));
        }
    }

    private static KeyStore createJks(X509Certificate root, X509Certificate intermediate){
        KeyStore jks = Jks.getKeyStore();
        Jks.load(jks);
        try {
            jks.setCertificateEntry("root", root);
            jks.setCertificateEntry("intermediate", intermediate);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        return jks;
    }
}
