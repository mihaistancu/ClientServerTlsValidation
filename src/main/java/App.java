import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;

import javax.net.ssl.HttpsURLConnection;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class App {
    public static void main(String[] args) throws Exception {
        if (args[0].equals("certs")) {
            Chain serverChain = createChain();

            KeyStore serverKeyStore = CertificateFactory.generateKeyStore(serverChain.leafKeyPair().getPrivate(), serverChain.leafCert(), "password");
            try(OutputStream outputStream = FileSystem.getFileOutputStream("server.jks")) {
                serverKeyStore.store(outputStream, "password".toCharArray());
            }

            KeyStore clientTrustStore = createJks(serverChain.rootCert(), serverChain.intermediateCert());
            try(OutputStream outputStream = FileSystem.getFileOutputStream("client-trust-store.jks")) {
                clientTrustStore.store(outputStream, "password".toCharArray());
            }

            Chain clientChain = createChain();

            KeyStore clientKeyStore = CertificateFactory.generateKeyStore(clientChain.leafKeyPair().getPrivate(), clientChain.leafCert(), "password");
            try(OutputStream outputStream = FileSystem.getFileOutputStream("client.jks")) {
                clientKeyStore.store(outputStream, "password".toCharArray());
            }

            KeyStore serverTrustStore = createJks(clientChain.rootCert(), clientChain.intermediateCert());
            try(OutputStream outputStream = FileSystem.getFileOutputStream("server-trust-store.jks")) {
                serverTrustStore.store(outputStream, "password".toCharArray());
            }
        }
        else if (args[0].equals("server")) {

            KeyStorePassPair keyStorePassPair = getKeyStorePassPair("server.jks");

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

            KeyStorePassPair keyStorePassPair = getKeyStorePassPair("client.jks");

            var gateway= new HttpGateway();
            HttpsURLConnection connection  = gateway.getConnection("https://localhost:8888/test", keyStorePassPair);
            byte[] bytes = connection.getInputStream().readAllBytes();
            System.out.println(new String(bytes));
        }
    }

    private static KeyStorePassPair getKeyStorePassPair(String path)
            throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStorePassPair keyStorePassPair = new KeyStorePassPair();
        KeyStore jks = KeyStore.getInstance("JKS");
        try (InputStream inputStream = FileSystem.getFileInputStream(path)) {
            jks.load(inputStream, "password".toCharArray());
        }
        keyStorePassPair.setKeyStore(jks);
        keyStorePassPair.setKeyStorePass("password");
        return keyStorePassPair;
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

    public static Chain createChain() throws Exception {
        KeyPair rootKeyPair = CertificateFactory.generateKeyPair();
        X509Certificate root = CertificateChainFactory.generateCertificate(
                "CN=root",
                rootKeyPair,
                "CN=root",
                rootKeyPair,
                true);
        FileSystem.write("root.cer", root.getEncoded());

        KeyPair intermediateKeyPair = CertificateFactory.generateKeyPair();
        X509Certificate intermediate = CertificateChainFactory.generateCertificate(
                "CN=intermediate",
                intermediateKeyPair,
                "CN=root",
                rootKeyPair,
                true);
        FileSystem.write("intermediate.cer", intermediate.getEncoded());

        KeyPair leafKeyPair = CertificateFactory.generateKeyPair();
        X509Certificate leaf = CertificateChainFactory.generateCertificate(
                "CN=localhost",
                leafKeyPair,
                "CN=intermediate",
                intermediateKeyPair,
                false,
                CertificateChainFactory.createExtendedKeyUsage(),
                CertificateChainFactory.createSubjectAlternativeNames());
        FileSystem.write("leaf.cer", leaf.getEncoded());

        return new Chain(rootKeyPair,root, intermediateKeyPair, intermediate, leafKeyPair, leaf);
    }

    public record Chain(KeyPair rootKeyPair, X509Certificate rootCert, KeyPair intermediateKeyPair, X509Certificate intermediateCert, KeyPair leafKeyPair, X509Certificate leafCert) {}
}
