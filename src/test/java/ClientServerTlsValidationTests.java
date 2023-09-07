import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class ClientServerTlsValidationTests {

    private Chain serverChain;
    private Chain clientChain;
    private KeyStore serverKeyStore;
    private KeyStore clientTrustStore;
    private KeyStore clientKeyStore;
    private KeyStore serverTrustStore;

    @Before
    public void init() throws Exception {
        serverChain = createChain();
        clientChain = createChain();
    }

    @Test
    public void trustRootsAndIntermediates() throws Exception {
        serverKeyStore = CertificateFactory.generateKeyStore(serverChain.leafKeyPair().getPrivate(), serverChain.leafCert(), "password");
        clientTrustStore = createJks(serverChain.rootCert(), serverChain.intermediateCert());
        clientKeyStore = CertificateFactory.generateKeyStore(clientChain.leafKeyPair().getPrivate(), clientChain.leafCert(), "password");
        serverTrustStore = createJks(clientChain.rootCert(), clientChain.intermediateCert());

        runServerAndClient();
    }

    @Test
    public void trustIntermediates() throws Exception {
        serverKeyStore = CertificateFactory.generateKeyStore(serverChain.leafKeyPair().getPrivate(), serverChain.leafCert(), "password");
        clientTrustStore = createJks(serverChain.intermediateCert());
        clientKeyStore = CertificateFactory.generateKeyStore(clientChain.leafKeyPair().getPrivate(), clientChain.leafCert(), "password");
        serverTrustStore = createJks(clientChain.intermediateCert());

        runServerAndClient();
    }

    private void runServerAndClient() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException, InterruptedException {
        save(serverKeyStore, "server.jks", "password");
        save(clientTrustStore, "client-trust-store.jks", "password");
        save(clientKeyStore, "client.jks", "password");
        save(serverTrustStore, "server-trust-store.jks", "password");

        JavaProcess server = new JavaProcess(
                "-Djavax.net.ssl.keyStore=server.jks",
                "-Djavax.net.ssl.keyStorePassword=password",
                "-Djavax.net.ssl.trustStore=server-trust-store.jks",
                "-Djavax.net.ssl.trustStorePassword=password", "-cp",
                "target/ClientServerTlsValidation-1.0-SNAPSHOT.jar;target/dependency/*", "App", "server");

        Thread.sleep(1000);

        var client = new JavaProcess(
                "-Djavax.net.ssl.keyStore=client.jks",
                "-Djavax.net.ssl.keyStorePassword=password",
                "-Djavax.net.ssl.trustStore=client-trust-store.jks",
                "-Djavax.net.ssl.trustStorePassword=password", "-cp",
                "target/ClientServerTlsValidation-1.0-SNAPSHOT.jar;target/dependency/*", "App", "client");

        client.waitToFinish();

        server.stop();
    }

    private void save(KeyStore serverKeyStore, String path, String password) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        try(OutputStream outputStream = FileSystem.getFileOutputStream(path)) {
            serverKeyStore.store(outputStream, password.toCharArray());
        }
    }

    private static KeyStore createJks(X509Certificate... certs){
        KeyStore jks = Jks.getKeyStore();
        Jks.load(jks);
        try {
            for (X509Certificate cert : certs) {
                jks.setCertificateEntry(cert.getSubjectX500Principal().getName(), cert);
            }
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
