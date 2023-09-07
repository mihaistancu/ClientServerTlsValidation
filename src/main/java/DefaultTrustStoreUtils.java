import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public final class DefaultTrustStoreUtils {
    private static KeyPair rootCAKeyPair;
    private static String rootCAName;

    private DefaultTrustStoreUtils() {
    }

    public static KeyStore loadDefaultTrustStore() {
        Path location = null;
        String type = null;
        String password = null;

        String locationProperty = System.getProperty("javax.net.ssl.trustStore");
        if ((null != locationProperty) && (locationProperty.length() > 0)) {
            Path p = Paths.get(locationProperty);
            File f = p.toFile();
            if (f.exists() && f.isFile() && f.canRead()) {
                location = p;
            }
        } else {
            String javaHome = System.getProperty("java.home");
            location = Paths.get(javaHome, "lib", "security", "jssecacerts");
            if (!location.toFile().exists()) {
                location = Paths.get(javaHome, "lib", "security", "cacerts");
            }
        }

        String passwordProperty = System.getProperty("javax.net.ssl.trustStorePassword");
        if ((null != passwordProperty) && (passwordProperty.length() > 0)) {
            password = passwordProperty;
        } else {
            password = "changeit";
        }

        String typeProperty = System.getProperty("javax.net.ssl.trustStoreType");
        if ((null != typeProperty) && (typeProperty.length() > 0)) {
            type = passwordProperty;
        } else {
            type = KeyStore.getDefaultType();
        }

        KeyStore trustStore = null;
        try {
            trustStore = KeyStore.getInstance(type, Security.getProvider("SUN"));
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

        try (InputStream is = Files.newInputStream(location)) {
            trustStore.load(is, password.toCharArray());
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return trustStore;
    }

    public static void setRootCAKeyPair(KeyPair value) {
        rootCAKeyPair = value;
    }
    public static KeyPair getRootCAKeyPair() {
        return rootCAKeyPair;
    }

    public static String getRootCAName() {
        return rootCAName;
    }

    public static void setRootCAName(String value) {
        rootCAName = value;
    }



    public static void ImportCertificateToTrustCertStore(X509Certificate certificate, String alias) throws Exception {

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

        String javaHome = System.getProperty("java.home");
        Path location = Paths.get(javaHome, "lib", "security", "cacerts");
        try (InputStream is = Files.newInputStream(location)) {
            keystore.load(is, null);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        // Add the certificate
        keystore.setCertificateEntry(alias, certificate);

        // Save the new keystore contents
        try (OutputStream os = Files.newOutputStream(location)) {
            keystore.store(os, null);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate getCertificateFromJksStore(String alias) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

        String javaHome = System.getProperty("java.home");
        Path location = Paths.get(javaHome, "lib", "security", "cacerts");
        try (InputStream is = Files.newInputStream(location)) {
            keystore.load(is, null);
            return (X509Certificate) keystore.getCertificate(alias);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String deleteCertificateFromJksStore(String alias) throws Exception {
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());

        String javaHome = System.getProperty("java.home");
        Path location = Paths.get(javaHome, "lib", "security", "cacerts");
        try (InputStream is = Files.newInputStream(location)) {
            keystore.load(is, null);
            keystore.deleteEntry(alias);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        try (FileOutputStream os = new FileOutputStream(String.valueOf(location))) {
            keystore.store(os, null);
            os.flush();
            // ks.store(null);
            return alias;
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
