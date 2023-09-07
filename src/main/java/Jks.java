import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Jks {

    public static KeyStore getKeyStore() {
        try {
            return KeyStore.getInstance("JKS");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public static void load(KeyStore jks) {
        try {
            jks.load(null, null);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static void setKeyEntry(
            Key privateKey,
            X509Certificate certificate,
            char[] password,
            KeyStore jks) {
        try {
            jks.setKeyEntry("key", privateKey, password, new Certificate[]{ certificate });
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public static void load(KeyStore jks, InputStream inputStream, char[] password) {
        try {
            jks.load(inputStream, password);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static void store(KeyStore keyStore, String password, FileOutputStream outputStream) {
        try(outputStream) {
            keyStore.store(outputStream, password.toCharArray());
        }
        catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception);
        }
    }
}
