import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

import javax.net.ssl.KeyManagerFactory;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

public class Keys {
    public static KeyPairGenerator getKeyPairGenerator() {
        try {
            return KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey getPrivateKey(KeyFactory kf, byte[] bytes) {
        try {
            return kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey getPublicKey(KeyFactory keyFactory, RSAPublicKeySpec spec) {
        try {
            return keyFactory.generatePublic(spec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static ASN1Primitive readObject(ASN1InputStream inputStream) {
        try {
            return inputStream.readObject();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyManagerFactory getKeyManagerFactory() {
        try {
            return KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void initialize(KeyManagerFactory keyManagerFactory, KeyStore keyStore, char[] password) {
        try {
            keyManagerFactory.init(keyStore, password);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
