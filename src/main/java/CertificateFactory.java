import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

public class CertificateFactory {
    private final static String PASSWORD = "password";

    public static KeyPair generateKeyPair() {
        KeyPairGenerator keyGen = Keys.getKeyPairGenerator();
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();
    }

    public static KeyStore generateKeyStore(Key privateKey, X509Certificate certificate, String password) {
        KeyStore jks = Jks.getKeyStore();
        Jks.load(jks);
        Jks.setKeyEntry(privateKey, certificate, password.toCharArray(), jks);
        return jks;
    }

    public static KeyStorePassPair generateKeyStorePassPair(Key privateKey, X509Certificate certificate) {
        return new KeyStorePassPair(
                generateKeyStore(privateKey, certificate, PASSWORD),
                PASSWORD);
    }

    public static X509Certificate generateCertificate(KeyPair keyPair) {
        Instant now = Instant.now();
        Date notBefore = Date.from(now);
        Date notAfter = Date.from(now.plus(Duration.ofDays(365)));
        X500Name x500Name = new X500Name("CN=localhost");
        BigInteger serial = BigInteger.valueOf(now.toEpochMilli());

        SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        DigestCalculator digestCalculator = Digest.getDigestCalculator(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        SubjectKeyIdentifier subjectKeyId = new X509ExtensionUtils(digestCalculator).createSubjectKeyIdentifier(publicKeyInfo);
        AuthorityKeyIdentifier authorityKeyId = new X509ExtensionUtils(digestCalculator).createAuthorityKeyIdentifier(publicKeyInfo);

        var builder = new JcaX509v3CertificateBuilder(x500Name, serial, notBefore, notAfter, x500Name, keyPair.getPublic());
        X509.addExtension(builder, Extension.subjectKeyIdentifier, false, subjectKeyId);
        X509.addExtension(builder, Extension.authorityKeyIdentifier, false, authorityKeyId);
        X509.addExtension(builder, Extension.basicConstraints, true, new BasicConstraints(true));

        JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder("SHA256WithRSAEncryption");
        ContentSigner contentSigner = X509.build(keyPair, contentSignerBuilder);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());
        return X509.getCertificate(builder, contentSigner, converter);
    }

    public static void generateKeyStore(String keyStorePath, String password) {
        KeyPair tlsKeyPair = CertificateFactory.generateKeyPair();
        X509Certificate tlsCertificate = CertificateFactory.generateCertificate(tlsKeyPair);
        KeyStore tls = CertificateFactory.generateKeyStore(tlsKeyPair.getPrivate(), tlsCertificate, password);
        Jks.store(tls, password, FileSystem.getFileOutputStream(keyStorePath));
    }

    public static void generateCertificateAndKey(String certificatePath, String keyPath) {
        KeyPair ebmsKeyPair = CertificateFactory.generateKeyPair();
        X509Certificate ebmsCertificate = CertificateFactory.generateCertificate(ebmsKeyPair);
        FileSystem.write(certificatePath, X509.getEncoded(ebmsCertificate));
        FileSystem.write(keyPath, ebmsKeyPair.getPrivate().getEncoded());
    }

    public static X509Certificate from(String base64) {
        byte[] cert = Base64.getDecoder().decode(base64);
        return (X509Certificate) X509.generateCertificate(X509.getCertificateFactory(), new ByteArrayInputStream(cert));
    }
}
