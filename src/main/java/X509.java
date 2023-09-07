import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.CertificateFactory;
import java.security.cert.*;

public class X509 {

    public static X509Certificate getCertificate(
            JcaX509v3CertificateBuilder builder,
            ContentSigner contentSigner,
            JcaX509CertificateConverter converter) {
        try {
            return converter.getCertificate(builder.build(contentSigner));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static CertificateFactory getCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static X509Certificate getCertificate(CertificateFactory certificateFactory, InputStream inputStream) {
        try {
            return (X509Certificate) certificateFactory.generateCertificate(inputStream);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] getEncoded(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static void addExtension(
            X509v3CertificateBuilder builder,
            ASN1ObjectIdentifier oid,
            boolean isCritical,
            ASN1Encodable value) {
        try {
            builder.addExtension(oid, isCritical, value);
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Certificate generateCertificate(CertificateFactory factory, InputStream stream) {
        try {
            return factory.generateCertificate(stream);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static ContentSigner build(KeyPair keyPair, JcaContentSignerBuilder contentSignerBuilder) {
        try {
            return contentSignerBuilder.build(keyPair.getPrivate());
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }
}
