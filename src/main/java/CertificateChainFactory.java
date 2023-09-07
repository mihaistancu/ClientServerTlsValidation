import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

public class CertificateChainFactory {

    public static X509Certificate generateCertificate(String cn, KeyPair keyPair, X509Certificate issuerCertificate, PrivateKey issuerKey, boolean isCaCertificate, Extension... extensions) {
        try {
            return issueCertificate(
                    issuerCertificate,
                    new X500Name(cn),
                    issuerKey,
                    keyPair,
                    isCaCertificate,
                    2023, extensions);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Extension createExtendedKeyUsage() throws IOException {
        // Create an ExtendedKeyUsage extension for Server and Client Authentication
        KeyPurposeId serverAuthPurpose = KeyPurposeId.id_kp_serverAuth;
        KeyPurposeId clientAuthPurpose = KeyPurposeId.id_kp_clientAuth;
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[] {serverAuthPurpose,clientAuthPurpose});
        ASN1Sequence seq = ASN1Sequence.getInstance(extendedKeyUsage.toASN1Primitive());
        return new Extension(Extension.extendedKeyUsage, false, seq.getEncoded());
    }

    public static X509Certificate issueCertificate(X509Certificate issuerCertificate, X500Name subjectDN, PrivateKey issuerKey,
            KeyPair issuedKeyPair, boolean isCACertificate, int validityYear, Extension... extensions) throws
            NoSuchAlgorithmException,
            OperatorCreationException,
            CertIOException,
            CertificateException {

        BigInteger serialNumber = new BigInteger(512, new Random()); //
        X500Name issuerDN = new X500Name(issuerCertificate.getSubjectX500Principal().getName());
        // X500Name subjectDN = new X500Name("CN=issued");
        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.YEAR, validityYear);
        Date notAfter = cal.getTime();
        // Subject public key
        byte[] publicKey;
        KeyPair keyPair;
        if (issuedKeyPair == null) {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(4096);
            keyPair = keyGen.generateKeyPair();
            publicKey = keyPair.getPublic().getEncoded();
        } else {
            keyPair = issuedKeyPair;
            publicKey = issuedKeyPair.getPublic().getEncoded();
        }
        SubjectPublicKeyInfo subjectPublicKey = SubjectPublicKeyInfo.getInstance(publicKey);

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN,
                subjectPublicKey);

        // Authority Key Identifier
        AuthorityKeyIdentifier authorityKeyIdentifier = createAuthorityKeyIdentifier(issuerCertificate.getPublicKey());
        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);

        // Subject Key Identifier
        SubjectKeyIdentifier subjectKeyIdentifier = createSubjectKeyIdentifier(keyPair.getPublic());
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        // Basic Constraints
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCACertificate)); // last value corresponds to
        // whether this is a CA certificate or not

        if (extensions != null) {
            for (Extension extension : extensions) {
                certificateGenerator.addExtension(extension);
            }
        }

        X509CertificateHolder certHolder = certificateGenerator
                .build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(issuerKey));

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public static AuthorityKeyIdentifier createAuthorityKeyIdentifier(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

    // Copied from CertificateFactory class
    public static SubjectKeyIdentifier createSubjectKeyIdentifier(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }
}
