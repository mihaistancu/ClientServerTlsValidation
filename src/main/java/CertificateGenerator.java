import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

public class CertificateGenerator {
    public X509Certificate issueCertificate(X509Certificate issuerCertificate, X500Name subjectDN, KeyPair issuerKeyPair, KeyPair issuedKeyPair, boolean isCACertificate, int validityYear, Extension... extensions) throws NoSuchAlgorithmException, OperatorCreationException, CertIOException, CertificateException {

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
                .build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(issuerKeyPair.getPrivate()));

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    public X509Certificate issueSelfSignedCertificate(KeyPair keyPair, X500Name subjectDN, int validityYear, Extension... extensions) throws CertIOException, OperatorCreationException, CertificateException {
        BigInteger serialNumber = new BigInteger(512, new Random());
        X500Name issuerDN = subjectDN;
        Date notBefore = new Date();
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.YEAR, validityYear);
        Date notAfter = cal.getTime();
        // Subject public key
        byte[] publicKey = keyPair.getPublic().getEncoded();
        SubjectPublicKeyInfo subjectPublicKey = SubjectPublicKeyInfo.getInstance(publicKey);

        X509v3CertificateBuilder certificateGenerator = new X509v3CertificateBuilder(issuerDN, serialNumber, notBefore, notAfter, subjectDN,
                subjectPublicKey);

        // Authority Key Identifier
        AuthorityKeyIdentifier authorityKeyIdentifier = createAuthorityKeyIdentifier(keyPair.getPublic());
        certificateGenerator.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyIdentifier);

        // Subject Key Identifier
        SubjectKeyIdentifier subjectKeyIdentifier = createSubjectKeyIdentifier(keyPair.getPublic());
        certificateGenerator.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyIdentifier);

        // Basic Constraints
        certificateGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true)); // last value corresponds to
        // whether this is a CA certificate or not

        certificateGenerator.addExtension(Extension.keyUsage, true, new X509KeyUsage(X509KeyUsage.keyCertSign | X509KeyUsage.cRLSign));

        if (extensions != null) {
            for (Extension extension : extensions) {
                certificateGenerator.addExtension(extension);
            }
        }

        X509CertificateHolder certHolder = certificateGenerator
                .build(new JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.getPrivate()));

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    // Copied from CertificateFactory class
    public AuthorityKeyIdentifier createAuthorityKeyIdentifier(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
        return new X509ExtensionUtils(digCalc).createAuthorityKeyIdentifier(publicKeyInfo);
    }

    // Copied from CertificateFactory class
    public SubjectKeyIdentifier createSubjectKeyIdentifier(final PublicKey publicKey) throws OperatorCreationException {
        final SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        final DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));

        return new X509ExtensionUtils(digCalc).createSubjectKeyIdentifier(publicKeyInfo);
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator CAKeyGen = KeyPairGenerator.getInstance("RSA");
        CAKeyGen.initialize(4096);
        return CAKeyGen.generateKeyPair();
    }


    public X509Certificate generateRootCertificate(KeyPair rootKeyPair, String rootCAName, boolean importToTruststore, int validityYear) throws Exception {
        X509Certificate rootCertificate = this.issueSelfSignedCertificate(
                rootKeyPair,
                new X500Name(rootCAName),
                validityYear);
        if (importToTruststore) {
            DefaultTrustStoreUtils.ImportCertificateToTrustCertStore(
                    rootCertificate,
                    rootCertificate.getSubjectX500Principal().getName());
        }
        return rootCertificate;
    }

    public X509Certificate generateIntermediateCertificate(X509Certificate rootCertificate, KeyPair rootKeyPair, KeyPair intermediateKeyPair, int validityYear, boolean importToTruststore) throws Exception {
        X509Certificate intermediateCertificate = this.issueCertificate(
                rootCertificate,
                new X500Name("CN=intermediate"),
                rootKeyPair,
                intermediateKeyPair,
                true,
                validityYear);
        if (importToTruststore) {
            DefaultTrustStoreUtils.ImportCertificateToTrustCertStore(
                    intermediateCertificate,
                    intermediateCertificate.getSubjectX500Principal().getName());
        }
        return intermediateCertificate;
    }

    public X509Certificate generateCertificateChain(String tlsCARootName, KeyPair tlsKeyPair, String certificateName) throws Exception {
        X509Certificate rootCertificate = DefaultTrustStoreUtils.getCertificateFromJksStore(tlsCARootName);
//        // Create and import intermediate cert
        KeyPair intermediateKeyPair = this.generateKeyPair();
        X509Certificate intermediateCertificate = this.generateIntermediateCertificate(rootCertificate, DefaultTrustStoreUtils.getRootCAKeyPair(), intermediateKeyPair, 1, true);

        // Create issued cert
        Extension extendedKeyUsageExtension = this.createExtendedKeyUsage();
//        X509Certificate tlsCertificate = this.issueCertificate(intermediateCertificate, new X500Name(certificateName), intermediateKeyPair, tlsKeyPair, false, 1, extendedKeyUsageExtension);
        X509Certificate tlsCertificate = this.issueCertificate(rootCertificate, new X500Name(certificateName), DefaultTrustStoreUtils.getRootCAKeyPair(), tlsKeyPair, false, 1, extendedKeyUsageExtension);

        return tlsCertificate;
    }

    public X509Certificate generateCertificateChain(X509Certificate rootCertificate, KeyPair tlsKeyPair, String certificateName) throws Exception {

//        // Create and import intermediate cert
        KeyPair intermediateKeyPair = this.generateKeyPair();
        X509Certificate intermediateCertificate = this.generateIntermediateCertificate(rootCertificate, DefaultTrustStoreUtils.getRootCAKeyPair(), intermediateKeyPair, 1, true);

        // Create issued cert
        Extension extendedKeyUsageExtension = this.createExtendedKeyUsage();
//        X509Certificate tlsCertificate = this.issueCertificate(intermediateCertificate, new X500Name(certificateName), intermediateKeyPair, tlsKeyPair, false, 1, extendedKeyUsageExtension);
        X509Certificate tlsCertificate = this.issueCertificate(rootCertificate, new X500Name(certificateName), DefaultTrustStoreUtils.getRootCAKeyPair(), tlsKeyPair, false, 1, extendedKeyUsageExtension);

        return tlsCertificate;
    }

    public Extension createExtendedKeyUsage() throws IOException {
        // Create an ExtendedKeyUsage extension for Server and Client Authentication
        KeyPurposeId serverAuthPurpose = KeyPurposeId.id_kp_serverAuth;
        KeyPurposeId clientAuthPurpose = KeyPurposeId.id_kp_clientAuth;
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(new KeyPurposeId[] {serverAuthPurpose,clientAuthPurpose});
        ASN1Sequence seq = ASN1Sequence.getInstance(extendedKeyUsage.toASN1Primitive());
        return new Extension(Extension.extendedKeyUsage, false, seq.getEncoded());
    }

}
