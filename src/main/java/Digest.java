import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Digest {
    public static DigestCalculator getDigestCalculator(AlgorithmIdentifier algorithmIdentifier) {
        try {
            return new BcDigestCalculatorProvider().get(algorithmIdentifier);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    public static MessageDigest getSha1MessageDigest() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
