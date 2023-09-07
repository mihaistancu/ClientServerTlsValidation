import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.KeyStore;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class KeyStorePassPair {
    private KeyStore keyStore;
    private String keyStorePass;
}
