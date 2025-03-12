package saml;

import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class SAMLKeyLoader {
    public static Credential getCredential()  throws Exception {
        // Keystore details
        String keystorePath = "E:\\MyLearning\\TestAzureSamlApplication\\src\\main\\resources\\samlKeystore.jks";
        String keystorePassword = "nalle123"; // Change this
        String keyAlias = "apollo"; // Alias used when generating keypair
        String keyPassword = "nalle123"; // Password for private key

        // Load keystore
        FileInputStream fis = new FileInputStream(keystorePath);
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(fis, keystorePassword.toCharArray());
        fis.close();

        // Retrieve private key
        PrivateKey privateKey = (PrivateKey) keystore.getKey(keyAlias, keyPassword.toCharArray());

        // Retrieve certificate
        Certificate cert = keystore.getCertificate(keyAlias);
        X509Certificate certificate = (X509Certificate) cert;

        // Create OpenSAML credential
        Credential credential = new BasicX509Credential(certificate, privateKey);

        // Output for verification
        System.out.println("Loaded private key and certificate from JKS!");
        return credential;
    }
}
