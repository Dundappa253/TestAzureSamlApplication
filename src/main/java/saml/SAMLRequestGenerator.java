package saml;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.core.xml.util.XMLObjectSupport;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public class SAMLRequestGenerator {
    public static AuthnRequest createAuthnRequest(String issuerUrl, String destinationUrl,String acsUrl) {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
        authnRequest.setID("_" + java.util.UUID.randomUUID().toString());
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authnRequest.setAssertionConsumerServiceURL(acsUrl);

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(issuerUrl);
        authnRequest.setIssuer(issuer);

        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        authnRequest.setNameIDPolicy(nameIDPolicy);
        authnRequest.setDestination(destinationUrl);

        return authnRequest;
    }

    public static void signSAMLRequest(AuthnRequest authnRequest, InputStream privateKeyStream, InputStream certificateStream) throws Exception {
      /*  byte[] privateKeyBytes = privateKeyStream.readAllBytes();
        String privateKeyPEM = new String(privateKeyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certificateStream);

        Credential credential = new BasicX509Credential(certificate, privateKey);
  */

        String keystorePath = "E:\\MyLearning\\TestAzureSamlApplication\\src\\main\\resources\\samlKeystore2.jks";
        String keystorePassword = "test123"; // Change this
        String keyAlias = "apollo"; // Alias used when generating keypair
        String keyPassword = "test123"; // Password for private key

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

        // Create the signature
        Signature signature = new SignatureBuilder().buildObject();
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        // Add KeyInfo with the public certificate
        KeyInfo keyInfo = new KeyInfoBuilder().buildObject();
        X509Data x509Data = new X509DataBuilder().buildObject();
        org.opensaml.xmlsec.signature.X509Certificate x509Certificate = new X509CertificateBuilder().buildObject();

        // Set the certificate value
        x509Certificate.setValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        x509Data.getX509Certificates().add(x509Certificate);
        keyInfo.getX509Datas().add(x509Data);

        // Attach KeyInfo to the signature
        signature.setKeyInfo(keyInfo);
        // Attach the signature to the SAML request
        authnRequest.setSignature(signature);
        // Marshal and sign the request
        try {
            XMLObjectSupport.marshall(authnRequest);
            Signer.signObject(signature);

            // Remove line breaks and spaces from the <ds:SignatureValue>
           // removeLineBreaksFromSignatureValue(authnRequest);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign SAML request", e);
        }
    }


}
