package saml;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class XMLSignatureVerifier {
    static {
        org.apache.xml.security.Init.init();
    }

    public static void main(String[] args) throws Exception {
        // Enable debug logging
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.SimpleLog");
        System.setProperty("org.apache.commons.logging.simplelog.defaultlog", "debug");

        // Load the signed XML document
        String xml = "<saml2p:AuthnRequest xmlns:saml2p=\"urn:oasis:names:tc:SAML:2.0:protocol\"\n" +
                "                     AssertionConsumerServiceURL=\"http://localhost:8085/saml/SSO\"\n" +
                "                     Destination=\"https://login.microsoftonline.com/dba21c9c-dbbc-4b6a-9473-8e886854204f/saml2\"\n" +
                "                     ID=\"_2653881e-599b-4717-9ff7-d83c1b64e10f\"\n" +
                "                     IssueInstant=\"2025-03-08T11:21:57.435Z\"\n" +
                "                     ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"\n" +
                "                     Version=\"2.0\"\n" +
                ">\n" +
                "    <saml2:Issuer xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\">testSaml253</saml2:Issuer>\n" +
                "    <ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\n" +
                "        <ds:SignedInfo>\n" +
                "            <ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
                "            <ds:SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" />\n" +
                "            <ds:Reference URI=\"#_2653881e-599b-4717-9ff7-d83c1b64e10f\">\n" +
                "                <ds:Transforms>\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" />\n" +
                "                    <ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" />\n" +
                "                </ds:Transforms>\n" +
                "                <ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" />\n" +
                "                <ds:DigestValue>6edhV8igXjdOS8JqfgWLFAeMl+IOdF9FE0t4d83y7yU=</ds:DigestValue>\n" +
                "            </ds:Reference>\n" +
                "        </ds:SignedInfo>\n" +
                "        <ds:SignatureValue>\n" +
                "            Hp4r5oZnFgMmw9FnFPIg0SEo4HYbhm3owXxCKq3Pv1ZZLBWDioptK6X1WB8yrY6DOIuZaZcCI4jBi98tcxAjLfkEsnZW5O13MevXTSoj05nSpRZXPku/5ixtoQ1ejSdkxAa2bAjY2Vn9Zza5AxnZDhGlTAfziOZKYtAtdAOnkIY=\n" +
                "        </ds:SignatureValue>\n" +
                "        <ds:KeyInfo>\n" +
                "            <ds:X509Data>\n" +
                "                <ds:X509Certificate>MIICWjCCAcOgAwIBAgIBADANBgkqhkiG9w0BAQsFADBKMQswCQYDVQQGEwJpbjEUMBIGA1UECAwLTWFoYXJhc2h0cmExETAPBgNVBAoMCHNhbWxkZW1vMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjUwMzA4MDkwMDQyWhcNMjYwMzA4MDkwMDQyWjBKMQswCQYDVQQGEwJpbjEUMBIGA1UECAwLTWFoYXJhc2h0cmExETAPBgNVBAoMCHNhbWxkZW1vMRIwEAYDVQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN1ODHF1lvl9AevIKi/eXWloepdZhbl3M0CwSY9gyhfel2C+j9l0XHZQg3GZmx7e0polyvibo7fshkICYquPQcPrTSgCh1X2HTPtX4JmR55FTBjSNVGwWIG4Syq78RN3BcgXCBmBhpGHc/M22eKklXrCAtDi997Om9aopLtQnvx1AgMBAAGjUDBOMB0GA1UdDgQWBBRDKVLVFqmXd7CaJuYTQnFZ7SNtJTAfBgNVHSMEGDAWgBRDKVLVFqmXd7CaJuYTQnFZ7SNtJTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBALZwUa6AlVCQCvOV5YfhqLUNy+l4ILNrT+4PBdHQyZ684BafO4MeQtEgl1eoaIT5YCUV/aHg4DPP2fML1W3pf+5sjWHnFrZlIfkqW6z4iTE6u8co7g7urkXKuijOlHFdKkZgAOUhg82pA6PbTdF+M+NvssiZDU8KKAJp5pAEh2V3</ds:X509Certificate>\n" +
                "            </ds:X509Data>\n" +
                "        </ds:KeyInfo>\n" +
                "    </ds:Signature>\n" +
                "    <saml2p:NameIDPolicy AllowCreate=\"true\" Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\"\n" +
                "    />\n" +
                "</saml2p:AuthnRequest>";
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document document = builder.parse(new ByteArrayInputStream(xml.getBytes()));

        // Locate the Signature element
        Element signatureElement = (Element) document.getElementsByTagNameNS(Constants.SignatureSpecNS, "Signature").item(0);

        // Create an XMLSignature object
        XMLSignature signature = new XMLSignature(signatureElement, "");

        // Load the public key or certificate for verification

        String keystorePath = "E:\\MyLearning\\TestAzureSamlApplication\\src\\main\\resources\\samlKeystore.jks";
        String keystorePassword = "nalle123 "; // Change this
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

        // Verify the signature
        boolean isValid = signature.checkSignatureValue(cert.getPublicKey());
        if (isValid) {
            System.out.println("Signature is valid.");
        } else {
            System.out.println("Signature verification failed.");
        }
    }
}
