package saml;

import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.w3c.dom.Element;

import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;

public class Main2 {
    public static void main(String[] args) throws Exception {
        // Initialize OpenSAML
        new SAMLUtils();

        // Create the SAML AuthnRequest
        String issuerUrl = "testSaml253"; // Replace with your Entity ID
        String destinationUrl = "https://login.microsoftonline.com/dba21c9c-dbbc-4b6a-9473-8e886854204f/saml2"; // Replace with your IdP's SSO URL
        String acsUrl = "http://localhost:8085/saml/SSO"; // Replace with your Reply URL
        AuthnRequest authnRequest = createAuthnRequest(issuerUrl, destinationUrl, acsUrl);

        // Load the private key and certificate
        InputStream privateKeyStream = SAMLRequestGenerator.class.getResourceAsStream("/private-key1.pem");
        InputStream certificateStream = SAMLRequestGenerator.class.getResourceAsStream("/certificate1.cer");
        Credential credential = loadCredential(privateKeyStream, certificateStream);

        // Sign the SAML request
    //    signSAMLRequest(authnRequest, credential);

        // Print the SAML request XML for debugging
      //  String samlRequestXml = XMLObjectSupport.ma(authnRequest);
    //    System.out.println("SAML Request XML: " + samlRequestXml);

        // Encode the SAML request
        String encodedRequest = encodeSAMLRequest(authnRequest);

        // Build the HTTP redirect URL
        String httpRedirectUrl = buildHttpRedirectUrl(destinationUrl, encodedRequest);

        // Print the HTTP redirect URL
        System.out.println("HTTP Redirect URL: " + httpRedirectUrl);
    }

    public static AuthnRequest createAuthnRequest(String issuerUrl, String destinationUrl, String acsUrl) {
        // Create the AuthnRequest object
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();

        // Set the request ID and issue instant
        authnRequest.setID("_" + java.util.UUID.randomUUID().toString());
        authnRequest.setIssueInstant(Instant.now());
        // Set the protocol binding and assertion consumer service URL
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authnRequest.setAssertionConsumerServiceURL(acsUrl); // Set the Reply URL here

        // Set the issuer
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue(issuerUrl);
        authnRequest.setIssuer(issuer);

        // Set the NameID policy
        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        authnRequest.setNameIDPolicy(nameIDPolicy);

        // Set the destination
        authnRequest.setDestination(destinationUrl);

        return authnRequest;
    }

    public static Credential loadCredential(InputStream privateKeyStream, InputStream certificateStream) throws Exception {
        // Load the private key
        byte[] privateKeyBytes = privateKeyStream.readAllBytes();
        String privateKeyPEM = new String(privateKeyBytes)
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedKey = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        // Load the public certificate
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(certificateStream);

        // Create a credential
        return new BasicX509Credential(certificate, privateKey);
    }

    public static void signSAMLRequest(AuthnRequest authnRequest, Credential credential) throws Exception {
        // Create the signature
        Signature signature = new SignatureBuilder().buildObject();
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        // Set the signature on the SAML request
        authnRequest.setSignature(signature);

        // Marshal the SAML request
        XMLObjectSupport.marshall(authnRequest);

        // Sign the SAML request
        Signer.signObject(signature);
    }

    public static String encodeSAMLRequest(AuthnRequest authnRequest) throws MarshallingException, IOException, TransformerException, IOException {
        // Marshal the SAML request to XML
        Element element = XMLObjectSupport.marshall(authnRequest);

        // Convert the XML to a byte array
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(element),
                        new javax.xml.transform.stream.StreamResult(outputStream));
        byte[] xmlBytes = outputStream.toByteArray();

        // DEFLATE-compress the XML
        byte[] deflatedBytes = SAMLUtils.deflate(xmlBytes);

        // Encode the compressed XML in Base64
        return Base64.getEncoder().encodeToString(deflatedBytes);
    }

    public static String buildHttpRedirectUrl(String idpSsoUrl, String encodedRequest) throws  UnsupportedEncodingException {
        // URL-encode the SAML request
        String urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8.toString());

        // Build the HTTP redirect URL
        return idpSsoUrl + "?SAMLRequest=" + urlEncodedRequest;
    }
}
