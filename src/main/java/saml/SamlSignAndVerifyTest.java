package saml;


import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.impl.KeyInfoBuilder;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.impl.X509CertificateBuilder;
import org.opensaml.xmlsec.signature.impl.X509DataBuilder;
import org.opensaml.xmlsec.signature.support.*;
import org.w3c.dom.Element;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.FileInputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;

public class SamlSignAndVerifyTest {

    public  static  String keystorePath = "E:\\MyLearning\\TestAzureSamlApplication\\src\\main\\resources\\samlKeystore2.jks";
    public  static  String keystorePassword = "test123"; // Change this
    public  static  String keyAlias = "apollo"; // Alias used when generating keypair
    public  static String keyPassword = "test123"; // Password for private key


    public static void main(String[] args) {
        try {
            InitializationService.initialize();

            // Create the SAML request
            AuthnRequest authnRequest = createAuthnRequest();


            // Load the private key and certificate
            PrivateKey privateKey = loadPrivateKey(keystorePath, keystorePassword, keyAlias, keyPassword);
            X509Certificate certificate = loadCertificate(keystorePath, keyPassword, keyAlias);
            Credential credential = new BasicX509Credential(certificate, privateKey);

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

            signature.setKeyInfo(keyInfo);

            authnRequest.setSignature(signature);

            XMLObjectSupport.marshall(authnRequest);
            Signer.signObject(signature);

            String encodedRequest = SAMLRequestEncoder.encodeSAMLRequest(authnRequest);
            System.out.println("SAML Request: " + encodedRequest);

            String httpRedirectUrl = buildHttpRedirectUrl("https://login.microsoftonline.com/dba21c9c-dbbc-4b6a-9473-8e886854204f/saml2", encodedRequest);

            // Print the signed SAML request
            System.out.println(httpRedirectUrl);
            verify(authnRequest,certificate);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String buildHttpRedirectUrl(String idpSsoUrl, String encodedRequest) throws UnsupportedEncodingException {
        // URL-encode the SAML request
        String urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8.toString());
        // Build the HTTP redirect URL
        return idpSsoUrl + "?SAMLRequest=" + urlEncodedRequest;
    }

    private static AuthnRequest createAuthnRequest() {
        AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject();
        authnRequest.setID("_" + java.util.UUID.randomUUID().toString());
        authnRequest.setIssueInstant(Instant.now());
        authnRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authnRequest.setAssertionConsumerServiceURL("http://localhost:8085/saml/SSO");

        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue("testSaml253");
        authnRequest.setIssuer(issuer);

        NameIDPolicy nameIDPolicy = new NameIDPolicyBuilder().buildObject();
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
        authnRequest.setNameIDPolicy(nameIDPolicy);
        authnRequest.setDestination("https://login.microsoftonline.com/dba21c9c-dbbc-4b6a-9473-8e886854204f/saml2");
        return authnRequest;
    }

    public static PrivateKey loadPrivateKey(String keystorePath, String keystorePassword, String alias, String keyPassword) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
        return (PrivateKey) keystore.getKey(alias, keyPassword.toCharArray());
    }

    public static X509Certificate loadCertificate(String keystorePath, String keystorePassword, String alias) throws Exception {
        KeyStore keystore = KeyStore.getInstance("JKS");
        keystore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
        return (X509Certificate) keystore.getCertificate(alias);
    }

    public static void verify(AuthnRequest authnRequest,X509Certificate certificate) {
        try {
            SignatureValidator.validate(authnRequest.getSignature(), new BasicX509Credential(certificate));
            System.out.println("Signature is valid!");
        } catch (SignatureException e) {
            System.out.println("Signature is invalid: " + e.getMessage());
        }
    }

    private static String serializeSAMLObject(AuthnRequest authnRequest) throws MarshallingException, TransformerException {
        // Get the marshaller factory
        MarshallerFactory marshallerFactory = org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport.getMarshallerFactory();

        // Get the marshaller for the AuthnRequest
        Marshaller marshaller = marshallerFactory.getMarshaller(authnRequest);

        // Marshal the AuthnRequest to a DOM element
        Element domElement = marshaller.marshall(authnRequest);

        // Convert the DOM element to a string
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(domElement);
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);
        transformer.transform(source, result);

        return writer.toString();
    }
}
