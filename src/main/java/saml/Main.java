package saml;

import org.opensaml.saml.saml2.core.AuthnRequest;

import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class Main {
    public static void main(String[] args) throws Exception {
        new SAMLUtils();
        String acsUrl = "http://localhost:8085/saml/SSO"; // Replace with your Reply URL
        String issuerUrl = "testSaml253"; // Replace with your Entity ID
        String destinationUrl = "https://login.microsoftonline.com/dba21c9c-dbbc-4b6a-9473-8e886854204f/saml2";

        AuthnRequest authnRequest = SAMLRequestGenerator.createAuthnRequest(issuerUrl, destinationUrl,acsUrl);

        InputStream privateKeyStream = Main.class.getResourceAsStream("/private-key.pem");
        InputStream certificateStream = Main.class.getResourceAsStream("/certificate.cer");

        SAMLRequestGenerator.signSAMLRequest(authnRequest, privateKeyStream, certificateStream);

        String encodedRequest = SAMLRequestEncoder.encodeSAMLRequest(authnRequest);
        System.out.println("SAML Request: " + encodedRequest);

        String httpRedirectUrl = buildHttpRedirectUrl(destinationUrl, encodedRequest);
        // Print the HTTP redirect URL
        System.out.println("HTTP Redirect URL: " + httpRedirectUrl);
    }



    public static String buildHttpRedirectUrl(String idpSsoUrl, String encodedRequest) throws UnsupportedEncodingException {
        // URL-encode the SAML request
        String urlEncodedRequest = URLEncoder.encode(encodedRequest, StandardCharsets.UTF_8.toString());
        // Build the HTTP redirect URL
        return idpSsoUrl + "?SAMLRequest=" + urlEncodedRequest;
    }


}
