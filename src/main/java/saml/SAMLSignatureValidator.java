package saml;
import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.keys.KeyInfo;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.xmlsec.signature.Signature;
import org.springframework.security.saml.util.SAMLUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAMLSignatureValidator {
    public static void main(String[] args) throws Exception {
        org.apache.xml.security.Init.init();

        // Load SAML request XML
        File file = new File("E:\\MyLearning\\TestAzureSamlApplication\\src\\main\\resources\\SamlRequest.xml");
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(file);

        // Get Signature element
        Element sigElement = (Element) doc.getElementsByTagNameNS(
                "http://www.w3.org/2000/09/xmldsig#", "Signature").item(0);
        XMLSignature signature = new XMLSignature(sigElement, "");

        // Load Public Key from Certificate
        FileInputStream fis = new FileInputStream("E:\\MyLearning\\TestAzureSamlApplication\\src\\main\\resources\\certificate.cer");
        Certificate cert = java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(fis);
        PublicKey publicKey = cert.getPublicKey();

        // Validate Signature
        boolean isValid = signature.checkSignatureValue(publicKey);
        System.out.println("Signature validation result: " + isValid);

    }

}
