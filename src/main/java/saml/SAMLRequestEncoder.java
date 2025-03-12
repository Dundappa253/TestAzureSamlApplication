package saml;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.util.Base64;


public class SAMLRequestEncoder {
    public static String encodeSAMLRequest(AuthnRequest authnRequest) throws Exception {
        Element element = XMLObjectSupport.marshall(authnRequest);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        javax.xml.transform.TransformerFactory.newInstance().newTransformer()
                .transform(new javax.xml.transform.dom.DOMSource(element),
                        new javax.xml.transform.stream.StreamResult(outputStream));
        byte[] xmlBytes = outputStream.toByteArray();
        byte[] deflatedBytes = SAMLUtils.deflate(xmlBytes);
        return Base64.getEncoder().encodeToString(xmlBytes);
    }
}
