package saml;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class SAMLUtils {
    static {
        try {
            // Initialize OpenSAML library
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("Failed to initialize OpenSAML", e);
        }
    }

    public static byte[] deflate(byte[] input) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, new Deflater(Deflater.DEFLATED, true));
        deflaterOutputStream.write(input);
        deflaterOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }
}
