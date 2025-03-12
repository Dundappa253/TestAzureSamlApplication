package saml;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class XMLDecoder {
    public static String decodeAndInflate(String encodedCompressedXml) throws IOException {
        // Step 1: URL Decode (only if necessary)

        // Step 2: Base64 Decode
        byte[] compressedBytes = Base64.getDecoder().decode(encodedCompressedXml);

        // Step 3: Inflate (Decompress)
        Inflater inflater = new Inflater(true);  // 'true' indicates raw DEFLATE (no zlib header)
        try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedBytes);
             InflaterInputStream inflaterInputStream = new InflaterInputStream(byteArrayInputStream, inflater)) {

            return new String(inflaterInputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IOException("Decompression failed: Ensure input is correctly encoded and compressed.", e);
        }
    }

    public static void main(String[] args) throws IOException {
        String encodedCompressedXml = "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";
        String xml = decodeAndInflate(encodedCompressedXml);
        System.out.println("Decoded XML: " + xml);
    }
}