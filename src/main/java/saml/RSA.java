package saml;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import javax.crypto.Cipher;

public class RSA {

    public static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    /**
     * Encrypt the content using the public key
     */
    public static byte[] encrypt(byte[] content, PublicKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decrypt the content using the private key
     */
    public static byte[] decrypt(byte[] content, PrivateKey key) {
        try {
            final Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(content);
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
    }

    public static void main(String[] args) {
        try {
            // 🔹 Load Keystore
            String keystorePath = "E:\\MyLearning\\TestAzureSamlApplication\\src\\main\\resources\\samlKeystore2.jks";
            String keystorePassword = "test123";
            String keyAlias = "apollo";
            String keyPassword = "test123";

            FileInputStream fis = new FileInputStream(keystorePath);
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(fis, keystorePassword.toCharArray());
            fis.close();

            Certificate cert = keystore.getCertificate(keyAlias);
            PrivateKey privateKey = (PrivateKey) keystore.getKey(keyAlias, keyPassword.toCharArray());
            PublicKey publicKey = cert.getPublicKey();
            // 🔹 Encryption
            String message = "This is RSA algorithm test";
            System.out.println("🔹 Original Message: " + message);

            byte[] encryptedBytes = encrypt(message.getBytes(StandardCharsets.UTF_8), publicKey);
            String encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes); // ✅ Encode to Base64
            System.out.println("🔹 Encrypted Message (Base64): " + encryptedMessage);
            encryptedMessage = "v1/YDkNK5vz/c2zOoz7TztuJM43zcWW09UqlvhWFaJA1LZeynHKdX+hn16PVlNzd/hA9FRkyWZ/P&#13;\n" +
                    "TCdjVAh4HOe1Uz7SiaWWGyOuv5fHAA2t5lWWDVd5SOg6eav1tTkcaEQ0FC8EJg6S1wUe4Iu/oVbb\n" +
                    "EoK7Rb4Cm1jILeS7AnZ5NMcSAXNsl/T8cnxHnLKz3IKD/o5mDT9dsivYPO7z7pSgkYzBY1NpH3w/\n" +
                    "IPzxH7nzicPE1rpVAYMADQQ2vOlGYQ6VDli/RIMRijHiVFPViLTJ3w7eU4NfabVMLsRRpSrfnLRM\n" +
                    "iqDInc3q6wUqnVLtACfW7Zzr3LDEwhJVromwBg==";
            // 🔹 Decryption
            byte[] decryptedBytes = decrypt(Base64.getDecoder().decode(encryptedMessage), privateKey); // ✅ Decode Base64 before decrypting
            String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
            System.out.println("🔹 Decrypted Message: " + decryptedMessage);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}