import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class RSAEncryptor {

    private static final String RSA_ALGORITHM = "RSA";
    private static final Path ENCRYPTED_FILE_PATH = Paths.get("src", "main", "resources", "encrypted.txt");

    public static KeyPair generateKeys() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void encrypt(PublicKey publicKey, String toEncrypt) {
        try {
            byte[] stringBytes = toEncrypt.getBytes();
            Cipher encryptCipher = Cipher.getInstance(RSA_ALGORITHM);
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedFileBytes = encryptCipher.doFinal(stringBytes);
            Files.write(ENCRYPTED_FILE_PATH, encryptedFileBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String decrypt(PrivateKey privateKey) {
        try {
            Cipher decryptCipher = Cipher.getInstance(RSA_ALGORITHM);
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedFileBytes = decryptCipher.doFinal(Files.readAllBytes(ENCRYPTED_FILE_PATH));
            return new String(decryptedFileBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
