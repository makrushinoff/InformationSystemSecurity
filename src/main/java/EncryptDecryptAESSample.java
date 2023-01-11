import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.stream.Stream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecryptAESSample {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_STRING = "CCE0EAF0F3F8E8ED98C0EDE4F0B3E998CCE8EAEEEBE0E9EEE2E8F70000000000";
    private static final Path SOURCE_FILE_PATH = Paths.get("вариант 9.txt");
    private static final Path ENCRYPTED_FILE_PATH = Paths.get("encryptedFile.txt");
    private static final Path DECRYPTED_FILE_PATH = Paths.get("decryptedFile.txt");

    private static String readFileText() {
        try(final Stream<String> lines = Files.lines(SOURCE_FILE_PATH)) {
            return lines.reduce("", (s1, s2) -> s1.concat(s2).concat("\n"));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static SecretKey getKey() {
        return new SecretKeySpec(KEY_STRING.getBytes(), 0, 32, "AES");
    }

    private static String encryptFile() throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, getKey(), generateIv());
        byte[] cipherText = cipher.doFinal(readFileText().getBytes());
        String encryptedText = Base64.getEncoder().encodeToString(cipherText);
        Files.write(ENCRYPTED_FILE_PATH, encryptedText.getBytes());
        return encryptedText;
    }

    private static void decryptFile(String encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, getKey(), generateIv());
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        Files.write(DECRYPTED_FILE_PATH, plainText);
    }

    public static void main(String[] args) throws Exception {
        decryptFile(encryptFile());
    }
}
