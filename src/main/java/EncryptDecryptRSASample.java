import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;

public class EncryptDecryptRSASample {

    private static final String RSA_ALGORITHM = "RSA";
    private static final Path SOURCE_FILE_PATH = Paths.get("вариант 9.txt");
    private static final Path DECRYPTED_FILE_PATH = Paths.get("decryptedFile.txt");
    private static final String PATH_TO_FILES = "encryptedFiles";

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        encryptFile(publicKey);
        decryptFiles(privateKey);
    }

    private static void encryptFile(PublicKey publicKey) throws Exception {
        byte[] fileBytes = Files.readAllBytes(SOURCE_FILE_PATH);
        List<byte[]> bytesList = new ArrayList<>();
        int i = 0;
        while (i < fileBytes.length) {
            byte[] bytes;
            if(i + 245 >= fileBytes.length) {
                bytes = Arrays.copyOfRange(fileBytes, i, fileBytes.length - 1);
            } else {
                bytes = Arrays.copyOfRange(fileBytes, i, (i + 245));
            }
            bytesList.add(bytes);
            i += 245;
        }
        Cipher encryptCipher = Cipher.getInstance(RSA_ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        i = 0;
        try {
            Files.createDirectory(Paths.get(PATH_TO_FILES));
        } catch (Exception ignore) {

        }
        for(byte[] bytes : bytesList) {
            Path tempFile = Files.createFile(Paths.get(PATH_TO_FILES, "temp".concat(String.valueOf(i)) + ".txt"));
            byte[] encryptedFileBytes = encryptCipher.doFinal(bytes);
            Files.write(tempFile, encryptedFileBytes);
            i++;
        }
    }

    private static void decryptFiles(PrivateKey privateKey) throws Exception {
        boolean done = false;
        List<byte[]> fromFiles = new ArrayList<>();
        int i = 0;
        while(!done) {
            try {
                fromFiles.add(Files.readAllBytes(Paths.get(PATH_TO_FILES, "temp" + i + ".txt")));
                i++;
            }
            catch (Exception e) {
                done = true;
            }
        }
        for(byte[] bytes : fromFiles) {
            Cipher decryptCipher = Cipher.getInstance(RSA_ALGORITHM);
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedFileBytes = decryptCipher.doFinal(bytes);
            try {
                Files.createFile(DECRYPTED_FILE_PATH);
            } catch (Exception ignore) {

            }
            Files.write(DECRYPTED_FILE_PATH, decryptedFileBytes, StandardOpenOption.APPEND);
        }
    }
}
