import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;

public class SHA1Sample {

    private static final int GROUP_ORDER = 9;
    private static final int GROUP_NUMBER = 91;
    private static final Path PATH_TO_MESSAGE = Paths.get("src", "main", "resources", "вариант 9.txt");

    private static int calculateSymmetricCipherKey() {
        return 10 + ((GROUP_ORDER + GROUP_NUMBER) % 7);
    }

    public static void main(String[] args) throws Exception {
        //calculate key
        int symmetricCipherKey = calculateSymmetricCipherKey();
        System.out.println(MessageFormat.format("Generated key: {0}", symmetricCipherKey));
        //calculate hash of message
        String message = Files.readString(PATH_TO_MESSAGE);
        String messageHash = getStringHash(message);
        System.out.println(MessageFormat.format("Hash of message to send: {0}", messageHash));
        //encrypt hash with symmetric cipher
        String encryptedMessageHash = SymmetricEncryptor.encrypt(messageHash, symmetricCipherKey);
        System.out.println();
        //encrypt key of symmetric cipher with asymmetric cipher by public key
        KeyPair keyPair = RSAEncryptor.generateKeys();
        RSAEncryptor.encrypt(keyPair.getPublic(), String.valueOf(symmetricCipherKey));
        System.out.println(MessageFormat.format("Encrypted by symmetric key hash of message to send: {0}", messageHash));
        Files.readString(Paths.get("src", "main", "resources", "encrypted.txt"));
        //decrypt key of symmetric cipher with asymmetric cipher by private key
        String decryptedKey = RSAEncryptor.decrypt(keyPair.getPrivate());
        //decrypt hash with symmetric cipher with decrypted key
        String decryptedHash = SymmetricEncryptor.decrypt(encryptedMessageHash, Integer.parseInt(decryptedKey)).replace("*", "");
        //compare starting hash with resulting hash
        System.out.println(decryptedHash);
        System.out.println(decryptedHash.contentEquals(messageHash));
    }

    private static String getStringHash(String stringToHash) {
        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        final byte[] digest = messageDigest.digest(stringToHash.getBytes());
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : digest) {
            stringBuilder.append((Integer.toString(b & 0xff, 16)));
        }

        return stringBuilder.toString();
    }

}
