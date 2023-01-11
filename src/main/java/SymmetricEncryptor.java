import java.util.concurrent.atomic.AtomicInteger;

public class SymmetricEncryptor {

    public static String encrypt(String stringToEncrypt, int key) {
        int dimension = (int) Math.ceil((double) stringToEncrypt.length() / key);
        String[][] encryptionMatrix = new String[dimension][key];
        for(int i = 0; i < dimension; i++) {
            for(int j = 0; j < key; j++) {
                encryptionMatrix[i][j] = "*";
            }
        }
        AtomicInteger rowIndex = new AtomicInteger();
        AtomicInteger columnIndex = new AtomicInteger();
        for (char ch : stringToEncrypt.toCharArray()) {
            encryptionMatrix[rowIndex.get()][columnIndex.get()] = String.valueOf(ch);
            rowIndex.getAndIncrement();
            if (rowIndex.get() == dimension) {
                rowIndex.set(0);
                columnIndex.getAndIncrement();
            }
        }
        StringBuilder stringBuilder = new StringBuilder();
        for(int i = 0; i < dimension; i++) {
            for(int j = 0; j < key; j++) {
                stringBuilder.append(encryptionMatrix[i][j]);
            }
        }
        return stringBuilder.toString();
    }

    public static String decrypt(String stringToDecrypt, int key) {
        int dimension = (int) Math.ceil((double) stringToDecrypt.length() / key);
        String[][] encryptionMatrix = new String[dimension][key];
        for(int i = 0; i < dimension; i++) {
            for(int j = 0; j < key; j++) {
                encryptionMatrix[i][j] = "*";
            }
        }
        AtomicInteger rowIndex = new AtomicInteger();
        AtomicInteger columnIndex = new AtomicInteger();
        for (char ch : stringToDecrypt.toCharArray()) {
            encryptionMatrix[rowIndex.get()][columnIndex.get()] = String.valueOf(ch);
            columnIndex.getAndIncrement();
            if (columnIndex.get() == key) {
                columnIndex.set(0);
                rowIndex.getAndIncrement();
            }
        }
        StringBuilder stringBuilder = new StringBuilder();
        for(int i = 0; i < key; i++) {
            for(int j = 0; j < dimension; j++) {
                stringBuilder.append(encryptionMatrix[j][i]);
            }
        }
        return stringBuilder.toString();
    }

}
