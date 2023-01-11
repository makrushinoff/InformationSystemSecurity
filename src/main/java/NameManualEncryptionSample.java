import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class NameManualEncryptionSample {

    private static final int E = 43;
    private static final BigInteger N = BigInteger.valueOf(49163);

    public static void main(String[] args) {

        String name = "Makrushyn Andrii Mykolayovych";
        System.out.println("Length: " + name.length());
        System.out.println("Symbols:");
        System.out.println(Arrays.toString(name.toCharArray()));
        final byte[] bytes = name.getBytes();
        System.out.println(Arrays.toString(bytes));
        System.out.println();
        encrypt(bytes);
    }

    private static void encrypt(byte[] bytes) {
        List<BigInteger> toEncrypt = new ArrayList<>();
        for(byte b : bytes) {
            toEncrypt.add(new BigInteger(String.valueOf(b)));
        }
        final List<BigInteger> collect = toEncrypt.stream()
                .map(charToEncrypt -> charToEncrypt.pow(E).mod(N))
                .collect(Collectors.toList());
        System.out.println(collect);
    }

}
