import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class Main {

    public static void main(String[] args) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream keyStoreStream = new FileInputStream("Lab1Store");
        keyStore.load(keyStoreStream, "lab1StorePass".toCharArray());
        PrivateKey privateKey = (PrivateKey) keyStore.getKey("lab1EncKeys", "lab1KeyPass"
                .toCharArray());

        FileInputStream encFile = new FileInputStream("ciphertext.enc");
        byte[] encKey1 = new byte[128];
        byte[] encIV = new byte[128];
        byte[] encKey2 = new byte[128];
        encFile.read(encKey1);
        encFile.read(encIV);
        encFile.read(encKey2);
        byte[] ciphertext = encFile.readAllBytes();
        encFile.close();

        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] key1 = rsaCipher.doFinal(encKey1);
        byte[] iv = rsaCipher.doFinal(encIV);
        byte[] key2 = rsaCipher.doFinal(encKey2);

        Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key1, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        aesCipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        byte[] plaintext = aesCipher.doFinal(ciphertext);
        String plaintextStr = new String(plaintext);
        String[] lines = plaintextStr.split("\n");
        for (String line : lines) {
            System.out.println(line);
            System.out.println();
        }


        Mac hmac = Mac.getInstance("HmacMD5");
        SecretKeySpec macKeySpec = new SecretKeySpec(key2, "HmacMD5");
        hmac.init(macKeySpec);

        byte[] computedMac = hmac.doFinal(plaintext);

        String mac1Hex = new String(Files.readAllBytes(Paths.get("ciphertext.mac1.txt"))).trim();
        String mac2Hex = new String(Files.readAllBytes(Paths.get("ciphertext.mac2.txt"))).trim();
        byte[] mac1 = hexStringToByteArray(mac1Hex);
        byte[] mac2 = hexStringToByteArray(mac2Hex);

        boolean macValid = Arrays.equals(computedMac, mac1) || Arrays.equals(computedMac, mac2);
        System.out.println("MAC Valid: " + macValid);
        if (Arrays.equals(computedMac, mac1)) {
            System.out.println("Correct MAC is from ciphertext.mac1.txt");
        } else if (Arrays.equals(computedMac, mac2)) {
            System.out.println("Correct MAC is from ciphertext.mac2.txt");
        }

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        FileInputStream certFile = new FileInputStream("Lab1Sign.cert");
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(certFile);
        PublicKey publicKey = certificate.getPublicKey();

        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(plaintext);

        boolean sig1Valid = signature.verify(Files.readAllBytes(Paths.get("ciphertext.enc.sig1")));
        boolean sig2Valid = signature.verify(Files.readAllBytes(Paths.get("ciphertext.enc.sig2")));

        System.out.println("Signature 1 Valid: " + sig1Valid);
        System.out.println("Signature 2 Valid: " + sig2Valid);
        if (sig1Valid) {
            System.out.println("Correct signature is from ciphertext.enc.sig1");
        } else if (sig2Valid) {
            System.out.println("Correct signature is from ciphertext.enc.sig2");
        }
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}
