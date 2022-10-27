package cat.uvic.teknos.wydryszekWojciech.m09.cryptoutil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.security.*;
import java.util.Properties;

public class cryptoUtils {
    /***
     * WydryszekWojciech implementation for encryption message encryption algorithm
     * @param plainText
     * @param password
     * @return byte[]
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] encrypt(byte[] plainText, String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();

        byte[] cipherText = null;

        properties.load(cryptoUtils.class.getResourceAsStream("/hash.properties"));

        var hashAlgorithm = String.valueOf(properties.get("hash.algorithm"));

        var salt = Boolean.parseBoolean(properties.getProperty("hash.salt"));

        var keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        var secretKey = keyGenerator.generateKey();

        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        if (salt) {
            var secureRandom = new SecureRandom();
            var bytes = new byte[16];
            secureRandom.nextBytes(bytes);
            var iv = new IvParameterSpec(bytes);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

            cipherText = cipher.doFinal(plainText);
        } else {
            cipherText = cipher.doFinal(plainText);
        }

        return cipherText;
    }

    /***
     * WydryszekWojciech implementation for encryption message decrypt algorithm
     * @param cipherText
     * @param password
     * @return byte[]
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] decrypt(byte[] cipherText, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        var decryptedTextBytes = cipher.doFinal(cipherText);

        return decryptedTextBytes;
    }
}
