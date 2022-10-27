package cat.uvic.teknos.wydryszekWojciech.m09.cryptoutil;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Properties;

public class CryptoUtils {
    /***
     * Symmetric encryption algorithm
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

        properties.load(cat.uvic.teknos.wydryszekWojciech.m09.cryptoutil.CryptoUtils.class.getResourceAsStream("/hash.properties"));

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
     * Symmetric encryption algorithm
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

    /***
     * Asymmetric signature algorithm
     * WydryszekWojciech implementation for sign message
     * @param message
     * @return byte[]
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public byte[] sign(byte[] message) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, InvalidKeyException, SignatureException {

        var keystore = KeyStore.getInstance("PKCS12");

        keystore.load(new FileInputStream
                ("app/src/main/resources/m09.p12"), "Teknos01.".toCharArray());

        var privateKey = keystore.getKey
                ("self_signed_ca", "Teknos01.".toCharArray());

        var signer = Signature.getInstance("SHA256withRSA");

        signer.initSign((PrivateKey) privateKey);
        signer.update(message);

        var signature = signer.sign();

        return signature;
    }

    /***
     * Asymmetric verify algorithm
     * WydryszekWojciech implementation for verify signature
     * @param message
     * @param signature
     * @param certificate
     * @return boolean
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws SignatureException
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     * @throws InvalidKeyException
     */
    public boolean verify(byte[] message, byte[] signature, Certificate certificate) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        var signer = Signature.getInstance("SHA256withRSA");

        var publicKey = certificate.getPublicKey();

        signer.initVerify(publicKey);
        signer.update(message);

        var isValid = signer.verify(signature);

        return isValid;
    }
}