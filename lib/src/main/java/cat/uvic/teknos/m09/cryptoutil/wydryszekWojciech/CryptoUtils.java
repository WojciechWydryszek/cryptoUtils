package cat.uvic.teknos.m09.cryptoutil.wydryszekWojciech;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Properties;

public class CryptoUtils {
    /**
     * Symmetric encryption algorithm
     * WydryszekWojciech implementation for encryption message encryption algorithm
     * @param plainText text in byte[]
     * @param password password String
     * @return byte[]
     * @throws IOException input output exception
     * @throws NoSuchAlgorithmException algorithm exeption
     * @throws NoSuchPaddingException padding exception
     * @throws InvalidAlgorithmParameterException invalid algorith exception
     * @throws InvalidKeyException key exception
     * @throws IllegalBlockSizeException block size exception
     * @throws BadPaddingException bad padding exception
     */
    public byte[] encrypt(byte[] plainText, String password) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        var properties = new Properties();

        byte[] cipherText = null;

        properties.load(CryptoUtils.class.getResourceAsStream("/hash.properties"));

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

    /**
     * Symmetric encryption algorithm
     * WydryszekWojciech implementation for encryption message decrypt algorithm
     * @param cipherText text byte[]
     * @param password password String
     * @return byte[]
     * @throws NoSuchPaddingException  padding exeption
     * @throws NoSuchAlgorithmException algorithm exeption
     * @throws IllegalBlockSizeException clock size exeption
     * @throws BadPaddingException bad padding exeption
     */
    public byte[] decrypt(byte[] cipherText, String password) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException {
        var cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        var decryptedTextBytes = cipher.doFinal(cipherText);

        return decryptedTextBytes;
    }

    /**
     * Asymmetric signature algorithm
     * WydryszekWojciech implementation for sign message
     * @param message message String
     * @return byte[]
     * @throws KeyStoreException key store exeption
     * @throws IOException input output exeption
     * @throws CertificateException certificate exeption
     * @throws NoSuchAlgorithmException algorithm exeption
     * @throws UnrecoverableKeyException key exeption
     * @throws InvalidKeyException invalid key exeption
     * @throws SignatureException signature exeption
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

    /**
     * Asymmetric verify algorithm
     * WydryszekWojciech implementation for verify signature
     * @param message message for encrypth
     * @param signature signature in byte[]
     * @param certificate certificate Object
     * @return Boolean
     * @throws NoSuchAlgorithmException algorithm exeption
     * @throws SignatureException signature exeption
     * @throws InvalidKeyException invalid key exeption
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