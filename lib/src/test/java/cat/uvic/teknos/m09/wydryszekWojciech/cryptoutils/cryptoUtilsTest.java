package cat.uvic.teknos.m09.wydryszekWojciech.cryptoutils;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class cryptoUtilsTest {

    @Test void EncryptMethod_Return_Same_All_Times() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        synchronized (CryptoUtils.class) {
            var message = "message";

            CryptoUtils cryptoUtils = new CryptoUtils();

            var digestResult1 = cryptoUtils.encrypt(message.getBytes(), "");
            var digestResult2=cryptoUtils.encrypt(message.getBytes(),"");
            assertTrue(Arrays.equals(digestResult1,digestResult2));
        }
    }

    @Test void DecryptMethod_work_nice() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        synchronized (CryptoUtils.class) {
            var message = "message";

            CryptoUtils cryptoUtils = new CryptoUtils();

            var digestResult1 = cryptoUtils.encrypt(message.getBytes(), "");
            var digestResult2=cryptoUtils.decrypt(digestResult1,"");
            assertTrue(Arrays.equals(digestResult2, message.getBytes()));
        }
    }
}