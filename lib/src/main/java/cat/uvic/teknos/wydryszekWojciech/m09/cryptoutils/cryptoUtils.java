package cat.uvic.teknos.wydryszekWojciech.m09;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Properties;

public class cryptoUtils {
    public static void hash() throws IOException {
        var properties = new Properties();

        properties.load(cryptoUtils.class.getResourceAsStream("/hash.properties"));

        var hashAlgorithm = properties.get("hash.algorithm");

        var salt = Boolean.parseBoolean(properties.getProperty("hash.salt"));

        if(salt == true)
            getSalt();
    }

    public static byte[] getSalt(){
        var secureRandom = new SecureRandom();
        var salt = new byte[16];

        secureRandom.nextBytes(salt);

        return salt;
    }

}
