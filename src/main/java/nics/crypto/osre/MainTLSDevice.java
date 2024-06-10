package nics.crypto.osre;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.NTRUReEncryptParams;
import nics.crypto.osre.TLSClient;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import java.math.BigInteger;
import java.util.Random;

import java.util.logging.Logger;

public class MainTLSDevice {

    static Logger logger = Logger.getLogger(MainTLSDevice.class.getName());
    public static void main( String[] args ) throws Exception {

        String hostname = "localhost";
        int port = 8443;
        String truststorePath = "certs/client.truststore";
        String password = "password";

        if(args.length == 2) {
            hostname = args[0];
            port = Integer.parseInt(args[1]);
        }

        logger.info("Starting device...");

        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(EncryptionParameters.EES1087EP2_FAST);
        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();
        int mLen = 128;
        Random rng = new Random(12345);
        BigInteger m1_bi = new BigInteger(mLen, rng);

        logger.info("Data to send: " + m1_bi.toString());

        TLSClient client = new TLSClient(hostname, port, truststorePath, password);
        client.connectAndSend(m1_bi.toByteArray());
    }
}
