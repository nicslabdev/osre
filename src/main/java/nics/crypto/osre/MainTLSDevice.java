package nics.crypto.osre;

import java.math.BigInteger;
import java.security.SecureRandom;
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
        int N = 1;

        if(args.length == 3) {
            hostname = args[0];
            port = Integer.parseInt(args[1]);
            N = Integer.parseInt(args[2]);
        }

        logger.info("Starting device...");

        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(EncryptionParameters.EES1087EP2_FAST);
        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();
        int mLen = 128;
        SecureRandom rng = new SecureRandom();
        BigInteger m1_bi = new BigInteger(mLen, rng);

        logger.info("Data to send: " + m1_bi.toString());

        long startCount = System.currentTimeMillis();
        for(int i = 0; i < N; i++) {
            int iterPort = port + i;
            TLSClient client = new TLSClient(hostname, iterPort, truststorePath, password);
            client.connectAndSend(m1_bi.toByteArray());
        }
        long endCount = System.currentTimeMillis();
        logger.info("Execution time: " + (endCount - startCount) + " milliseconds");
    }
}
