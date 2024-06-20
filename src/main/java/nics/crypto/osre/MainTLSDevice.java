package nics.crypto.osre;

import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.NTRUReEncryptParams;
import nics.crypto.osre.TLSClient;
import nics.crypto.osre.ShamirSharing;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import java.math.BigInteger;
import java.util.Random;

import java.util.logging.Logger;

public class MainTLSDevice {

    static Logger logger = Logger.getLogger(MainTLSDevice.class.getName());
    
    public static void main( String[] args ) throws Exception {
    
    		if(args.length < 4) {
            throw new Exception("Less than 4 arguments provided. The correct format is (N, port, thr, address)");
        }
        
        logger.info("Starting device...");
        
        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        int nThreads = Integer.parseInt(args[2]);
        String ipAddress = args[3];
        String truststorePath = "certs/client.truststore";
        String password = "password";
        BigInteger prime = new BigInteger("66333221577766244971668217470771604112433242586277759383795847128687502424749");

        // Generate secret
        //NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(EncryptionParameters.EES1087EP2_FAST);
        //EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();
        int mLen = 128;
        SecureRandom rng = new SecureRandom();
        BigInteger secret = new BigInteger(mLen, rng);
        logger.info("Data to send: " + secret.toString());

        long tsStart = System.currentTimeMillis();

        // Generate shares
        ArrayList<BigInteger> shares = ShamirSharing.share(secret, N, N-1, prime);

        parallelTLSConnections(nThreads, shares, port, truststorePath, password);

        long tsEnd = System.currentTimeMillis();
        logger.info("Execution time: " + (tsEnd - tsStart) + " milliseconds");
    
        String path = "/logs/tlsDevice_" + String.valueOf(N) + ".txt";
        FileWriter fileWriter = new FileWriter(path, true);
        fileWriter.write("---\n");
        fileWriter.write("N = " + String.valueOf(N) + "\n");
        fileWriter.write("start: " + String.valueOf(tsStart) + "\n");
        fileWriter.write("end: " + String.valueOf(tsEnd) + "\n");
        fileWriter.write("full-execution-time: " + String.valueOf(tsEnd - tsStart) + "\n");
        fileWriter.close();

        /*
        for(int i = 1; i <= N; i++) {
        		String hostname = "tls-holder_" + String.valueOf(i);
            //int iterPort = port + i;
            TLSClient client = new TLSClient(hostname, port, truststorePath, password);
            client.connectAndSend(shares.get(i-1).toByteArray());
        }
        long tsEnd = System.currentTimeMillis();
        logger.info("Execution time: " + (tsEnd - tsStart) + " milliseconds");
    
        String path = "/logs/tlsDevice_" + String.valueOf(N) + ".txt";
        FileWriter fileWriter = new FileWriter(path, true);
        fileWriter.write("---\n");
        fileWriter.write("N = " + String.valueOf(N) + "\n");
        fileWriter.write("start: " + String.valueOf(tsStart) + "\n");
        fileWriter.write("end: " + String.valueOf(tsEnd) + "\n");
        fileWriter.write("full-execution-time: " + String.valueOf(tsEnd - tsStart) + "\n");
        fileWriter.close();
        */
    }

    public static void parallelTLSConnections(final int nThreads, final ArrayList<BigInteger> shares, int port, String truststorePath, String password) {
        final int shareCount = shares.size();
        final int fPort = port;
        final String fTrustStorePath = truststorePath;
        final String fPassword = password;
        Thread[] threads = new Thread[nThreads];

        for(int i = 0; i < nThreads; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(new Runnable() {
                @Override
                public void run() {
                    for(int j = threadIndex + 1; j <= shareCount; j += nThreads) {
                        try {
                            String hostname = "tls-holder_" + String.valueOf(j);
                            TLSClient client = new TLSClient(hostname, fPort, fTrustStorePath, fPassword);
                            client.connectAndSend(shares.get(j-1).toByteArray());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            });
        }

        for (int i = 0; i < nThreads; i++) {
            threads[i].start();
        }

        for (int i = 0; i < nThreads; i++) {
            try {
                threads[i].join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
