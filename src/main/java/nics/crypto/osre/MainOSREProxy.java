package nics.crypto.osre;

import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.logging.Logger;
import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.NTRUReEncryptParams;
import nics.crypto.ntrureencrypt.ReEncryptionKey;
import nics.crypto.osre.OSRE;
import nics.crypto.osre.SocketClient;
import nics.crypto.osre.SocketServer;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.encrypt.EncryptionPublicKey;

public class MainOSREProxy {
    
    static Logger logger = Logger.getLogger(MainOSREProxy.class.getName());

    public static void main(String[] args) throws Exception {

        if(args.length < 5) {
            throw new Exception("Less than 5 arguments provided. The correct format is (N, port, nC, thr, address)");
        }

        logger.info("Starting MainOSREProxy...");

        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        int nC = Integer.parseInt(args[2]);
        int nThreads = Integer.parseInt(args[3]);
        String ipAddress = args[4];
        //SocketServer socketServer = new SocketServer(port, ipAddress);
        SocketServer socketServer = new SocketServer(port);
        SecureRandom sRNG = new SecureRandom();
        BigInteger prime = new BigInteger("66333221577766244971668217470771604112433242586277759383795847128687502424749");

        // Init encryptor
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);


        long tsKeysStart = System.currentTimeMillis();
        // Receive PublicKey from Owner
        EncryptionPublicKey devicePublicKey = new EncryptionPublicKey(socketServer.acceptAndReceive());
        logger.info("Public key received from the owner");

        ArrayList<IntegerPolynomial> encryptedMessages = new ArrayList<IntegerPolynomial>();
        for(int i = 0; i < nC; i++) {
            // Receive a single ciphertext from the Device
            byte[] encodedEncryptedMessage = socketServer.acceptAndReceive();
            IntegerPolynomial encryptedMessage = IntegerPolynomial.fromBinary(
                encodedEncryptedMessage,
                params.N,
                params.q);
            encryptedMessages.add(encryptedMessage);
        }
        logger.info("Ciphertexts received from the device");

        // Receive the blinding factor r from the owner
        byte[] encodedBlinding = socketServer.acceptAndReceive();
        IntegerPolynomial r = IntegerPolynomial.fromBinary(
            encodedBlinding,
            params.N,
            params.q);
        logger.info("Blinding factor r received from the owner");

        // Receive the blinded key from each holder (pull request)
        ConcurrentLinkedQueue<ReEncryptionKey> reEncryptionKeysTMP = parallelReEncKeys(nThreads, N, port, params, r, socketServer, ntruReEncrypt);
        /*
        ArrayList<ReEncryptionKey> reEncryptionKeys = new ArrayList<ReEncryptionKey>();
        for(int i = 1; i <= N; i++) {
            String hostname = "osre-holder_" + String.valueOf(i);
            SocketClient socketClientToHolder = new SocketClient(hostname, port);
            socketClientToHolder.connectAndSend(new byte[]{1});

            IntegerPolynomial blindedReEncKey = IntegerPolynomial.fromBinary(socketServer.acceptAndReceive(), params.N, params.q);
            logger.info("BlindedReEncKey received from holder");

            reEncryptionKeys.add(new ReEncryptionKey(ntruReEncrypt.extractBlinding(r, blindedReEncKey).coeffs, params.q));
        }
        */

        long tsKeysEnd = System.currentTimeMillis();

        logger.info("tsKeysEnd: " + (tsKeysEnd - tsKeysStart) + " ms");

        ArrayList<ReEncryptionKey> reEncryptionKeys = new ArrayList<>(reEncryptionKeysTMP);

        long tsOSREStart = System.currentTimeMillis();
        
        for(int j = 0; j < nC; j++) {
            // OSRE
            OSRE osre = new OSRE(encryptedMessages.get(j), N, N-1, prime, paramSpecs);
            List<BigInteger> coefficients = osre.sampleCoefficients();
            for(int i = 1; i <= N; i++) {
                IntegerPolynomial encryptedPartialShare = osre.encryptPartialShare(i, coefficients, devicePublicKey);
                IntegerPolynomial reEncryptedPartialShare = ntruReEncrypt.reEncrypt(reEncryptionKeys.get(i-1), encryptedPartialShare, SecureRandom.getSeed(64));

                // Send share to holder i
                String hostname = "osre-holder_" + String.valueOf(i);
                SocketClient socketClientToHolder = new SocketClient(hostname, port);
                socketClientToHolder.connectAndSend(reEncryptedPartialShare.toBinary(params.q));
                logger.info("Encrypted share sent to holder " + String.valueOf(i));
            }
        }
        long tsOSREEnd = System.currentTimeMillis();

        String path = "/logs/osreProxy_N" + String.valueOf(N) + "_nC" + String.valueOf(nC) + ".txt";
        FileWriter fileWriter = new FileWriter(path, true);
        fileWriter.write("---\n");
        fileWriter.write("N = " + String.valueOf(N) + "\n");
        fileWriter.write("key-start: " + String.valueOf(tsKeysStart) + "\n");
        fileWriter.write("key-end: " + String.valueOf(tsKeysEnd) + "\n");
        fileWriter.write("key-total: " + String.valueOf(tsKeysEnd - tsKeysStart) + "\n");
        fileWriter.write("osre-start: " + String.valueOf(tsOSREStart) + "\n");
        fileWriter.write("osre-end: " + String.valueOf(tsOSREEnd) + "\n");
        fileWriter.write("osre-total: " + String.valueOf(tsOSREEnd - tsOSREStart) + "\n");
        fileWriter.close();

    }

    public static ConcurrentLinkedQueue<ReEncryptionKey> parallelReEncKeys(final int nThreads, final int N, final int port, final EncryptionParameters params, final IntegerPolynomial r, final SocketServer socketServer, final NTRUReEncrypt ntruReEncrypt) {
        Thread[] threads = new Thread[nThreads];
        final ConcurrentLinkedQueue<ReEncryptionKey> results = new ConcurrentLinkedQueue<>();

        for(int i = 0; i < nThreads; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(new Runnable() {
                @Override
                public void run() {
                    for(int j = threadIndex + 1; j <= N; j += nThreads) {
                        try {
                            String hostname = "osre-holder_" + String.valueOf(j);
                            SocketClient socketClientToHolder = new SocketClient(hostname, port);
                            socketClientToHolder.connectAndSend(new byte[]{1});
                            IntegerPolynomial blindedReEncKey = IntegerPolynomial.fromBinary(socketServer.acceptAndReceive(), params.N, params.q);
                            logger.info("BlindedReEncKey received from holder");
                            results.add(new ReEncryptionKey(ntruReEncrypt.extractBlinding(r, blindedReEncKey).coeffs, params.q));
                        } catch(Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            });
        }

        for(int i = 0; i < nThreads; i++) {
            threads[i].start();
        }

        for(int i = 0; i < nThreads; i++) {
            try {
                threads[i].join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        return results;
    }

}
