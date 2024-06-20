package nics.crypto.osre;

import java.io.FileWriter;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.polynomial.IntegerPolynomial;
import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.NTRUReEncryptParams;

public class MainOSREOwner {
    
    static Logger logger = Logger.getLogger(MainOSREOwner.class.getName());

    public static void main(String[] args) throws Exception, IOException {

        if(args.length < 5) {
            throw new Exception("Less than 5 arguments provided. The correct format is (N, port, nC, thr, address)");
        }

        logger.info("Starting MainOSREOwner...");

        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        int nC = Integer.parseInt(args[2]);
        int nThreads = Integer.parseInt(args[3]);
        String ipAddress = args[4];
        //SocketServer socketServer = new SocketServer(port, ipAddress);
        SocketServer socketServer = new SocketServer(port);
        SecureRandom sRNG = new SecureRandom();

        // Init encryptor and generate keys
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);
        EncryptionKeyPair deviceKeyPair = ntruReEncrypt.generateKeyPair();

        long tsSendPKStart = System.currentTimeMillis();
        // Send public key to proxy
        SocketClient socketClientToProxy = new SocketClient("osre-proxy", port);
        socketClientToProxy.connectAndSend(deviceKeyPair.getPublic().getEncoded());
        logger.info("Public key sent to the proxy");

        long tsSendPKEnd = System.currentTimeMillis();

        // Send public key to device
        SocketClient socketClientToDevice = new SocketClient("osre-device", port);
        socketClientToDevice.connectAndSend(deviceKeyPair.getPublic().getEncoded());
        logger.info("Public key sent to the device");

        long tsBlindingStart = System.currentTimeMillis();
        // Generate blinded secret key and send to holders
        IntegerPolynomial r = ntruReEncrypt.sampleBlinding(sRNG);
        IntegerPolynomial blindedKeyOwner = ntruReEncrypt.blindPrivateKey(r, deviceKeyPair.getPrivate());

        parallelBlindedKey(nThreads, N, port, blindedKeyOwner, params.q);
        /*
        for(int i = 1; i <= N; i++) {
            String host = "osre-holder_" + String.valueOf(i);
            SocketClient socketClientToHolder = new SocketClient(host, port);
            socketClientToHolder.connectAndSend(blindedKeyOwner.toBinary(params.q));
            logger.info("Blinded key sent to holder " + String.valueOf(i));
        }
        */

        // Send blinding r to the proxy
        //SocketClient socketClientToProxy = new SocketClient("osre-proxy", port);
        socketClientToProxy.connectAndSend(r.toBinary(params.q));
        logger.info("Blinded factor r sent to proxy");

        long tsBlindingEnd = System.currentTimeMillis();
        logger.info("Blinding key time: " + (tsBlindingEnd - tsBlindingStart) + " ms");

        String path = "/logs/osreOwner_N" + String.valueOf(N) + "_nC" + String.valueOf(nC) + ".txt";
        FileWriter fileWriter = new FileWriter(path, true);
        fileWriter.write("---\n");
        fileWriter.write("N = " + String.valueOf(N) + "\n");
        fileWriter.write("pk-start: " + String.valueOf(tsSendPKStart) + "\n");
        fileWriter.write("pk-end: " + String.valueOf(tsSendPKEnd) + "\n");
        fileWriter.write("pk-total: " + String.valueOf(tsSendPKEnd - tsSendPKStart) + "\n");
        fileWriter.write("blinding-start: " + String.valueOf(tsBlindingStart) + "\n");
        fileWriter.write("blinding-end: " + String.valueOf(tsBlindingEnd) + "\n");
        fileWriter.write("blinding-total: " + String.valueOf(tsBlindingEnd - tsBlindingStart) + "\n");
        fileWriter.close();

    }

    public static void parallelBlindedKey(final int nThreads, final int N, final int port, final IntegerPolynomial blindedKeyOwner, final int q) {
        Thread[] threads = new Thread[nThreads];

        for(int i = 0; i < nThreads; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(new Runnable() {
                @Override
                public void run() {
                    for(int j = threadIndex + 1; j <= N; j+= nThreads) {
                        try {
                            String host = "osre-holder_" + String.valueOf(j);
                            SocketClient socketClientToHolder = new SocketClient(host, port);
                            socketClientToHolder.connectAndSend(blindedKeyOwner.toBinary(q));
                            logger.info("Blinded key sent to holder " + String.valueOf(j));
                        } catch (Exception e) {
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
    }
}
