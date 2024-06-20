package nics.crypto.osre;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.NTRUReEncryptParams;
import nics.crypto.ntrureencrypt.Utils;
import nics.crypto.osre.SocketServer;

import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.polynomial.IntegerPolynomial;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.EncryptionPrivateKey;

public class MainOSREHolder {
    
    static Logger logger = Logger.getLogger(MainOSREHolder.class.getName());

    public static void main(String[] args) throws Exception {

        if(args.length < 5) {
            throw new Exception("Less than 5 arguments provided. The correct format is (N, port, nC, thr, address)");
        }

        logger.info("Starting MainOSREHolder...");

        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        int nC = Integer.parseInt(args[2]);
        int nThreads = Integer.parseInt(args[3]);
        String ipAddress = args[4];
        //SocketServer socketServer = new SocketServer(port, ipAddress);
        SocketServer socketServer = new SocketServer(port);
        SecureRandom sRNG = new SecureRandom();
        int numBits = 128;

        // Init encryptor and generate keys
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);
        EncryptionKeyPair holderKeyPair = ntruReEncrypt.generateKeyPair();

        // Receive blinded key from the owner
        IntegerPolynomial blindedKey = IntegerPolynomial.fromBinary(socketServer.acceptAndReceive(), params.N, params.q);
        logger.info("Blinded key received from the owner");

        // Add the holder secret key factor and send to the proxy (after receiving request)
        byte[] request = socketServer.acceptAndReceive();

        IntegerPolynomial blindedReEncKey = ntruReEncrypt.blindInversePrivateKey(blindedKey, holderKeyPair.getPrivate());
        SocketClient socketClientToProxy = new SocketClient("osre-proxy", port);
        socketClientToProxy.connectAndSend(blindedReEncKey.toBinary(params.q));
        logger.info("Blinded ReEncKey sent to proxy");

        for(int i = 0; i < nC; i++) {
            // Receive encrypted share from the proxy
            IntegerPolynomial encryptedShare = IntegerPolynomial.fromBinary(socketServer.acceptAndReceive(), params.N, params.q);
            IntegerPolynomial share = ntruReEncrypt.decrypt(holderKeyPair.getPrivate(), encryptedShare);
            BigInteger intShare = ntruReEncrypt.decodeMessagetoBigInteger(share, numBits);
            logger.info("Share received from the proxy: " + intShare.toString());
        }

    }

}
