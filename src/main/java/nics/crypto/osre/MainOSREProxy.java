package nics.crypto.osre;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
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

        // Init encryptor
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);

        // Receive the public key of the Device
        int port = 5555;
        SocketServer socketServer = new SocketServer(port);
        byte[] encodedPublicKey = socketServer.acceptAndReceive();
        EncryptionPublicKey devicePublicKey = new EncryptionPublicKey(encodedPublicKey);
        logger.info("Public key received from the device.");
        
        // Receive a single ciphertext from the Device
        byte[] encodedEncryptedMessage = socketServer.acceptAndReceive();
        IntegerPolynomial encryptedMessage = IntegerPolynomial.fromBinary(
            encodedEncryptedMessage,
            params.N,
            params.q);
        logger.info("Ciphertext received from the device.");

        // Receive the keys of the Holders
        byte[] encodedHolderKey1 = socketServer.acceptAndReceive();
        EncryptionPublicKey holderKey1 = new EncryptionPublicKey(encodedHolderKey1);
        logger.info("Public key received from holder 1.");
        byte[] encodedHolderKey2 = socketServer.acceptAndReceive();
        EncryptionPublicKey holderKey2 = new EncryptionPublicKey(encodedHolderKey2);
        logger.info("Public key received from holder 2.");

        // Receive re-encryption keys from the device
        ReEncryptionKey rkH1 = new ReEncryptionKey(socketServer.acceptAndReceive());
        ReEncryptionKey rkH2 = new ReEncryptionKey(socketServer.acceptAndReceive());
        logger.info("ReEncryption keys received from the device.");

        // Perform OSRE to the single ciphertext
        //BigInteger prime = new BigInteger("66333221577766244971668217470771604112433242586277759383795847128687502424749");
        BigInteger prime = new BigInteger("229");
        OSRE osre = new OSRE(encryptedMessage, 2, 1, prime, paramSpecs);
        List<BigInteger> coefficients = osre.sampleCoefficients();
        for(BigInteger c : coefficients) {
            logger.info(c.toString());
        }
        BigInteger partialPolyHolder1 = osre.computePartialPoly(1, coefficients);
        BigInteger partialPolyHolder2 = osre.computePartialPoly(2, coefficients);
        IntegerPolynomial encryptedShareHolder1withDevice = osre.encryptPartialShare(1, coefficients, devicePublicKey);
        IntegerPolynomial encryptedShareHolder2withDevice = osre.encryptPartialShare(2, coefficients, devicePublicKey);
        IntegerPolynomial encryptedShareHolder1 = ntruReEncrypt.reEncrypt(rkH1, encryptedShareHolder1withDevice, SecureRandom.getSeed(64));
        IntegerPolynomial encryptedShareHolder2 = ntruReEncrypt.reEncrypt(rkH2, encryptedShareHolder2withDevice, SecureRandom.getSeed(64));

        // Send each encrypted share to each Holder
        SocketClient socketClient1 = new SocketClient("localhost", 7001);
        socketClient1.connectAndSend(encryptedShareHolder1.toBinary(params.q));
        SocketClient socketClient2 = new SocketClient("localhost", 7002);
        socketClient2.connectAndSend(encryptedShareHolder2.toBinary(params.q));
        logger.info("Encrypted shares sent to the holders.");

        /*
        //// OSRE //////////
        String params = "EES1087EP2_FAST";
        NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(NTRUReEncryptParams.getParams(params));
        EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();
        IntegerPolynomial m = ntruReEnc.message(new byte[]{12,34,56});
        int N = 3;
        // TODO: init OSRE with a real encrypted message, not directly with m
        OSRE osre = new OSRE(m, N, 2, new BigInteger("11"), params);
        List<BigInteger> coeffs = osre.sampleCoefficients();
        for (BigInteger c : coeffs) {
            logger.info("COEFF: " + c.toString());
        }
        for (int i = 1; i <= N; i++) {
            logger.info("SHARE " + String.valueOf(i) + ": " + osre.computePartialPoly(i, coeffs).toString());
        }

        IntegerPolynomial share1 = osre.encryptPartialShare(1, coeffs, kpA.getPublic());
        logger.info(Arrays.toString(share1.coeffs));
        IntegerPolynomial share2 = osre.encryptPartialShare(2, coeffs, kpA.getPublic());
        logger.info(Arrays.toString(share2.coeffs));
        */
    }

}
