package nics.crypto.osre;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Logger;

import nics.crypto.ntrureencrypt.NTRUReEncrypt;
import nics.crypto.ntrureencrypt.NTRUReEncryptParams;
import nics.crypto.ntrureencrypt.ReEncryptionKey;
import nics.crypto.ntrureencrypt.Utils;
import nics.crypto.osre.SocketClient;

import net.sf.ntru.encrypt.EncryptionParameters;
import net.sf.ntru.encrypt.EncryptionPublicKey;
import net.sf.ntru.encrypt.EncryptionPrivateKey;
import net.sf.ntru.encrypt.EncryptionKeyPair;
import net.sf.ntru.polynomial.IntegerPolynomial;

public class MainOSREDevice {
    
    static Logger logger = Logger.getLogger(MainOSREDevice.class.getName());

    public static void main(String[] args) throws Exception, IOException {

        long startTime = System.currentTimeMillis();

        SecureRandom sRNG = new SecureRandom();

        // Generate a message
        //int numBits = 128;
        int numBits = 8;
        //BigInteger prime = new BigInteger("66333221577766244971668217470771604112433242586277759383795847128687502424749");
        BigInteger prime = new BigInteger("229");
        BigInteger m = new BigInteger(numBits, sRNG).mod(prime);
        logger.info("Secret generated: " + m.toString());

        // Init encryptor and keys
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);
        EncryptionKeyPair deviceKeyPair = ntruReEncrypt.generateKeyPair();

        // Send public key to the proxy
        EncryptionPublicKey devicePublicKey = deviceKeyPair.getPublic();
        byte[] encodedPublicKey = devicePublicKey.getEncoded();

        int port = 5555;
        SocketClient socketClient = new SocketClient("localhost", port);
        socketClient.connectAndSend(encodedPublicKey);
        logger.info("Public key sent to the proxy.");

        // Encrypt the message and send it to the Proxy
        IntegerPolynomial polyMessage = ntruReEncrypt.encodeMessage(
            Utils.bigIntegerToBitArray(m), 
            SecureRandom.getSeed(64), 
            NTRUReEncryptParams.getDM0(paramSpecs)
        );
        IntegerPolynomial polyCiphertext = ntruReEncrypt.encrypt(devicePublicKey, polyMessage, SecureRandom.getSeed(64));

        socketClient.connectAndSend(polyCiphertext.toBinary(NTRUReEncryptParams.getParams(paramSpecs).q));
        logger.info("Ciphertext sent to the proxy.");

        // TODO: modify NtruReEncrypt to derive the re-encryption key with the public key or through an interactive protocol
        // Receive the private keys of the holders
        int devPort = 6666;
        SocketServer socketServer = new SocketServer(devPort);

        byte[] encodedPrivateKeyHolder1 = socketServer.acceptAndReceive();
        EncryptionPrivateKey privateKeyHolder1 = new EncryptionPrivateKey(encodedPrivateKeyHolder1);
        logger.info("Private key received from holder 1.");

        byte[] encodedPrivateKeyHolder2 = socketServer.acceptAndReceive();
        EncryptionPrivateKey privateKeyHolder2 = new EncryptionPrivateKey(encodedPrivateKeyHolder2);
        logger.info("Private key received from holder 2.");

        // Derive re-encryption keys and send them to the proxy
        ReEncryptionKey rkHolder1 = ntruReEncrypt.generateReEncryptionKey(deviceKeyPair.getPrivate(), privateKeyHolder1);
        ReEncryptionKey rkHolder2 = ntruReEncrypt.generateReEncryptionKey(deviceKeyPair.getPrivate(), privateKeyHolder2);
        socketClient.connectAndSend(rkHolder1.getEncoded());
        socketClient.connectAndSend(rkHolder2.getEncoded());
        logger.info("ReEncryption keys sent to the proxy.");

        long endTime = System.currentTimeMillis();
        logger.info("Starting time: " + startTime);
        logger.info("Final time: " + endTime);

    }

}
