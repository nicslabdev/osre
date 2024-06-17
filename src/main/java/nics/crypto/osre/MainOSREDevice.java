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

        if(args.length < 3) {
            throw new Exception("Less than 3 arguments provided. The correct format is (N, port, address)");
        }

        logger.info("Starting MainOSREDevice...");

        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        String ipAddress = args[2];
        //SocketServer socketServer = new SocketServer(port, ipAddress);
        SocketServer socketServer = new SocketServer(port);
        SecureRandom sRNG = new SecureRandom();

        // Init encryptor
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);
        
        // Receive PublicKey from Owner
        EncryptionPublicKey devicePublicKey = new EncryptionPublicKey(socketServer.acceptAndReceive());
        logger.info("Public key received from the owner");

        // Send public key to the proxy
        SocketClient socketClientToProxy = new SocketClient("osre-proxy", port);
        socketClientToProxy.connectAndSend(devicePublicKey.getEncoded());
        logger.info("Public key sent to the proxy");

        // Generate a message
        int numBits = 128;
        BigInteger prime = new BigInteger("66333221577766244971668217470771604112433242586277759383795847128687502424749");
        BigInteger m = new BigInteger(numBits, sRNG).mod(prime);
        logger.info("Secret generated: " + m.toString());

        // Encrypt the message and send it to the Proxy
        IntegerPolynomial polyMessage = ntruReEncrypt.encodeMessage(
            Utils.bigIntegerToBitArray(m), 
            SecureRandom.getSeed(64), 
            NTRUReEncryptParams.getDM0(paramSpecs)
        );
        IntegerPolynomial polyCiphertext = ntruReEncrypt.encrypt(devicePublicKey, polyMessage, SecureRandom.getSeed(64));
        socketClientToProxy.connectAndSend(polyCiphertext.toBinary(NTRUReEncryptParams.getParams(paramSpecs).q));
        logger.info("Ciphertext sent to the proxy");

        //////////////////////////////////////////////////////////////////////
        /*

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

        */
    }

}
