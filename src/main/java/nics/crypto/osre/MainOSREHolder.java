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

        if(args.length < 2) {
            throw new Exception("Less than 2 arguments provided. The correct format is (N, port)");
        }

        logger.info("Starting MainOSREHolder...");

        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        SocketServer socketServer = new SocketServer(port);
        SecureRandom sRNG = new SecureRandom();

        // Init encryptor
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);

        // Receive blinded key from the owner
        IntegerPolynomial blindedKey = IntegerPolynomial.fromBinary(socketServer.acceptAndReceive(), params.N, params.q);
        logger.info("Blinded key received from the owner");
        logger.info(Arrays.toString(blindedKey.coeffs));

        ///////////////////////////////
        /*
        BigInteger prime = new BigInteger("229");

        // Init encryptor and keys
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);
        EncryptionKeyPair holderKeyPair = ntruReEncrypt.generateKeyPair();

        // Send public key to the proxy
        EncryptionPublicKey holderPublicKey = holderKeyPair.getPublic();
        byte[] encodedPublicKey = holderPublicKey.getEncoded();

        int port = 5555;
        SocketClient socketClient = new SocketClient("localhost", port);
        socketClient.connectAndSend(encodedPublicKey);
        logger.info("Public key sent to the proxy");

        // TODO: modiy NTRU to use public key
        // Send *private* key to the device
        int devPort = 6666;
        socketClient = new SocketClient("localhost", devPort);
        socketClient.connectAndSend(holderKeyPair.getPrivate().getEncoded());
        logger.info("Private key sent to the device");

        // Receive encrypted share from Proxy
        SocketServer socketServer = new SocketServer(serverPort);
        byte[] encodedEncryptedShare = socketServer.acceptAndReceive();
        IntegerPolynomial encryptedShare = IntegerPolynomial.fromBinary(
            encodedEncryptedShare,
            params.N,
            params.q);
        logger.info("Ciphertext received from the proxy");

        // Decrypt and extract share
        IntegerPolynomial polyShare = ntruReEncrypt.decrypt(holderKeyPair.getPrivate(), encryptedShare);
        BigInteger share = Utils.bitArrayToBigInteger(ntruReEncrypt.decodeMessagetoBitArray(polyShare, 8)).mod(prime);
        logger.info("Received share: " + share.toString());
        */

    }

}
