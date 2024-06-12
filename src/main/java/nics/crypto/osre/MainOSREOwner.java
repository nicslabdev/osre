package nics.crypto.osre;

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

        if(args.length < 2) {
            throw new Exception("Less than 2 arguments provided. The correct format is (N, port)");
        }

        logger.info("Starting MainOSREOwner...");

        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        SocketServer socketServer = new SocketServer(port);
        SecureRandom sRNG = new SecureRandom();

        // Init encryptor and generate keys
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);
        EncryptionKeyPair deviceKeyPair = ntruReEncrypt.generateKeyPair();

        // Send public key to device
        SocketClient socketClientToDevice = new SocketClient("osre-device", port);
        socketClientToDevice.connectAndSend(deviceKeyPair.getPublic().getEncoded());
        logger.info("Public key sent to the device");

        // Generate blinded secret key
        IntegerPolynomial r = ntruReEncrypt.sampleBlinding(sRNG);
        IntegerPolynomial blindedKeyOwner = ntruReEncrypt.blindPrivateKey(r, deviceKeyPair.getPrivate());

        for(int i = 1; i <= N; i++) {
            String host = "osre-holder_" + String.valueOf(i);
            SocketClient socketClientToProxy = new SocketClient(host, port);
            socketClientToProxy.connectAndSend(blindedKeyOwner.toBinary(params.q));
            logger.info("Blinded key sent to holder " + String.valueOf(i));
        }

    }

}
