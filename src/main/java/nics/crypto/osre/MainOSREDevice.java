package nics.crypto.osre;

//import org.json.JSONObject;
import java.io.IOException;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
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

        if(args.length < 5) {
            throw new Exception("Less than 5 arguments provided. The correct format is (N, port, nC, thr, address)");
        }

        logger.info("Starting MainOSREDevice...");

        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        int nC = Integer.parseInt(args[2]);
        int nThreads = Integer.parseInt(args[3]);
        String ipAddress = args[4];
        //SocketServer socketServer = new SocketServer(port, ipAddress);
        SocketServer socketServer = new SocketServer(port);
        SecureRandom sRNG = new SecureRandom();

        // Generate a message
        int numBits = 128;
        BigInteger prime = new BigInteger("66333221577766244971668217470771604112433242586277759383795847128687502424749");
        ArrayList<BigInteger> messages = new ArrayList<BigInteger>();
        for(int i = 0; i < nC; i++) {
            messages.add(new BigInteger(numBits, sRNG).mod(prime));
        }
        logger.info("Secrets generated");

        // Receive PublicKey from Owner
        EncryptionPublicKey devicePublicKey = new EncryptionPublicKey(socketServer.acceptAndReceive());
        logger.info("Public key received from the owner");

        long tsStart = System.currentTimeMillis();

        // Init encryptor
        String paramSpecs = "EES1087EP2_FAST";
        EncryptionParameters params = NTRUReEncryptParams.getParams(paramSpecs);
        NTRUReEncrypt ntruReEncrypt = new NTRUReEncrypt(params);

        // Encrypt the message and send it to the Proxy
        SocketClient socketClientToProxy = new SocketClient("osre-proxy", port);
        for(int i = 0; i < nC; i++) {
            IntegerPolynomial polyMessage = ntruReEncrypt.encodeMessage(
                Utils.bigIntegerToBitArray(messages.get(i)), 
                SecureRandom.getSeed(64), 
                NTRUReEncryptParams.getDM0(paramSpecs)
            );
            IntegerPolynomial polyCiphertext = ntruReEncrypt.encrypt(devicePublicKey, polyMessage, SecureRandom.getSeed(64));
            socketClientToProxy.connectAndSend(polyCiphertext.toBinary(NTRUReEncryptParams.getParams(paramSpecs).q));
        }
        logger.info("Ciphertexts sent to the proxy");
        
        long tsEnd = System.currentTimeMillis();
        
        String path = "/logs/osreDevice_N" + String.valueOf(N) + "_nC" + String.valueOf(nC) + ".txt";
        FileWriter fileWriter = new FileWriter(path, true);
        fileWriter.write("---\n");
        fileWriter.write("N = " + String.valueOf(N) + "\n");
        fileWriter.write("start: " + String.valueOf(tsStart) + "\n");
        fileWriter.write("end: " + String.valueOf(tsEnd) + "\n");
        fileWriter.write("encrypt-and-send: " + String.valueOf(tsEnd - tsStart) + "\n");
        fileWriter.close();

    }

}
