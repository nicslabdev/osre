package nics.crypto.osre;

import java.util.Arrays;
import java.util.logging.Logger;

import java.math.BigInteger;

import nics.crypto.ntrureencrypt.*;
import net.sf.ntru.encrypt.*;
//import nics.crypto.ntrureencrypt.Utils;

public class MainTLSHolder {

    static Logger logger = Logger.getLogger(MainTLSHolder.class.getName());
    
    public static void main(String[] args) throws Exception {
    
    		if(args.length < 5) {
            throw new Exception("Less than 4 arguments provided. The correct format is (N, port, thr, address, id)");
        }
        
        logger.info("Starting Holder...");
        
        // Init variables
        int N = Integer.parseInt(args[0]);
        int port = Integer.parseInt(args[1]);
        int nThreads = Integer.parseInt(args[2]);
        String ipAddress = args[3];
        int id = Integer.parseInt(args[4]);

        logger.info("Starting Holder server with id " + id + " and port " + port);

        String keystorePath = "certs/holder_" + id + ".keystore";
        String password = "password";

        TLSServer server = new TLSServer(port, keystorePath, password);
        byte[] res = server.listen();
        logger.info("Data received: " + new BigInteger(res));

    }

}
