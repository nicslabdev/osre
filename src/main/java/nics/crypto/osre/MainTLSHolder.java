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

        int id = 1;
        int port = 8443;
        
        if(args.length == 2) {
            id = Integer.parseInt(args[0]);
            port = Integer.parseInt(args[1]);
        }

        logger.info("Starting Holder server with id " + id + " and port " + port);

        String keystorePath = "certs/holder" + id + ".keystore";
        String password = "password";

        TLSServer server = new TLSServer(port, keystorePath, password);
        byte[] res = server.listen();
        logger.info("Data received: " + new BigInteger(res));

    }

}