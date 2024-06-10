package nics.crypto.osre;

//import javax.net.ssl.*;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TLSServer {

    SSLServerSocketFactory sslServerSocketFactory;
    int port;

    Logger logger = Logger.getLogger(TLSServer.class.getName());

    public TLSServer(int port, String keystorePath, String password) throws 
        KeyStoreException, FileNotFoundException, NoSuchAlgorithmException, IOException, UnrecoverableKeyException, KeyManagementException, CertificateException {

        logger.info("Starting TLS Server in port " + port);

        this.port = port;
        
        KeyStore keyStore = KeyStore.getInstance("JKS");
        FileInputStream keyStoreStream = new FileInputStream(keystorePath);
        keyStore.load(keyStoreStream, password.toCharArray());

        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, password.toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        this.sslServerSocketFactory = sslContext.getServerSocketFactory();

        //SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();

    }

    public byte[] listen() throws IOException {

        SSLServerSocket sslServerSocket = (SSLServerSocket) this.sslServerSocketFactory.createServerSocket(this.port);
        logger.info("TLS server started and listening in port " + this.port);

            
        SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
            //BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
        InputStream byteReader = sslSocket.getInputStream();

        byte[] res = new byte[17];
        byteReader.read(res);

        logger.info("Received data: " + Arrays.toString(res));

            /*
            // Read and echo the input back to the client
            String line;
            while ((line = reader.readLine()) != null) {
                logger.info("Received from device: " + line);
            }*/

        return res;
            
    }

    // Deprecated, used for testing
    public static void main(String[] args) throws Exception {
        int port = 8443;  // Port to listen on

        // Load the server's key store
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream keyStoreStream = new FileInputStream("certs/holder1.keystore")) {
            keyStore.load(keyStoreStream, "password".toCharArray());
        }

        // Set up the key manager factory
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
        keyManagerFactory.init(keyStore, "password".toCharArray());

        // Set up the SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

        // Create SSL server socket factory
        SSLServerSocketFactory sslServerSocketFactory = sslContext.getServerSocketFactory();
        try (SSLServerSocket sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(port)) {
            System.out.println("TLS server started and listening on port " + port);

            while (true) {
                try (SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept()) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                    BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));

                    // Read and echo the input back to the client
                    String line;
                    while ((line = reader.readLine()) != null) {
                        System.out.println("Received: " + line);
                        writer.write("Echo: " + line);
                        writer.newLine();
                        writer.flush();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
