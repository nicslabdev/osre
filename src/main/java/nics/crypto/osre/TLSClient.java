package nics.crypto.osre;

import java.io.*;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class TLSClient {

    SSLSocketFactory sslSocketFactory;
    int port;
    String hostname;

    Logger logger = Logger.getLogger(TLSClient.class.getName());

    public TLSClient(String hostname, int port, String keystorePath, String password) throws
        KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, KeyManagementException {

        this.port = port;
        this.hostname = hostname;

        logger.info("Starting TLS client in address (" + hostname + "," + port + ")");

        KeyStore trustStore = KeyStore.getInstance("JKS");
        FileInputStream trustStoreStream = new FileInputStream(keystorePath);
        trustStore.load(trustStoreStream, password.toCharArray());

        // Set up the trust manager factory
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(trustStore);

        // Set up the SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        // Create SSL socket factory
        this.sslSocketFactory = sslContext.getSocketFactory();

    }

    public void connectAndSend(byte[] data) throws IOException, UnknownHostException{

        SSLSocket sslSocket = (SSLSocket) this.sslSocketFactory.createSocket(this.hostname, this.port);
        sslSocket.startHandshake();

        //BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));
        OutputStream byteWriter = sslSocket.getOutputStream();

        byteWriter.write(data);

        //writer.write(data);
        //writer.newLine();
        //writer.flush();

        logger.info("Data sent to server: " + data.length + " B");

        sslSocket.close();

    }

    public static void main(String[] args) throws Exception {
        String hostname = "localhost";
        int port = 8443;

        // Load the client's trust store
        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream trustStoreStream = new FileInputStream("certs/client.truststore")) {
            trustStore.load(trustStoreStream, "password".toCharArray());
        }

        // Set up the trust manager factory
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("SunX509");
        trustManagerFactory.init(trustStore);

        // Set up the SSL context
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        // Create SSL socket factory
        SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();
        try (SSLSocket sslSocket = (SSLSocket) sslSocketFactory.createSocket(hostname, port)) {
            sslSocket.startHandshake();

            BufferedReader reader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(sslSocket.getOutputStream()));

            // Send a message to the server
            writer.write("Hello, TLS Server!");
            writer.newLine();
            writer.flush();

            // Read the response from the server
            String response = reader.readLine();
            System.out.println("Received from server: " + response);
        }
    }
}
