package nics.crypto.osre;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.logging.Logger;

public class SocketServer {

    int port;
    ServerSocket serverSocket;

    Logger logger = Logger.getLogger(SocketServer.class.getName());

    public SocketServer(int port) throws IOException {

        this.port = port;
        this.serverSocket = new ServerSocket(port);

        logger.info("Init new SocketServer in port " + String.valueOf(port));

    }
    
    public SocketServer(int port, String address) throws IOException {
    
    	this.port = port;
    	InetAddress bindAddr = InetAddress.getByName(address);
    	this.serverSocket = new ServerSocket(port, 50, bindAddr);
    	
    	logger.info("Init new SocketServer in port " + String.valueOf(port) + " and ip " + address);
    
    }

    public byte[] acceptAndReceive() throws IOException {

        Socket socket = this.serverSocket.accept();
        InputStream inputStream = socket.getInputStream();

        logger.info("Connection established with: " + socket.getRemoteSocketAddress().toString());

        byte[] bufferLength = new byte[4];
        bufferLength = inputStream.readNBytes(4);
        int length = ((bufferLength[0] & 0xFF) << 24) |
                     ((bufferLength[1] & 0xFF) << 16) |
                     ((bufferLength[2] & 0xFF) << 8) |
                     (bufferLength[3] & 0xFF);

        byte[] receivedData = inputStream.readNBytes(length);

        socket.close();

        return receivedData;

        /*
        ////////////
        SocketChannel socketChannel = this.serverSocketChannel.accept();
        logger.info("Connection established with: " + socketChannel.getRemoteAddress());

        ByteBuffer buffer = ByteBuffer.allocate(256);
        int bytesRead = socketChannel.read(buffer);

        if (bytesRead != -1) {
            buffer.flip();
            byte[] receivedData = new byte[buffer.remaining()];
            buffer.get(receivedData);

            logger.info("Received data: " +  Arrays.toString(receivedData));
        }

        socketChannel.close();

        return buffer.array();
        */
    }

    public void closeSocketServer() throws IOException {

        this.serverSocket.close();

        logger.info("ServerSocket channel has been closed.");

    }

    public static void main(String[] args) {
        try (ServerSocketChannel serverSocketChannel = ServerSocketChannel.open()) {
            serverSocketChannel.bind(new InetSocketAddress(5000));
            System.out.println("Server started, waiting for connections...");

            while (true) {
                try (SocketChannel socketChannel = serverSocketChannel.accept()) {
                    System.out.println("Connection established with: " + socketChannel.getRemoteAddress());

                    ByteBuffer buffer = ByteBuffer.allocate(256);
                    int bytesRead = socketChannel.read(buffer);

                    if (bytesRead != -1) {
                        buffer.flip();
                        byte[] receivedData = new byte[buffer.remaining()];
                        buffer.get(receivedData);

                        System.out.println("Received data: " + new String(receivedData));
                    }
                } catch (IOException e) {
                    System.err.println("I/O error: " + e.getMessage());
                }
            }
        } catch (IOException e) {
            System.err.println("Server exception: " + e.getMessage());
        }
    }
}
