package nics.crypto.osre;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.logging.Logger;

public class SocketClient {

    int port;
    String hostname;

    Logger logger = Logger.getLogger(SocketClient.class.getName());

    public SocketClient(String hostname, int port) {
        
        this.hostname = hostname;
        this.port = port;

        logger.info("New SocketClient initiated.");

    }

    public void connectAndSend(byte[] data) throws IOException {

        Socket socket = new Socket(this.hostname, this.port);

        logger.info("Socket connected to " + socket.getRemoteSocketAddress().toString());

        OutputStream outputStream = socket.getOutputStream();

        byte[] dataLength = new byte[4];
        dataLength[0] = (byte) (data.length >> 24);
        dataLength[1] = (byte) (data.length >> 16);
        dataLength[2] = (byte) (data.length >> 8);
        dataLength[3] = (byte) (data.length);
        outputStream.write(dataLength);

        outputStream.write(data);

        socket.close();

        /*
        SocketChannel socketChannel = SocketChannel.open(new InetSocketAddress(this.hostname, this.port));

        logger.info("SocketClient connected to " + socketChannel.getRemoteAddress());

        DataInputStream inputStream = new DataInputStream(socket.getInputStream());

        socketChannel.write(ByteBuffer.wrap());

        ByteBuffer buffer = ByteBuffer.wrap(data);
        socketChannel.write(buffer);

        logger.info("Data sent.");

        socketChannel.close();

        logger.info("Client's channel closed.");
        */

    }

    public static void main(String[] args) {
        try (SocketChannel socketChannel = SocketChannel.open(new InetSocketAddress("localhost", 5000))) {
            String message = "Hello, Server!";
            byte[] data = message.getBytes();

            ByteBuffer buffer = ByteBuffer.wrap(data);
            socketChannel.write(buffer);

            System.out.println("Data sent to the server.");
        } catch (IOException e) {
            System.err.println("Client exception: " + e.getMessage());
        }
    }
}
