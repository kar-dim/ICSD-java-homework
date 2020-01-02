//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Main {

    public static void main(String[] args) {
        ServerSocket server;
        Socket connection = null;
        ObjectOutputStream outputstream = null;
        ObjectInputStream inputstream = null;
        try {
            server = new ServerSocket(1312);
            System.out.println("Waiting for connection....");
            connection = server.accept(); //περιμένουμε σύνδεση από client
            System.out.println("Client: " + connection.getInetAddress().getHostName() + " connected!");
            //αφού συνδεθεί ο client, κάνουμε bind τα streams
            inputstream = new ObjectInputStream(connection.getInputStream());
            outputstream = new ObjectOutputStream(connection.getOutputStream());
            System.out.println("Streams are up and running!");
            //1ο μήνυμα του πρωτοκόλλου είναι μήνυμα από τον client στον server
            //στο οποίο ο client γράφει ποιον αλγόριθμο θέλει να χρησιμοποιηθεί για το key agreement
            String choice = inputstream.readUTF();
            if (choice.equals("StartRSA")) {
                new Server_RSA(connection, outputstream, inputstream);
            } else if (choice.equals("StartDH")) {
                new Server_DH(connection, outputstream, inputstream);
            } else if (choice.equals("StartSts")) {
                new Server_StS(connection, outputstream, inputstream);
            } else {
                throw new UnknownProtocolCommandException("Error\nTerminating program....");
            }
        } catch (IOException ex) {
            System.err.println("Error while accepting connections");
            closeConnection(connection, inputstream, outputstream);
            System.exit(-1);
        } catch (UnknownProtocolCommandException ex) {
            closeConnection(connection, inputstream, outputstream);
            System.exit(-1);
        }
    }

    //κλείνει τη σύνδεση
    private static void closeConnection(Socket connection, ObjectInputStream inputstream,
            ObjectOutputStream outputstream) {
        try {
            if (outputstream != null && inputstream != null) {
                outputstream.close();
                inputstream.close();
            }
            connection.close();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("Error while closing session....");
        }
    }
}
