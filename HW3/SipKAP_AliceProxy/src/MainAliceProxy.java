//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MainAliceProxy {

    public static void main(String[] args) {
        try (ServerSocket server = new ServerSocket(1312)) {
            System.out.println("Waiting for connection....");
            while (true) {
                Socket connection = server.accept(); //περιμένουμε σύνδεση από client
                System.out.println("Client: " + connection.getInetAddress().getHostName() + " connected!");
                //αφού συνδεθεί ο client, κάνουμε bind τα streams
                ObjectInputStream inputstream = new ObjectInputStream(connection.getInputStream());
                ObjectOutputStream outputstream = new ObjectOutputStream(connection.getOutputStream());
                System.out.println("Streams are up and running!");

                //1ο μήνυμα του πρωτοκόλλου είναι μήνυμα από τον client στον server
                //στο οποίο ο client γράφει ποιον αλγόριθμο θέλει να χρησιμοποιηθεί για το key agreement
                String choice = inputstream.readUTF();
                if (choice.equals("StartSTS")) {
                    new Thread(new AliceProxy(connection, outputstream, inputstream, "RSA")).start();
                } else if (choice.equals("StartRSA")) {
                    new Thread(new AliceProxy(connection, outputstream, inputstream, "RSA")).start();
                } else {
                    throw new UnknownProtocolCommandException("Error\nTerminating program....");
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(MainAliceProxy.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnknownProtocolCommandException ex) {
            Logger.getLogger(MainAliceProxy.class.getName()).log(Level.SEVERE, null, ex);
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
