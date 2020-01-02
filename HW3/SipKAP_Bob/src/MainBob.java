//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Random;

public class MainBob {

    public static void main(String[] args) throws IOException {
        Socket connection = null;
        ObjectOutputStream outputstream = null;
        ObjectInputStream inputstream = null;
        try {
            connection = new Socket("127.0.0.1", 2312);
            //εφόσον γίνει η σύνδεση με τον server, κάνουμε bind τα streams
            outputstream = new ObjectOutputStream(connection.getOutputStream());
            inputstream = new ObjectInputStream(connection.getInputStream());
            System.out.println("Streams are up and running!!");
        } catch (IOException ex) {
            System.err.println("No server found to connect, exiting");
            closeConnection(connection, inputstream, outputstream);
            System.exit(-1);
        }

        Random rand = new Random();
        boolean algorithm = rand.nextBoolean();
        if (!algorithm) {
            outputstream.writeUTF("StartSTS");
            outputstream.flush();
            new Bob(connection, outputstream, inputstream, "STS");
        } else {
            outputstream.writeUTF("StartRSA");
            outputstream.flush();
            new Bob(connection, outputstream, inputstream, "RSA");
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
