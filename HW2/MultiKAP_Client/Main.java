//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws IOException {
        Socket connection = null ;
        ObjectOutputStream outputstream = null;
        ObjectInputStream inputstream = null;
        Scanner scan = new Scanner(System.in);
        boolean selected=false;
        try {
            connection = new Socket("127.0.0.1",1312);
            //εφόσον γίνει η σύνδεση με τον server, κάνουμε bind τα streams
            outputstream = new ObjectOutputStream(connection.getOutputStream());
            inputstream = new ObjectInputStream(connection.getInputStream());
            System.out.println("Streams are up and running!!");
        } catch (IOException ex) {
            System.err.println("No server found to connect, exiting");
            closeConnection(connection, inputstream, outputstream);
            System.exit(-1);
        }
        //εδώ ο client επιλέγει ποιον αλγόριθμο θέλει να χρησιμοποιήσει
        while(!selected){
            System.out.println("Select a key-exchange method\n1: Encapsulation\n2: Diffie-Hellman\n3:StS Protocol");
            int choice = scan.nextInt();
            if (choice==1){
                outputstream.writeUTF("StartRSA");
                outputstream.flush();
                new Client_RSA(connection, outputstream, inputstream);
                selected=true;
            } else if (choice==2){
                outputstream.writeUTF("StartDH");
                outputstream.flush();
                new Client_DH(connection, outputstream, inputstream);
                selected=true;
            } else if (choice==3){
                outputstream.writeUTF("StartSts");
                outputstream.flush();
                new Client_Sts(connection, outputstream, inputstream);
                selected=true;
            } else {
                System.err.println("Wrong choice, please type 1,2 or 3");
            }
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
