//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.i2p.I2PException;
import net.i2p.client.I2PSession;
import net.i2p.client.streaming.I2PServerSocket;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;

public class I2PServer {

    private I2PSocketManager manager = null;
    private I2PServerSocket serverSocket = null;
    private I2PSocket socket;
    private String i2p_string = null;
    private I2PSession session = null;
    private ObjectInputStream ois; //plain χρειαζονται για να σταλει το session string
    private ObjectOutputStream oos;

    public I2PServer() {
        this.manager = I2PSocketManagerFactory.createManager(); //δημιουργούμε τον I2P manager
        this.serverSocket = manager.getServerSocket(); //μέσω του manager παίρνουμε ένα serversocket αντικείμενο
        this.session = manager.getSession(); //και με βάση τον manager δημιουργούμε το session
        this.i2p_string = session.getMyDestination().toBase64(); //τέλος, βάζουμε σε μια μεταβλητή το destination string στο οποίο πρέπει να συνδεθεί ο client
        System.out.println("Waiting for i2p connections");

    }

    public String getDestinationString() {
        return this.i2p_string;
    }

    public ObjectOutputStream getI2POutputStream() {
        return this.oos;
    }

    public ObjectInputStream getI2PInputStream() {
        return this.ois;
    }

    //αναμένουμε σύνδεση
    public void accept() {
        try {
            this.socket = this.serverSocket.accept();
            System.out.println("I2P Connection established");
            this.oos = new ObjectOutputStream(this.socket.getOutputStream());
            this.ois = new ObjectInputStream(this.socket.getInputStream());

        } catch (I2PException ex) {
            System.err.println("General I2P exception!");
        } catch (ConnectException ex) {
            System.err.println("Error connecting!");
        } catch (SocketTimeoutException ex) {
            System.err.println("Timeout!");
        } catch (IOException ex) {
            Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    //κλείσιμο των streams και Sockets
    public void close(){
        try {
            this.ois.close();
            this.oos.close();
            this.manager.destroySocketManager();
            this.session = null;
            this.i2p_string = null;
            this.serverSocket.close();
        } catch (IOException | I2PException ex) {}
    }
}
