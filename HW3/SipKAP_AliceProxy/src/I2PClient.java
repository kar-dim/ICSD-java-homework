//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.i2p.I2PException;
import net.i2p.client.streaming.I2PSocket;
import net.i2p.client.streaming.I2PSocketManager;
import net.i2p.client.streaming.I2PSocketManagerFactory;
import net.i2p.data.Destination;

public class I2PClient {

    private I2PSocketManager manager = null;
    private I2PSocket socket;
    private String i2p_string = null;
    private ObjectInputStream ois;
    private ObjectOutputStream oos;

    public I2PClient(String dest) {
        this.manager = I2PSocketManagerFactory.createManager(); //δημιουργούμε τον I2P manager
        this.i2p_string = dest; //i2p session στέλνεται έτοιμο από server

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

    //με αυτλη τη μέθοδο γίνεται η σύνδεση στον i2p server που δείχνει το destination string
    public void accept() {
        try {
            this.socket = manager.connect(new Destination(this.i2p_string));
            System.out.println("Connected to I2P Server");
            this.ois = new ObjectInputStream(this.socket.getInputStream());
            this.oos = new ObjectOutputStream(this.socket.getOutputStream());

        } catch (I2PException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ConnectException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoRouteToHostException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InterruptedIOException ex) {
            Logger.getLogger(I2PClient.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(I2PServer.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    //κλείσιμο των streams και του i2p socket
    public void close(){
        try {
            this.ois.close();
            this.oos.close();
            this.socket.close();
        } catch (IOException ex) {}
    }
}

