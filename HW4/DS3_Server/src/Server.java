/* Dimitris Karatzas icsd13072
   Apostolos Lazaros icsd13096
 */
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server {

    public static void main(String[] args) {
        try {
            java.rmi.registry.LocateRegistry.createRegistry(1099);
            System.setProperty("Djava.rmi.server.codebase", "rmi://localhost/ReservationService/");
            // String name = "rmi://localhost/ReservationService/";
            //bind το remote object στη συγκεκριμένη διεύθυνση (localhost/ReservationService), οι χρήστες που θέλουν
            //να εκτελούν τις μεθόδους του interface πρέπει να κοιτάξουν σε αυτή τη διεύθυνση
            AirReservationServant servant = new AirReservationServant();
            java.rmi.registry.LocateRegistry.getRegistry().bind("ReservationService", servant);
            //Naming.rebind(name, servant);

        } catch (RemoteException | AlreadyBoundException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
