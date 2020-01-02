/* Dimitris Karatzas icsd13072
   Apostolos Lazaros icsd13096
*/
//η απομακρυσμένη διεπαφή μας, παρέχει τις ενέργειες που θα εφαρμόσει ο client

import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Date;

public interface AirReservation extends Remote{
    
    String checkAvailability(String start, String dest, Date date) throws RemoteException;
    int[] reserve(int id, final int mode, ArrayList<Integer> seats_list, ArrayList<String> names) throws RemoteException;
    String displayReservationData( String name, String lname, int id) throws RemoteException;
}
