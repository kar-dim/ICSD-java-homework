/* Dimitris Karatzas icsd13072
   Apostolos Lazaros icsd13096
 */
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.MalformedURLException;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

//η κλάση που υλοποιεί την απομακρυσμένη διεπαφη, δηλαδή αυτή η κλάση ορίζει τη ακριβώς θα κάνουν οι μεθόδοι της διεπαφής που θα χρησιμοποιεί ο client
public class AirReservationServant extends UnicastRemoteObject implements AirReservation {

    private ArrayList<Flight> f_list = new ArrayList<>();
    private Flight temp;

    public AirReservationServant() throws RemoteException {
        super();
        try {
            //Θα ανοίξουμε το αρχείο με τις πτήσεις και θα τις βάλουμε στη λίστα,πρώτα όμως ελέγχουμε αν υπάρχει ή όχι
            //η εκφώνηση λέει "Ο εξυπηρετητής διαθέτει ένα αρχείο με τις διαθέσιμες θέσεις για όλες τις πτήσεις", εμείς απλώς αποθηκεύουμε τις πτήσεις στο αρχείο
            //οπότε δεν ακολουθούμε ακριβώς την εκφώνηση αλλά από το αρχείο παίρνουμε τις διαθέσιμες πτήσεις στη συνέχεια
            //ο σερβερ πουθενά δεν ξανα αλλάζει το αρχείο (δε ζητείται), οπότε το αρχείο πρέπει να το φτιάξουμε μια φορά με τυχαίες πτήσεις 
            boolean flights = new File("flights.txt").exists();
            //αν υπάρχει απλώς παίρνουμε τις πτήσεις (και να είναι κενό δε μας ενοχλεί)
            if (flights) {
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream("flights.txt"));
                //διαβάζουμε όλο το αρχείο μέχρι να φτάσουμε στο τέλος, αν είναι άδειο δεν αλλάζει κάτι, απλώς η λίστα είναι άδεια
                while ((temp = (Flight) ois.readObject()) != null) {
                    f_list.add(temp);
                }
            } else {
                //αν δεν υπάρχει τότε απλώς το δημιουργούμε (άδειο)
                new File("flights.txt").createNewFile();
                // ο κώδικας στα σχόλια παρακάτω εκτελείται μια φορά για να δημιουργήσει τις τυχαίες πτήσεις για το πρόγραμμα
                //κάθε μία από τις 3 πτήσεις έχει μόνο 1 κράτηση στο συγκεκριμένο παράδειγμα
                ArrayList<Reservation> reservations_for_first = new ArrayList<>();
                ArrayList<Reservation> reservations_for_second = new ArrayList<>();
                ArrayList<Reservation> reservations_for_third = new ArrayList<>();
                int[] seats1 = {2, 51, 100};
                int[] seats2 = {24};
                int[] seats3 = {17, 18};
                reservations_for_first.add(new Reservation("Name1", "Lname1", seats1));
                reservations_for_second.add(new Reservation("Name1", "Lname1", seats2));
                reservations_for_third.add(new Reservation("Name2", "Lname2", seats3));

                ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("flights.txt"));
                oos.writeObject(new Flight(1, "Athens", "Prague", 120, new SimpleDateFormat("dd-MM-yyyy HH:mm").parse("10-10-2016 16:30"), reservations_for_first));
                oos.writeObject(new Flight(2, "New York", "Athens", 160, new SimpleDateFormat("dd-MM-yyyy HH:mm").parse("12-10-2016 18:00"), reservations_for_second));
                oos.writeObject(new Flight(3, "Thessaloniki", "Berlin", 120, new SimpleDateFormat("dd-MM-yyyy HH:mm").parse("17-10-2016 09:00"), reservations_for_third));
                
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream("flights.txt"));
                //διαβάζουμε όλο το αρχείο μέχρι να φτάσουμε στο τέλος
                while ((temp = (Flight) ois.readObject()) != null) {
                    f_list.add(temp);
                }
            }
        } catch (EOFException eofe) {
        } catch (RemoteException | MalformedURLException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParseException ex) {
            Logger.getLogger(AirReservationServant.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //implement τις μεθόδους
    @Override
    //έλεγχος για τον αν υπάρχούν πτήσεις με βάση τις ημερομηνίες και τις πόλεις προορισμού/αναχώρησης
    public String checkAvailability(String start, String dest, Date date) throws RemoteException {
        ArrayList<Flight> temp_list = new ArrayList<>(); //λίστα που θα επιστραφεί
        String str = "";
        if (f_list.isEmpty()) { //αν δεν υπάρχουν κρατήσεις (δηλαδή η λίστα με τις πτήσεις είναι άδεια, οπότε αν δεν έχουμε πτήσεις δεν υπάρχουν και κρατήσεις)
            return "Nothing found! EMPTY";
        } else {
            //για κάθε πτήση, παίρνουμε τα στοιχεία και ελέγχουμε αν τα στοιχεία που έδωσε ο client είναι ίδια με τη συγκεκριμένη πτήση που ελέγχουμε
            //συγκεκριμένα για όνομα/επώνυμο καθώς επίσης και για τις ημερομηνίες
            for (int i = 0; i < f_list.size(); i++) {
                if (f_list.get(i).getStart().equals(start) && (f_list.get(i).getDestination().equals(dest)) && (f_list.get(i).getDate().getDate() == date.getDate()) && (f_list.get(i).getDate().getMonth() == date.getMonth()) && (f_list.get(i).getDate().getYear() == date.getYear())) {
                    temp_list.add(f_list.get(i));
                }
            }
            //αν δε βρέθηκε τπτ τότε δεν επιστρέφει τίποτα
            if (temp_list.isEmpty()) {
                return "Nothing found!";
            } else {
                for (int i = 0; i < temp_list.size(); i++) {
                    str += temp_list.get(i).displayFlightData();
                }
                return str;
            }
        }
    }

    //αυτή η μέθοδος είναι που κάνει τη κράτηση, συγκεκριμένα παίρνει το ID του χρήστη και ελέγχει ποιες θέσεις είναι μη δεσμευμένες για τη συγκεκριμένη πτήση
    //επειδή εδώ γράφουμε στη λίστα με τις κρατήσεις, πρέπει να χρησιμοποιήσουμε synchronized
    //η 2η παράμετρος δείχνει τι θα κάνει η μέθοδος, δηλαδή
    //0: ψάξε τη λίστα με τις πτήσεις και στείλε τα δεδομένα (τις διαθεσιμες θεσεις)
    //1: θετουμε timer και περιμενουμε απαντηση
    // ο client στελνει τα δεδομενα (ονοματεπωνυμο) οποτε προσθετουμε στη συγκεκριμενη πτηση μια κρατηση (synchronized)
    @Override
    public int[] reserve(int id, final int mode, ArrayList<Integer> seats_list, ArrayList<String> names) throws RemoteException {
        //αν mode==0 σημαίνει πως ο client ζητά τις διαθέσιμες θέσεις, οπότε απλώς του τις στέλνουμε
        if (mode == 0) {
            for (int i = 0; i < f_list.size(); i++) {
                if (f_list.get(i).getId() == id) {
                    return f_list.get(i).getNonReservedSeats();
                }
            }
            //αν mode==1 σημαίνει πως ο client έχει στείλει μια λίστα με τις θέσεις που θέλει να δεσμεύσει
            //στη μεριά του server θα θέσουμε έναν Timer, αν λήξει και δε λάβουμε κάποια απάντηση από τον Client τότε δεν επιτρέπουμε στον client να συνεχίσει
            //(πρέπει να ξαναβάλει τον κωδικό, δεν είναι δύσκολο να σπαμάρει, και έτσι αν θέλει μπορεί να το κάνει συνέχεια, προφανώς δεν είναι και πολύ ασφαλές το σύστημα
            //αφού έτσι θα δεσμευόνται άσκοπα οι θέσεις)
        } else if (mode == 1) {
            /* TIMER */
            
        } //ο client έστειλε το ονοματεπώνυμο, οπότε κάνουμε δέσμευση (synchronized στο γράψιμο της λίστας)
        else if (mode == 2) {
            synchronized (this) {
                int seats[] = new int[seats_list.size()];
                for (int i = 0; i < seats_list.size(); i++) {
                    seats[i] = seats_list.get(i);
                }
                //ο client έχει στείλει τα στοιχεία οπότε μπορούμε να κάνουμε τη κράτηση
                for (int i = 0; i < f_list.size(); i++) {
                    if (f_list.get(i).getId() == id) {
                        //η μέθοδος addReservation της κλάσης Flight αυτόματα "αφαιρεί" τις θέσεις που προσθέσαμε για τη συγκεκριμένη πτήση, δηλαδή δεν θα είναι πλέον διαθέσιμες
                        f_list.get(i).addReservation(names.get(0), names.get(1), seats);
                    }
                }
            }
        }
        return null;
    }

    @Override
    public String displayReservationData(String name, String lname, int id) throws RemoteException {
        String result = "";
        //για κάθε κράτηση ελέγχουμε αν ο κάτοχος της έχει το όνομα που δόθηκε καθώς επίσης και το ID που δόθηκε
        //o έλεγχος στα ονόματα γίνεται αφού τα γράμματα γίνουν πεζά ώστε να μην υπάρχει σφάλμα αν ο χρήστης π.χ βάλει όνομα "dimitris" αντί για "Dimitris"
        for (int i = 0; i < f_list.size(); i++) {
            //έλεγχος κάθε πτήσης αν υπάρχει το id
            if (f_list.get(i).getId() == id) {
                //έλεγχος κάθε κράτησης της συγκεκριμένης πτήσης, αν βρεθούν τα στοιχεία τότε επιστρέφονται στον πελάτη, αλλιώς επιστρέφεται σφάλμα
                //ένας πελάτης μπορεί να έχει κάνει πολλές κρατήσεις οπότε προσθέτουμε στο αποτέλεσμα επιστροφής κάθε κράτηση
                for (int j = 0; j < f_list.get(i).getReservations().size(); j++) {
                    if (f_list.get(i).getReservations().get(j).getPassengerName().toLowerCase().equals(name.toLowerCase()) && f_list.get(i).getReservations().get(j).getPassengerLastName().toLowerCase().equals(lname.toLowerCase())) {
                        result += f_list.get(i).toString()+f_list.get(i).getReservations().get(j).toString()+"\n"; //η άσκηση λέει "θα εμφανίζει αναλυτικά τα στοιχεία της κράτησης", στην ουσία θα εμφανίζονται τα στοιχεία της πτήσης και της κράτησης
                        //διότι μια κράτηση ανήκει στη συγκεκριμένη πτήση, κάθε κράτηση απλώς κρατάει το όνομα και τις θέσεις, άρα θα εμφανίζονται τα στοιχεία της κράτησης και οι θέσεις
                    }
                }
            }
        }
        if (result.equals("")) {
            return "No results found!";
        }
        return result;
    }
}
