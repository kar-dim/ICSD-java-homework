/* icsd13072 Karatzas Dimitris
   icsd13096 Lazaros Apostolos*/
//η κλάση του server, χρειαζόμαστε νήματα διότι θα εξυπηρετούνται πολλοί πελάτες ταυτόχρονα
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Server implements Runnable {

    private final Socket sock;
    private static ArrayList<User> logged_in = new ArrayList<>(); //τη χρησιμοποιούμε για να ελέγξουμε αν ένας χρήστης προσπαθεί να κάνει ξανα Log in
    private static ArrayList<Announcement> announcements = new ArrayList<>(); //η λίστα των ανακοινώσεων
    private static ArrayList<User> users = new ArrayList<>();

    //o constructor της κλάσης καλείται στην main static μέθοδο για να δημιουργήσει το νεο thread
    //είναι πολύ σημαντικό το ότι περνάμε στο νέο thread της κλάσης Server τις ιδιότητες με τις λίστες, διότι τα νήματα πρέπει να αλλάζουν ιδιότητες οι οποίες
    //πρέπει να είναι κοινές για τα νήματα (όπως οι λίστες), αλλιώς θα είχαν τις δικές τους (άδειες αρχικά εκτός από τη λίστα Users) λίστες και δε θα είχαν πρόσβαση στα σωστά στοιχεία
    public Server(Socket soc, ArrayList<User> logged, ArrayList<Announcement> announces, ArrayList<User> users) {
        sock = soc;
        logged_in = new ArrayList<>(logged);
        announcements = new ArrayList<>(announces);
        //προσθήκη administrators
        users.add(new User("admin1", "admin1", "admin_a", "admin_aa"));
        users.add(new User("admin2", "admin2", "admin_b", "admin_bb"));
    }

    //η main όταν τρέξει αυτόματα θα δημιουργεί συνέχεια Threads για κάθε accept της serversocket
    //έτσι δεν θα περιμένει να τελειώσει κάποια accept αλλά θα τρέχουν παράλληλα πολλά threads
    public static void main(String[] args) {
        try {
            ServerSocket sc = new ServerSocket(5555); //5555 port
            while (true) {
                Socket sock = sc.accept();
                new Thread(new Server(sock, logged_in, announcements, users)).start();
            }
        } catch (IOException ioe) {
            System.out.print("Can't make the connection with the client");
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ioe);
        }
    }

    //κάθε νήμα θα εκτελεί τον παρακάτω κώδικα, δηλαδή για κάθε σύνδεση σε client (σε κάθε accept δηλαδή, όπως
    //φαίνεται και από την main μέθοδο) θα τρέχει η run() η οποία κάνει όλη τη δουλεία του server
    @Override
    public void run() {
        Message msg;
        try {
            //παίρνουμε τα streams
            ObjectInputStream ois = new ObjectInputStream(sock.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(sock.getOutputStream());

            /* εδώ ξεκινάει η μεταφορά οφέλιμων δεδομένων μεταξύ client και server */
            //ακολουθόντας το πρωτόκολλο, ο server παίρνει ένα μήνυμα START από κάθε client και έπειτα του στέλνουμε μήνυμα STARTED
            //έπειτα ο client μπορεί να στείλει ό,τι μήνυμα θέλει από τα διαθέσιμα μηνύματα του πρωτοκόλλου (INSERT,DELETE,REGISTER,LOGIN,EDIT/DELETE,EDIT,END)
            while (true) {
                msg = (Message) ois.readObject();
                //ο έλεγχος είναι περιττός για τη συγκεκριμένη εφαρμογή, αφού πάντα στέλνεται το START αλλά καλύτερα να είμαστε τυπικοί
                if (msg.getMessage().equals("START")) {
                    oos.writeObject(new Message("STARTED"));
                    oos.flush();
                } else {
                    oos.writeObject(new Message("BAD FORMAT"));
                    oos.flush();
                }
                //εφόσον τελείωσε η χειραψία, τώρα θα αναμένουμε κάποιο μήνυμα από τον client για κάποια ενέργεια
                msg = (Message) ois.readObject();
                //αν ο client στείλει REGISTER τότε ψάχνουμε στη λίστα του σερβερ αν έχει τον χρήστη ήδη, αν υπάρχει τότε δεν τον βάζουμε και στέλνουμε error
                //αν δεν υπάρχει τον προσθέτουμε και στέλνουμε μήνυμα επιτυχίας
                if (msg.getMessage().equals("REGISTER")) {
                    boolean exists = false;
                    //έλεγχος αν ο χρήστης είναι ήδη εγγεγραμμένος, αν η λίστα με τους χρήστες είναι άδεια τότε απλά τον βάζουμε (δηλαδή δε θα μπει στο loop και το if (exists==false) θα τον βαλει
                    for (int i = 0; i < users.size(); i++) {
                        if (users.get(i).getUsername().equals(msg.getUser().getUsername())) {
                            exists = true;
                            //μήνυμα λάθους
                            oos.writeObject(new Message("REGISTER FAIL"));
                            oos.flush();
                            break;
                        }
                    }
                    if (exists == false) {
                        //επειδή θα γράψουμε στη λίστα, αναγκαία χρειάζεται συγχρονισμός
                        synchronized (this) {
                            users.add(new User(msg.getUser()));
                        }
                        //μήνυμα επιτυχίας
                        oos.writeObject(new Message("REGISTER OK"));
                        oos.flush();
                    }

                } //αν σταλεί μήνυμα για LOGIN, τότε ελέγχουμε στη λίστα αν υπάρχει ο χρήστης, αν δεν υπάρχει μήνυμα λάθος (ίδια λογική με register)
                //δε χρειαζόμαστε συγχρονισμό εδώ επειδή έχουμε μόνο διάβασμα
                else if (msg.getMessage().equals("LOGIN")) {
                    boolean exists = false, is_already_logged_in = false;
                    int index = -1; //θέση στον πίνακα users του χρήστη που βρέθηκε (αν βρεθεί)
                    loop:
                    for (int i = 0; i < users.size(); i++) {
                        if (users.get(i).getUsername().equals(msg.getUser().getUsername())) {
                            exists = true;
                            index = i;
                            //έλεγχος αν είναι ήδη Logged in, αν είναι τότε μήνυμα λάθους, αλλιώς ΟΚ
                            for (int j = 0; j < logged_in.size(); j++) {
                                if (msg.getUser().getUsername().equals(logged_in.get(j).getUsername())) {
                                    is_already_logged_in = true;
                                    break loop;
                                }
                            }
                            break;
                        }
                    }
                    //αν δεν υπάρχει στη λίστα στέλνουμε στον client μήνυμα ότι δεν έχει κάνει register, ή αν είναι ήδη logged in (άλλη λίστα αυτή)
                    if (exists == false || is_already_logged_in) {
                        oos.writeObject(new Message("LOGIN FAIL"));
                        oos.flush();
                    }
                    //έλεγχος του password
                    if (exists && is_already_logged_in == false) {
                        if (users.get(index).getPassword().equals(msg.getUser().getPassword())) {
                            //ενημέρωση του Logged_in arraylist ώστε να μπει στη λίστα ο χρήστης που συνδέθηκε τώρα
                            //synchronized λόγω ότι αλλάζει ο κοινός πόρος των νημάτων
                            synchronized (this) {
                                logged_in.add(new User(msg.getUser()));
                            }
                            oos.writeObject(new Message("LOGIN OK"));
                            oos.flush();
                        } //αν ο κωδικός δεν είναι σωστός, τότε μήνυμα λάθους
                        else {
                            oos.writeObject(new Message("LOGIN FAIL"));
                            oos.flush();
                        }
                    }

                } else if (msg.getMessage().equals("CREATE")) {

                    //εδώ δε χρειάζεται έλεγχος για το αν ο χρήστης υπάρχει, αφού για να μπορεί να κάνει εισαγωγή κάποιας ανακοίνωσης σημαίνει πως 
                    //έχει ήδη κάνει login, αυτό απλουστεύει τη διαδικασία εισαγωγής, διότι θα υπάρχει ήδη στη λίστα με τους χρήστες ο χρήστης αυτός
                    //υποθέτουμε ότι ο κάθε χρήστης μπορεί να κάνει όσες ανακοινώσεις θέλει, οπότε δεν υπάρχει μεγάλη πιθανότητα να υπάρχει
                    //κάποιο λάθος στη προσθήκη της ανακοίνωσης στη λίστα, αλλά τυπικά το ελέγχουμε
                    try {
                        //synchronized block επειδή γράφουμε στη λίστα
                        synchronized (this) {
                            announcements.add(msg.getAnnouncement());
                        }
                        oos.writeObject(new Message("CREATE OK"));
                        oos.flush();
                    } catch (Exception e) {
                        oos.writeObject(new Message("CREATE FAIL"));
                        oos.flush();
                    }

                    //αν ο client στείλει EDIT/DELETE σημαίνει πως θέλει να του στείλουμε μια λίστα με τις ανακοινώσεις του συγκεκριμένου χρήστη
                    //που μας δίνει από το stream, άρα απλά γράφουμε την λίστα στο stream
                } else if (msg.getMessage().equals("EDIT/DELETE")) {

                    ArrayList<Announcement> list_to_send = new ArrayList<>(); // η λίστα που θα στείλουμε
                    //για κάθε ανακοίνωση που κρατάει ο σερβερ (δε χρειάζεται synchronized διοτι διαβάζουμε μόνο)
                    //ελέγχουμε αν το username της κάθε ανακοίνωσης ταιριάζει με το username που έστειλε ο client, και αν ναι προσθήκη στη λίστα που θα στείλει πίσω ο σερβερ
                    //επίσης ελέγχουμε αν ζητάει τη συγκεκριμένη ενέργεια κάποιος admin

                    for (int i = 0; i < announcements.size(); i++) {
                        if (announcements.get(i).getAuthor().equals(msg.getUser().getUsername()) || msg.getUser().getUsername().equals("admin1") || msg.getUser().getUsername().equals("admin2")) {
                            list_to_send.add(announcements.get(i));
                        }
                    }
                    //αν η λίστα με τις ανακοινώσεις του χρήστη είναι άδεια σημαίνει πως δεν έχει βάλει ακόμα κάποια ανακοίνωση, οπότε μήνυμα λάθους
                    //πίσω στον client
                    if (list_to_send.isEmpty()) {
                        oos.writeObject(new Message("EDIT/DELETE FAIL"));
                        oos.flush();
                    } else {
                        oos.writeObject(new Message("EDIT/DELETE OK", list_to_send));
                        oos.flush();
                    }

                    //αν ο client στείλει EDIT σημαίνει πως στέλνει όλη τη λίστα με τις ανακοινώσεις του χρήστη αυτουνου, ο σερβερ θα ψάξει στη δικια του λιστα
                    //για ανακοινώσεις με το username του client και θα τις διαγράψει, στη συνέχεια θα ξαναπροσθέσει όλες τις ανακοινώσεις
                    //προφανώς θα υπάρχει αλλαγή στη σειρά των ανακοινώσεων αλλά δεν μας απασχολεί
                    //Επίσης εδώ δε μπορεί να υπάρξει κάποιο σοβαρό σφάλμα αλλά το ελέγχουμε τυπικά
                } else if (msg.getMessage().equals("EDIT")) {
                    //επειδή έχουμε τροποποίηση της λίστας θα χρειαστεί synchronized
                    try {
                        synchronized (this) {
                            //διαγραφή όλων
                            for (int i = 0; i < announcements.size(); i++) {
                                if (announcements.get(i).getAuthor().equals(msg.getUser().getUsername())) {
                                    announcements.remove(i);
                                }
                            }
                            //προσθήκη
                            for (int i = 0; i < msg.getAnnouncements().size(); i++) {
                                announcements.add(msg.getAnnouncements().get(i));
                            }
                        }
                        oos.writeObject(new Message("EDIT OK"));
                        oos.flush();
                    } catch (Exception e) {
                        oos.writeObject(new Message("EDIT FAIL"));
                        oos.flush();
                    }

                } //για διαγραφή -> ο client στέλνει τη λίστα που έχει όλες τις δικές του ανακοινώσεις για αυτόντ ον χρήστη, η λίστα εκείνη
                //είναι η λίστα που του έδωσε ο σερβερ στο EDIT/DELETE, όταν πατήθηκε το κουμπί διαγραφής στον client, τοπικά στον client
                //η λίστα ενημερώθηκε, διαγράφοντας τις ανακοινώσεις που είχε επιλέξει στο checkbox, οπότε εδώ στον σερβερ διαγράφουμε όλες τις
                //ανακοινώσεις για το username αυτό και μετά εισάγουμε στο αρχείο τη λίστα, και επειδή γράφουμε στη λίστα του σερβερ χρειάζεται synchronized
                else if (msg.getMessage().equals("DELETE")) {
                    //έλεγχος στη λίστα και διαγραφή
                    try {
                        synchronized (this) {
                            for (int i = 0; i < announcements.size(); i++) {
                                if (announcements.get(i).getAuthor().equals(msg.getUser().getUsername())) {
                                    announcements.remove(i);
                                }
                            }
                            //προσθήκη
                            for (int i = 0; i < msg.getAnnouncements().size(); i++) {
                                announcements.add(msg.getAnnouncements().get(i));
                            }
                        }
                        oos.writeObject(new Message("DELETE OK"));
                        oos.flush();
                    } catch (Exception e) {
                        oos.writeObject(new Message("DELETE FAIL"));
                        oos.flush();
                    }
                } //View -> θα ψάξει ο σερβερ όλη τη λίστα με ανακοινώσεις για να βρει αν η ημερομηνία της λίστας έχει τελευταία ημερομηνία
                //τροποποίησης ανάμεσα στις 2 ημερομηνίες που έστειλε ο client, αν ναι προσθέτει στη λίστα την ανακοίνωση και τη στέλνει πίσω
                //όχι synchronized διότι δεν τροποποιείται η λίστα announcements του σερβερ
                else if (msg.getMessage().equals("VIEW")) {
                    ArrayList<Announcement> list_to_send = new ArrayList<>();
                    for (int i = 0; i < announcements.size(); i++) {
                        if ((announcements.get(i).getLastEditDate().after(msg.getFirstDate())) && (announcements.get(i).getLastEditDate().before(msg.getSecondDate()))) {
                            list_to_send.add(announcements.get(i));
                        }
                    }
                    //άδεια=δε βρέθηκε τίποτα, οπότε λάθος
                    if (list_to_send.isEmpty()) {
                        oos.writeObject(new Message("VIEW FAIL"));
                        oos.flush();
                    } else {
                        oos.writeObject(new Message("VIEW OK", list_to_send));
                        oos.flush();
                    }

                } else if (msg.getMessage().equals("END")) {
                    //αν στείλει ο client "END" και κωδικό κατάστασης log in=-1 ότε αποσυνδέσουμε τον χρήστη
                    //χρειάζεται synnchronized αφού πειράζουμε κοινό πόρο
                    if (msg.getCode() == -1) {
                        synchronized (this) {
                            for (int i = 0; i < logged_in.size(); i++) {
                                if ((logged_in.get(i).getUsername().equals(msg.getUser().getUsername())) && (logged_in.get(i).getPassword().equals(msg.getUser().getPassword()))) {
                                    logged_in.remove(i);
                                }
                            }
                        }
                    } //αλλιώς αν στείλει κωδικό=0 τότε δε κάνουμε κάτι

                } //αν στείλει οτιδήποτε άλλο ο client, τότε στέλνουμε αυτό το μήνυμα, λογικά στη συγκεκριμένη εφαρμογή δε θα εκτελεστεί αυτό το κομμάτι
                //κώδικα, διότι οι τιμές που στέλνονται από τον client είναι προκαθορισμένες
                else {
                    oos.writeObject(new Message("BAD FORMAT"));
                    oos.flush();

                    sock.close();
                    oos.close();
                    ois.close();
                }
            }
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(Server.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
