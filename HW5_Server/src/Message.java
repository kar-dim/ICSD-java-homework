/* icsd13072 Karatzas Dimitris
   icsd13096 Lazaros Apostolos*/
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;

//η κλάση για το μήνυμα, αντικείμενα αυτού του τύπου μεταφέρονται μόνο από client σε server και αντίστροφα
public class Message implements Serializable {

    private Announcement announcement;
    private ArrayList<Announcement> list_to_send;
    private User user;
    private final String message;
    private Date d1, d2;
    private int exit = 0;
    //override τους constructors ανάλογα το μήνυμα και από ποιόν προέρχεται

    //απλό μήνυμα (END, START κτλ, που δεν περιέχουν κάποιο αντικείμενο απλώς πληροφορούν για κάποια κατάσταση)
    public Message(String msg) {
        message = msg;
    }
    //μήνυμα+username, χρησιμοποιείται για να δώσει το όνομα του user που είναι Logged in στην εφαρμογή προς τον σερβερ
    public Message(String msg, String usern){
        message=msg;
        user = new User(usern, null, null, null); //μας νοιάζει μόνο το username για έλεγχο
    }
    //μήνυμα+ register (νέος χρήστης) Client->Server
    public Message(String msg, User usr) {
        message = msg;
        user = new User(usr.getUsername(), usr.getPassword(), usr.getName(), usr.getLname());
    }
//μήνυμα+ user+ ειδική τιμή που πρέπει να είναι -1 για έξοδο με logout(έλεγχος στον σερβερ)

    public Message(String msg, User usr, int val) {
        message = msg;
        user = new User(usr.getUsername(), usr.getPassword(), usr.getName(), usr.getLname());
        exit = val;
    }
    //μήνυμα+ ειδική τιμή που πρέπει να είναι 0 για έξοδο (χωρίς logout)

    public Message(String msg, int logged) {
        message = msg;
        exit = logged;
    }

    //μήνυμα+λίστα μόνο (View)
    public Message(String msg, ArrayList<Announcement> list) {
        message = msg;
        list_to_send = new ArrayList<>(list);
    }

    //μήνυμα και ανακοίνωση μόνο
    public Message(String msg, Announcement announce) {
        message = msg;
        announcement = new Announcement(announce.getAnnouncement(), announce.getAuthor(), announce.getLastEditDate());
    }

    //το αντικειμενο χρηστη ειναι απραιτητο ωστε ο σερβερ να ψαξει στο αρχειο του και να διαγραψει μονο αυτουνου του χρηστη τις ανακοινωσεις που
    //θελει ο χρηστης να διαγραψει (τον constructor αυτόν τον χρησιμοποιεί ο Client)
    public Message(String msg, ArrayList<Announcement> list, User usr) {
        message = msg;
        list_to_send = new ArrayList<>(list);
        user = new User(usr);
    }

    //εδω ο client στελνει τις ημερομηνιες που θελει να ψαξει ανακοινωσεις
    public Message(String msg, Date d1, Date d2) {
        message = msg;
        this.d1 = d1;
        this.d2 = d2;
    }

    //ανακοίνωση για δημιουργία (χρειάζεταιαντικείμενο χρήστη προφανώς αφού δε μπορεί ο καθένας να φτιάχνει ανακοινώσεις αλλά οι logged in users)
    public Message(String msg, User usr, Announcement announce) {
        announcement = announce;
        message = msg;
        user = new User(usr);
    }

    //setters/getters
    public String getMessage() {
        return message;
    }

    public User getUser() {
        return user;
    }

    public Announcement getAnnouncement() {
        return announcement;
    }

    public void setAnnouncement(Announcement announce) {
        announcement = new Announcement(announce);
    }

    public ArrayList<Announcement> getAnnouncements() {
        return list_to_send;
    }

    public int getCode() {
        return exit;
    }

    public Date getFirstDate() {
        return d1;
    }

    public Date getSecondDate() {
        return d2;
    }
}
