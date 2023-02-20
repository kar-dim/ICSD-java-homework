/* icsd13072 Karatzas Dimitris
   icsd13096 Lazaros Apostolos*/
//απλή κλάση η οποία περιέχει τη main μέθοδο του project και δημιουργεί το frame στο οποίο θα μπει το GUI της κλάσης MainMenu

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;

public class Client {

    public static void main(String args[]) {
        //δημιουργία του frame
        JFrame frame = new JFrame("Reservations");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
        //βάζουμε στο frame το JTabbedPane
        MainMenu menu = new MainMenu();
        frame.add(menu, BorderLayout.CENTER);
        frame.pack(); //να πιάνει όσο χώρο χρειάζεται
        /*frame.setResizable(false); */
        //όταν κλείσει το παράθυρο βάζουμε listener για να σταλεί στον server το μήνυμα END καθώς και ο Logged in χρήστης
        //ώστε ο σερβερ να τον κάνει Log out
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {

                try {
                    //παίρνουμε το socket και streams του MainMenu 
                    //και κανονικά στέλνουμε μήνυμα START και αναμένουμε STARTED και τέλος στέλνουμε END
                    MainMenu.sock = new Socket("localhost", 5555);
                    //System.out.print(MainMenu.sock.getInetAddress());
                    MainMenu.oos = new ObjectOutputStream(MainMenu.sock.getOutputStream());
                    MainMenu.ois = new ObjectInputStream(MainMenu.sock.getInputStream());
                    MainMenu.oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                    MainMenu.oos.flush();
                    //διαβασμα ("consume") του STARTED μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                    MainMenu.ois.readObject();

                    //έλεγχος αν έχει γίνει Log in, αλλιώς δε χρειάζεται να κάνουμε Log out
                    //-1 βάζουμε ώστε να δείξουμε στον σερβερ ότι ο χρήστης αυτόςθέλει να κάνει Log out και όχι register
                    //0 βάζουμε για να δείξουμε ότι δε χρειάζεται log out
                    if (MainMenu.logged_in != null) {
                        MainMenu.oos.writeObject(new Message("END", MainMenu.logged_in, -1));
                        MainMenu.oos.flush();
                    } else {
                        MainMenu.oos.writeObject(new Message("END", 0));
                        MainMenu.oos.flush();
                    }
                    System.exit(0);
                } catch (Exception ex) {
                    //βέβαια μπορεί να μην έχει κάνει καν Login οπότε θα υπάρχει exception, απλά κλείνουμε την εφαρμογή
                    Logger.getLogger(Client.class.getName()).log(Level.SEVERE, null, ex);
                    System.exit(0);
                }

            }
        });
    }
}
