/* icsd13072 Karatzas Dimitris
   icsd13096 Lazaros Apostolos*/
//Η κλάση για το γραφικό περιβάλλον
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

public class MainMenu extends JPanel {

    private final JTabbedPane jtp;
    private JTextArea text;
    private JScrollPane scroll;
    private JCheckBox[] check; //checkboxes για επιλογή αν θα διαγραφτεί η ανακοίνωση   
    private JPanel del_ins_panel;
    private JPanel jPanel1, jPanel2, jPanel3, jPanel4, jPanel5;
    private JTable table;
    private JTextField username_tf, username_tf_l, lname_tf, name_tf, date_1_tf, date_2_tf;
    private JPasswordField password_pf, password_pf_l;
    private JButton register_b, login_b, view_b, create_b, delete_b, update_b;
    private JLabel username_lb, password_lb, password_lb_l, username_lb_l, date_1_lb, date_2_lb, lname_lb, name_lb;
    private ArrayList<Announcement> list;
    /* αυτή η λίστα είναι η λίστα  που  έχει τις ανακοινώσεις του logged in user */
    private SimpleDateFormat ft;
    //για λόγους απλότητας βάλαμε τα streams και το socket ώς public για να μπορεί η  κλάση Client να τα δεί, κανονικά έπρεπε να κάνουμε static import αλλά
    //η java δεν επιτρέπει static import από το default package οπότε πρέπει να φτιάξουμε το δικό μας package αλλά δεν υπάρχει διαφορά στη λειτουργία
    //(ίσως στην ασφάλεια οπότε κανονικά δε θα το κάναμε έτσι)
    public static Socket sock; //static ώστε να χρησιμοποηθούν από την Client κλάση για αποστολή END μηνύματος
    public static ObjectInputStream ois;
    public static ObjectOutputStream oos;
    public static User logged_in;

    //Στον constructor πέρα από τη δημιουργία του JTabbedPane βάζουμε και τον Listener για τα κουμπιά των tabs, όλα γίνονται
    //στον constructor στην ουσία
    public MainMenu() {
        super(new GridLayout(1, 1));
        del_ins_panel = new JPanel();
        //JTabbedPane, 5 Tabs: Register, Login, ανάγνωση, εισαγωγή, διαγραφή/τροποποίηση ανακοινώσεων
        jtp = new JTabbedPane(JTabbedPane.TOP);
        jtp.addTab("Register", createRegisterPanel());
        jtp.addTab("Login", createLoginPanel());
        jtp.addTab("View Announcements", createViewPanel());
        jtp.addTab("Insert announcement", createInsertPanel());
        //σχετικά με τη προβολή/διαγραφή, δε ξέρουμε εξ αρχής πόσα στοιχεία θα βάλουμε, οπότε θα δείξουμε ποιο panel
        //να χρησιμοποιεί το tab αυτό, και μόλις ο χρήστης κάνει κλικ στο tab τότε θα φέρουμε τα στοιχεία των ανακοινώσεων
        jtp.addTab("Edit/Delete Your Announcements", createEditDeletePanel());
        //δεν επιτρέπουμε δημιουργία, διαγραφή και τροποποίηση ανακοινώσεων, παρα μόνο ανάγνωση, οπότε πρέπει να
        //απενεργοποιήσουμε τα αντίστοιχα panels (θα τα ενεργοποιήσουμε πάλι αν επιτύχει το login/register)
        //η αρίθμιση ξεκινάει από το 0, οπότε απενεργοποιούμε τα 3 και 4 panels (εισαγωγή και τροποποίηση/διαγραφή)
        jtp.setEnabledAt(3, false);
        jtp.setEnabledAt(4, false);
        //βάζουμε το JTabbedPane στο Panel
        add(jtp);
        //σε αυτή τη μέθοδο θα φτιαχτούν οι listeners για τα κουμπιά (μέσω anonymous inner classes) και του tab edit/delete
        addActionListeners();

    }

    //μέθοδος ώπου δημιουργούμε το Insert Tab
    //υποθέτουμε πως στην εφαρμογή ένας χρήστης αναπαριστάνεται μόνο από το username,τον κωδικό του και ονοματεπώνυμο, θα μπορούσε να έχει και άλλα
    //δεν θα άλλαζει κάτι το ιδιαίτερο στον κώδικα
    private JPanel createRegisterPanel() {
        //για κάθε J-στοιχείο που θέλουμε το δημιουργούμε και το βάζουμε στο panel

        jPanel1 = new JPanel();
        jPanel1.setLayout(new GridLayout(5, 2));

        //Label για username και textbox
        username_lb = new JLabel("Username:");
        jPanel1.add(username_lb);
        username_tf = new JTextField(20);
        jPanel1.add(username_tf);

        //Label για κωδικό και textbox (password mode)
        password_lb = new JLabel("Password:");
        jPanel1.add(password_lb);
        password_pf = new JPasswordField(20);
        jPanel1.add(password_pf);

        //Labels για ονομα, επωνυμο και textboxes
        name_lb = new JLabel("Name:");
        jPanel1.add(name_lb);
        name_tf = new JTextField(20);
        jPanel1.add(name_tf);

        lname_lb = new JLabel("Last Name:");
        jPanel1.add(lname_lb);
        lname_tf = new JTextField(20);
        jPanel1.add(lname_tf);

        //τέλος θα βάλουμε το κουμπί
        register_b = new JButton("Register");
        jPanel1.add(register_b);
        return jPanel1;
    }

    //μέθοδος για δημιουργία του Login tab, ίδιο ακριβώς με το register
    private JPanel createLoginPanel() {
        //για κάθε J-στοιχείο που θέλουμε το δημιουργούμε και το βάζουμε στο panel

        jPanel2 = new JPanel();
        jPanel2.setLayout(new GridLayout(3, 2));

        //Label για username και textbox
        username_lb_l = new JLabel("Username:");
        jPanel2.add(username_lb_l);
        username_tf_l = new JTextField(20);
        jPanel2.add(username_tf_l);

        //Label για κωδικό και textbox (password mode)
        password_lb_l = new JLabel("Password:");
        jPanel2.add(password_lb_l);
        password_pf_l = new JPasswordField(20);
        jPanel2.add(password_pf_l);

        //τέλος θα βάλουμε το κουμπί
        login_b = new JButton("Login");
        jPanel2.add(login_b);
        return jPanel2;
    }

    //tab για ψάξιμο αναζητήσεων από κάποια ημερομηνία μέχρι κάποια άλλη
    private JPanel createViewPanel() {
        //προσθήκη labels και textfields
        jPanel3 = new JPanel();
        jPanel3.setLayout(new GridLayout(3, 2));

        date_1_lb = new JLabel("Search Dates from (dd-MM-yyyy only):");
        jPanel3.add(date_1_lb);
        date_1_tf = new JTextField(20);
        jPanel3.add(date_1_tf);

        date_2_lb = new JLabel("Search Dates to (dd-MM-yyy only):");
        jPanel3.add(date_2_lb);
        date_2_tf = new JTextField(20);
        jPanel3.add(date_2_tf);

        //προσθήκη του κουμπιού
        view_b = new JButton("Search");
        jPanel3.add(view_b);
        return jPanel3;
    }

    //tab δημιουργίας ανακοίνωσης, απλώς υπάρχει ένα JTextArea και επίσης το κουμπί για τη δημιουργία
    private JPanel createInsertPanel() {
        jPanel4 = new JPanel();
        jPanel4.setLayout(new GridLayout(2, 1));

        //Στο πεδίο αυτό θα γραφτεί η ανακοίνωση
        text = new JTextArea(7, 57);
        scroll = new JScrollPane(text);
        jPanel4.add(scroll, BorderLayout.CENTER);

        //τέλος θα βάλουμε το κουμπί
        create_b = new JButton("Create");
        //panel για το κουμπί ώστε να μη πιάνει τη μισή οθόνη
        JPanel button_panel = new JPanel();
        button_panel.setLayout(new BorderLayout());
        button_panel.add(create_b, BorderLayout.SOUTH);

        jPanel4.add(button_panel);

        return jPanel4;
    }

    //το layout Θα το φτιάξουμε μόλις πατηθεί το tab
    private JPanel createEditDeletePanel() {
        del_ins_panel = new JPanel();
        delete_b = new JButton("Delete");
        update_b = new JButton("Update");
        return del_ins_panel;
    }

    //η μέθοδος που βάζει τα listeners για τα κουμπια, σε καθε κουμπι θα δημιουργειται socket και streams
    private void addActionListeners() {
        //listener για tab τροποποίησης ή διαγραφής ανακοίνωσης, θα πάρουμε τις ανακοινώσεις που έχει ο συγκεκριμένος χρήστης και θα 
        //τις βάλουμε στο table, στη συνέχεια θα βάλουμε ένα scrollpane στο οποίο θα μπούν οι ανακοινώσεις σε μορφή πίνακα (JTable)
        jtp.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                if (jtp.getSelectedIndex() == 4) {
                    //αν επιλεχθεί το tab αυτό, ξεκινάμε κανονικά όπως με τα κουμπιά, αρχικά sockets/streams κτλ 

                    //λίστα που έχει μέσα ποια indexes των ανακοινώσεων θα διαγραφούν
                    try {
                        sock = new Socket("localhost", 5555);
                        //System.out.print(sock.getInetAddress());
                        oos = new ObjectOutputStream(sock.getOutputStream());
                        ois = new ObjectInputStream(sock.getInputStream());
                        oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                        oos.flush();
                        //διαβασμα ("consume") του STARTED μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                        ois.readObject();

                        //νέο μήνυμα με βάση τον χρήστη που είναι logged in
                        //πρωτα στελνουμε μηνυμα EDIT/DELETE για να παρουμε τις ανακοινωσεις του χρηστη, και μετα
                        //στελνουμε ειτε DELETE ειτε EDIT ξεχωριστα για να δηλωσουμε ξεχωριστα τι θελουμε αλλα πρωτα
                        //χρειαζεται να παρουμε τα δεδομενα και να τα δειξουμε στο GUI του client
                        oos.writeObject(new Message("EDIT/DELETE", logged_in.getUsername()));
                        oos.flush();
                        Message msg = (Message) ois.readObject(); //διάβασμα της απάντησης
                        if (msg.getMessage().equals("EDIT/DELETE FAIL")) {
                            JOptionPane.showMessageDialog(jtp, "Error trying to access data from server, or you don't have any announcements", "Error", JOptionPane.ERROR_MESSAGE);
                        } else {
                            //πήραμε τη λίστα με τις ανακοινώσεις και γίνεται δέσμευση μνήμης στα στοιχεία ανάλογα το μέγεθος
                            list = new ArrayList<>(msg.getAnnouncements());
                            int size = list.size();
                            System.out.print(size);
                            check = new JCheckBox[size + 1]; //αν επιλεχθει μια ανακοινωση σημαινει πως ο χρηστης θελει να διαγραφει (size+1 αφού πίνακες ξεκινάνε με 0 )
                            //χρειαζόμαστε το table model για να γράψουμε στο table τις γραμμές
                            TableModel tablemodel = new TableModel(size, 3);
                            table = new JTable();
                            
                            //θέτουμε false στο να ειναι τροποποιήσιμα τα πεδία
                            //για κάθε γραμμή βάζουμε την ανακοίνωση και την ημερομηνία τελευταίας τροποποίησης
                            Object[][] row_data = new Object[size][3];
                            Object[] column_names = {"Check to delete", "Announcement", "Last Edit Date"};
                            for (int i = 0; i < size; i++) {
                                check[i] = new JCheckBox();
                                row_data[i][0] = false;
                                row_data[i][1] = list.get(i).getAnnouncement();
                                row_data[i][2] = list.get(i).getLastEditDate();
                                tablemodel.setValueAt(row_data[i][0], i, 0);
                                tablemodel.setValueAt(row_data[i][1], i, 1);
                                tablemodel.setValueAt(row_data[i][2], i, 2);
                                tablemodel.fireTableDataChanged();   
                            }
                            
                            table.setModel(tablemodel);
                            //αφού τελειώσουμε με τον κώδικα για τη μεταφορά δεδομένων και τους ελέγχους, πρέπει να φτιάξουμκε και το layout
                            //του del_ins_panel
                            del_ins_panel.removeAll();
                            del_ins_panel.setLayout(new GridLayout(2, 1));
                            JScrollPane jsp = new JScrollPane(table);

                            del_ins_panel.add(jsp);

                            JPanel buttons = new JPanel();
                            buttons.setLayout(new FlowLayout());
                            buttons.add(delete_b);
                            buttons.add(update_b);

                            del_ins_panel.add(buttons);

                            jtp.revalidate();
                            jtp.repaint();

                        }

                    } catch (IOException | ClassNotFoundException ex) {
                        Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            }
        });

        //αν πατηθεί το κουμπί για διαγραφή ελέγχουμε κάθε checkbox αν είναι selected που σημαίνει πως ο client θέλει να διαγραφούν
        delete_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    sock = new Socket("localhost", 5555);
                    //System.out.print(sock.getInetAddress());
                    oos = new ObjectOutputStream(sock.getOutputStream());
                    ois = new ObjectInputStream(sock.getInputStream());
                    oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                    oos.flush();
                    //διαβασμα ("consume") του STARTED μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                    ois.readObject();

                    //ενημερώνουμε την λίστα και έπειτα θα τη γράψουμε στο socket ώστε να ενημερωθεί στον server
                    for (int i = 0; i < check.length; i++) {
                        if (check[i].isSelected()) {
                            list.remove(i);
                        }
                    }
                    //γράψιμο της λίστας
                    oos.writeObject(new Message("DELETE", list, new User(username_tf_l.getText(), new String(password_pf_l.getPassword()))));
                    oos.flush();
                    //διάβασμα αν γράφτηκε σωστά
                    Message msg = (Message) ois.readObject();
                    //έλεγχος
                    if (msg.getMessage().equals("DELETE FAIL")) {
                        JOptionPane.showMessageDialog(jtp, "Failed to delete your announcements", "Error", JOptionPane.ERROR_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(jtp, "Successfully deleted your announcements", "Success", JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (IOException | ClassNotFoundException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        //αν πατηθεί το κουμπί για τροποποίηση ανακοινώσεων
        //απλά ξαναγράφει στο socket όλες τις ανακοινώσεις.
        //εδώ ίσως να μην είναι καλή υλοποίηση, διότι γράφει στο socket όλες τις ανακοινώσεις άσχετα αν τις τροποποίησε ή όχι
        update_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    sock = new Socket("localhost", 5555);
                    //System.out.print(sock.getInetAddress());
                    oos = new ObjectOutputStream(sock.getOutputStream());
                    ois = new ObjectInputStream(sock.getInputStream());
                    oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                    oos.flush();
                    //διαβασμα ("consume") του STARTED μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                    ois.readObject();

                    //update όλη τη λίστα και γράψιμο στο stream
                    for (int i = 0; i < list.size(); i++) {
                        list.get(i).setLastEditDate(new Date());
                    }
                    oos.writeObject(new Message("EDIT", list, new User(username_tf_l.getText(), new String(password_pf_l.getPassword()))));
                    oos.flush();

                    //διάβασμα αν γράφτηκε σωστά
                    Message msg = (Message) ois.readObject();
                    //έλεγχος
                    if (msg.getMessage().equals("EDIT FAIL")) {
                        JOptionPane.showMessageDialog(jtp, "Failed to update your announcements", "Error", JOptionPane.ERROR_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(jtp, "Successfully updated your announcements", "Success", JOptionPane.INFORMATION_MESSAGE);
                    }
                } catch (IOException | ClassNotFoundException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        //αν πατηθεί το κουμπί για register
        register_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e
            ) {
                try {
                    sock = new Socket("localhost", 5555);
                    //System.out.print(sock.getInetAddress());
                    oos = new ObjectOutputStream(sock.getOutputStream());
                    ois = new ObjectInputStream(sock.getInputStream());
                    oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                    oos.flush();
                    //διαβασμα ("consume") του STARTED μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                    ois.readObject();

                    //έλεγχος αν υπάρχει έστω και μια κενή τιμή , αν υπάρχει τότε nullpointer exception και μήνυμα λάθους
                    //επίσης ελέγχουμε και αν το μήκος του κωδικού είναι τουλάχιστον 6
                    if (username_tf.getText().isEmpty() || name_tf.getText().isEmpty() || lname_tf.getText().isEmpty() || username_tf.getText().isEmpty() || password_pf.getPassword().length < 6 || password_pf.getPassword() == null) {
                        throw new NullPointerException();
                    }
                    //αν όλα πάνε καλά μέχρι στιγμής τότε στέλνουμε τον νέο χρήστη στον server καλώντας τον κατάλληλο constructor του Message
                    oos.writeObject(new Message("REGISTER", new User(username_tf.getText(), new String(password_pf.getPassword()), name_tf.getText(), lname_tf.getText())));
                    oos.flush();
                    //διάβασμα της απάντησης του server
                    Message msg = (Message) ois.readObject();
                    if (msg.getMessage().equals("REGISTER OK")) {
                        //αν επιτύχει το register τότε απλά εμφανίζουμε ένα μήνυμα που δείχνει ότι έγινε επιτυχημένα το register
                        JOptionPane.showMessageDialog(jtp, "Successfully registered! Please select the Login tab to login", "Success", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        //εφόσον τα πεδία δεν είναι κενά (και εφόσον σταλούν επιτυχημένα στο stream, δηλαδή δεν έχουμε IOException, αλλά ο server στείλει REGISTER FAIL τότε
                        //σημαίνει πως υπάρχει ήδη λογαριασμός με αυτό το username
                        JOptionPane.showMessageDialog(jtp, "Could not make your account, maybe there is already a user with this username", "Error registering", JOptionPane.ERROR_MESSAGE);
                    }

                } catch (IOException | ClassNotFoundException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NullPointerException npe) {
                    JOptionPane.showMessageDialog(jtp, "Could not make your account, please check your input data, password must be greater than 6 characters long", "Error registering", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
        );

        //όταν πατηθεί το κουμπί του login
        login_b.addActionListener(
                new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    sock = new Socket("localhost", 5555);
                    //System.out.print(sock.getInetAddress());
                    oos = new ObjectOutputStream(sock.getOutputStream());
                    ois = new ObjectInputStream(sock.getInputStream());
                    oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                    oos.flush();
                    //διαβασμα ("consume") του STARTED μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                    ois.readObject();

                    //έλεγχος κενών τιμών
                    if (username_tf_l.getText().isEmpty() || password_pf_l.getPassword().length < 6 || password_pf_l.getPassword() == null) {
                        throw new NullPointerException();
                    }
                    //γράψιμο στο stream
                    oos.writeObject(new Message("LOGIN", new User(username_tf_l.getText(), new String(password_pf_l.getPassword()))));
                    oos.flush();

                    //έλεγχος μηνύματος
                    Message msg = (Message) ois.readObject();
                    if (msg.getMessage().equals("LOGIN OK")) {
                        //αν το login επιτύχει τότε ενεργοποίηση των tabs τροποποίησης/διαγραφής και εισαγωγής
                        jtp.setEnabledAt(3, true);
                        jtp.setEnabledAt(4, true);
                        JOptionPane.showMessageDialog(jtp, "Welcome back", "Success", JOptionPane.INFORMATION_MESSAGE);
                        //κρατάμε τον logged_in user αν επιτύχει το login
                        logged_in = new User(username_tf_l.getText(), new String(password_pf_l.getPassword()));
                    } else {
                        //εφόσον τα πεδία δεν είναι κενά (και εφόσον σταλούν επιτυχημένα στο stream, δηλαδή δεν έχουμε IOException, αλλά ο server στείλει LOGIN FAIL τότε
                        //σημαίνει πως υπάρχει ήδη λογαριασμός με αυτό το username
                        JOptionPane.showMessageDialog(jtp, "Could not login, maybe there is already a user with this username or your password is incorrect", "Error in login", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (IOException | ClassNotFoundException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NullPointerException npe) {
                    JOptionPane.showMessageDialog(jtp, "Cannot Login, please check your data", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        //listener για το κουμπί της ανάγνωσης
        view_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    sock = new Socket("localhost", 5555);
                    //System.out.print(sock.getInetAddress());
                    oos = new ObjectOutputStream(sock.getOutputStream());
                    ois = new ObjectInputStream(sock.getInputStream());
                    oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                    oos.flush();
                    //διαβασμα ("consume") του STARTED μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                    ois.readObject();

                    //παίρνουμε τα Dates από τον client
                    ft = new SimpleDateFormat("dd-MM-yyyy");
                    Date d1 = ft.parse(date_1_tf.getText());
                    Date d2 = ft.parse(date_2_tf.getText());

                    //custom exception για το αν η 1η ημερομηνία είναι μεγαλύτερη από τη 2η
                    if (d1.after(d2)) {
                        throw new DatesCompException();
                    }
                    //γράφουμε στο socket τις ημερομηνίες και το μήνυμα (δε χρειάζεται να στείλουμε τον χρήστη αφού ο καθένας μπορεί να κάνει view)
                    oos.writeObject(new Message("VIEW", d1, d2));
                    oos.flush();
                    //έλεγχος μηνύματος
                    Message msg = (Message) ois.readObject();
                    if (msg.getMessage().equals("VIEW OK")) {

                        //αρχικοποίηση της λίστας με βάση τη λίστα που έστειλε ο σερβερ
                        ArrayList<Announcement> list = new ArrayList<>(msg.getAnnouncements());

                        JFrame jf = new JFrame("Search results");
                        jf.setVisible(true);

                        JPanel panel = new JPanel();
                        JTextArea jta = new JTextArea(20, 40);
                        jta.setEditable(false); //εφόσον αρχικοποιηθεί, δεν επιτρέπουμε την αλλαγή του αφού είναι read only
                        JScrollPane jsp = new JScrollPane(jta);

                        //προσθήκη των ανακοινώσεων στο textarea
                        for (int i = 0; i < list.size(); i++) {
                            jta.append(list.get(i).toString());
                        }
                        panel.add(jsp);
                        //προσθήκη όλου του πανελ στο frame
                        jf.add(panel);
                        jf.pack();
                    } else {
                        //εφόσον τα πεδία δεν είναι κενά (και εφόσον σταλούν επιτυχημένα στο stream, δηλαδή δεν έχουμε IOException, αλλά ο server στείλει VIEW FAIL
                        //σημαίνει πως δε βρέθηκε κάποια ανακοίνωση σε αυτό το εύρος ημερομηνιών
                        JOptionPane.showMessageDialog(jtp, "Could not find any announcements", "Nothing found", JOptionPane.ERROR_MESSAGE);
                    }
                } catch (NullPointerException npe) {
                    JOptionPane.showMessageDialog(jtp, "Could not search for announcements, please check your input data", "Error searching for announcements", JOptionPane.ERROR_MESSAGE);
                } catch (FileNotFoundException ex) {
                    JOptionPane.showMessageDialog(jtp, "Could not search announcements, server error", "Error searching data", JOptionPane.ERROR_MESSAGE);
                    //Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    //Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(jtp, "Could not search announcements", "Error searching data", JOptionPane.ERROR_MESSAGE);
                } catch (ParseException ex) {
                    JOptionPane.showMessageDialog(jtp, "Could not search announcements, make sure your dates are in format dd-MM-yyyy", "Error searching data", JOptionPane.ERROR_MESSAGE);
                } catch (DatesCompException ex) {
                    JOptionPane.showMessageDialog(jtp, "Could not search announcements, maybe the first date is after the second?", "Error searching data", JOptionPane.ERROR_MESSAGE);
                }
                /*finally {
                    try {
                        //κλείσιμο socket/streams
                        ois.close();
                        oos.close();
                        sock.close();
                    } catch (IOException ex) {
                        Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                    }
                } */
            }
        });
        //αν πατηθεί το κουμπί για δημιουργία ανακοίνωσης
        create_b.addActionListener(
                new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e
            ) {
                int cost;
                Long id;
                try {
                    sock = new Socket("localhost", 5555);
                    oos = new ObjectOutputStream(sock.getOutputStream());
                    ois = new ObjectInputStream(sock.getInputStream());
                    oos.writeObject(new Message("START")); //εκκίνηση της χειραψίας
                    oos.flush();
                    //διαβασμα ("consume") του waiting μηνυματος, δε χρειάζεται να εκτυπωθεί στον χρήστη του GUI
                    ois.readObject();

                    //έλεγχος αν η τιμή είναι κενή
                    if (text.getText().isEmpty()) {
                        throw new NullPointerException(); //θα γίνει catch από κάτω
                    }
                    //στέλνουμε μήνυμα στο stream για εισαγωγή
                    oos.writeObject(new Message("CREATE", new Announcement(text.getText(), username_tf_l.getText(), new Date())));
                    oos.flush();
                    //έλεγχος
                    Message msg = (Message) ois.readObject();
                    if (msg.getMessage().equals("CREATE OK")) {
                        JOptionPane.showMessageDialog(jtp, "Successfully added your announcement", "Success", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(jtp, "Could not create your announcement", "Error", JOptionPane.ERROR_MESSAGE);
                    }

                } catch (NullPointerException | ClassNotFoundException npe) {
                    JOptionPane.showMessageDialog(jtp, "Could not create your announcement, please check your details", "Error inserting data", JOptionPane.ERROR_MESSAGE);
                } catch (FileNotFoundException ex) {
                    //είναι δικό μας το λάθος και όχι του χρήστη αν έχουμε FileNotFoundException και IOException, οπότε και αντίστοιχο μήνυμα
                    JOptionPane.showMessageDialog(jtp, "Could not create announcement, server error", "Error inserting data", JOptionPane.ERROR_MESSAGE);
                } catch (IOException exc) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, exc);
                    JOptionPane.showMessageDialog(jtp, "Could not create announcement, server error", "Error inserting data", JOptionPane.ERROR_MESSAGE);
                }
                /*finally {
                    try {
                        //κλείσιμο socket/streams
                        ois.close();
                        oos.close();
                        sock.close();
                    } catch (IOException ex) {
                        Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                    }
                } */
            }
        });
    }
}
