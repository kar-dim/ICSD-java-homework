/* Dimitris Karatzas icsd13072
   Apostolos Lazaros icsd13096
 */
//η βασική κλάση η οποία υλοποιεί το GUI και κάνει όλες τις ενέργειες από τη μεριά του Client
import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
//η μορφή που θα έχει το GUI είναι ένα JTabbedPane με 3 tabs: εισαγωγή, έλεγχος και εμφάνιση στοιχείων

public class MainMenu extends JPanel {

    private JTabbedPane jtp;
    private JPanel j1, j2, j3;
    private JLabel check_l_dep, check_l_dest, check_l_date, display_l_name, display_l_id, display_l_lname, reserve_l_id;
    private JTextField check_tf_dep, check_tf_dest, check_tf_date, display_tf_name, display_tf_id, display_tf_lname, reserve_tf_id;
    private JButton check_b, create_b, create2_b, display_b, clear_check, clear_display, clear_reserve;

    public MainMenu() {
        super(new GridLayout(1, 1));
        initializePanels(); //μέθοδος που φτιάχνει όλο το GUI
    }

    private void initializePanels() {
        //δημιουργία GUI
        jtp = new JTabbedPane(JTabbedPane.TOP);
        //προσθήκη tabs
        jtp.addTab("Check availability", createAvailabilityPanel());
        jtp.addTab("Reserve ticket", createReservePanel());
        jtp.addTab("Display reservation", createDisplayPanel());
        //προσθήκη listeners 
        addActionListeners();
        add(jtp);
    }
    //οι παρακάτω 3 μέθοδοι απλώς δημιουργούν τα γραφικά στοιχεία της εφαρμογής, για κάθε ενέργεια έχουμε ένα αντίστοιχο πανελ
    //με αντίστοιχά textfields, labels και κουμπιά
    private JPanel createAvailabilityPanel() {
        j1 = new JPanel();
        j1.setLayout(new GridLayout(4, 2));

        check_l_dep = new JLabel("Type Departure City:");
        j1.add(check_l_dep);
        check_tf_dep = new JTextField(25);
        j1.add(check_tf_dep);

        check_l_dest = new JLabel("Type Destination City:");
        j1.add(check_l_dest);
        check_tf_dest = new JTextField(25);
        j1.add(check_tf_dest);

        check_l_date = new JLabel("Date (dd-MM-yyyy):");
        j1.add(check_l_date);
        check_tf_date = new JTextField(25);
        j1.add(check_tf_date);

        check_b = new JButton("Check");
        j1.add(check_b);
        clear_check = new JButton("Clear data");
        j1.add(clear_check);

        return j1;
    }

    private JPanel createReservePanel() {
        j2 = new JPanel();
        j2.setLayout(new GridLayout(2, 2));

        reserve_l_id = new JLabel("Enter Flight ID:");
        j2.add(reserve_l_id);
        reserve_tf_id = new JTextField(3);
        j2.add(reserve_tf_id);

        create_b = new JButton("Reserve");
        j2.add(create_b);
        clear_reserve = new JButton("Clear");
        j2.add(clear_reserve);
        return j2;
    }

    private JPanel createDisplayPanel() {
        j3 = new JPanel();
        j3.setLayout(new GridLayout(4, 2));
        display_l_name = new JLabel("Your Name:");
        j3.add(display_l_name);
        display_tf_name = new JTextField(25);
        j3.add(display_tf_name);

        display_l_lname = new JLabel("Your Last Name:");
        j3.add(display_l_lname);
        display_tf_lname = new JTextField(25);
        j3.add(display_tf_lname);

        display_l_id = new JLabel("Flight ID:");
        j3.add(display_l_id);
        display_tf_id = new JTextField(3);
        j3.add(display_tf_id);

        display_b = new JButton("Display");
        j3.add(display_b);
        clear_display = new JButton("Clear");
        j3.add(clear_display);
        return j3;
    }

    //μέθοδος που βάζει listeners για τα κουμπιά
    private void addActionListeners() {
        //όταν πατηθεί το κουμπί για έλεγχο
        check_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    LocateRegistry.getRegistry("ReservationService");
                    //η διεύθυνση 192.168.1.67 είναι η διεύθυνση του σερβερ (εδώ βέβαια είναι η τοπική του υπολογιστή στο τοπικό lab, η οποία αλλάζει οπότε κάθε φορά
                    //πρέπει να βάζουμε τη σωστή διεύθυνση, σε έναν σερβερ με στατική διεύθυνση όμως δε θα είχαμε θέμα, επίσης δε δουλεύει με localhost)
                    AirReservation air = (AirReservation) LocateRegistry.getRegistry("192.168.1.67").lookup("ReservationService");
                    SimpleDateFormat ft = new SimpleDateFormat("dd-MM-yyyy");
                    Date date = ft.parse(check_tf_date.getText());

                    //θα καλέσουμε τη μέθοδο για να εμφανίσει τα αποτελέσματα σε ένα νέο παράθυρο
                    JFrame jf = new JFrame("Search results");
                    jf.setVisible(true);

                    JPanel panel = new JPanel();
                    JTextArea jta = new JTextArea(20, 40);
                    jta.setEditable(false); //εφόσον αρχικοποιηθεί, δεν επιτρέπουμε την αλλαγή του αφού είναι read only
                    JScrollPane jsp = new JScrollPane(jta);
                    jta.append(air.checkAvailability(check_tf_dep.getText(), check_tf_dest.getText(), date));

                    panel.add(jsp);
                    //προσθήκη όλου του πανελ στο frame
                    jf.add(panel);
                    jf.pack();

                } catch (NotBoundException | RemoteException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ParseException ex) {
                    JOptionPane.showMessageDialog(jtp, "Date must be in format: dd-MM-yyyy", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        //όταν πατηθει το κουμπί για δημιουργία κράτησης θα γίνουν τα εξής γεγονότα:
        //ο server θα επιστρέψει μια λίστα με διαθέσιμες θέσεις, στη συνέχεια ο client θα επιλέξει κάποιες τιμές
        //μετά δίνεται όριο 2 λεπτών για να ολοκληρωθεί η κράτηση, συγκεκριμένα ο χρήστης γράφει το όνομα και το επώνυμο του
        //αν δεν περάσουν τα 2 λεπτά και ο client πατήσει το κουμπί "ΟΚ" τότε θα δημιουργηθεί η κράτηση
        //αλλιώς (περάσουν 2 λεπτά ή ο client κλείσει το παράθυρο) δεν αλλάζει κάτι, ακυρώνεται η προς-δημιουργία κράτηση
        create_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    LocateRegistry.getRegistry("ReservationService");
                    AirReservation air = (AirReservation) LocateRegistry.getRegistry("192.168.1.67").lookup("ReservationService");
                    int id = Integer.parseInt(reserve_tf_id.getText()); //μπορεί να είναι οτιδήποτε (ακόμα και string, οπότε έλεγχος για το NumberFormatException (λάθος μετατροπή)
                    int[] nreserved_seats = air.reserve(id, 0, null, null);
                    //η JList που θα εμφανίσει τις διαθέσιμες θέσεις, δέχεται Object[] οπότε μετατρέπουμε το int[] σε Object[]
                    Object[] nreserved_seatz = new Object[nreserved_seats.length];
                    for (int i=0; i<nreserved_seats.length; i++)
                        nreserved_seatz[i]=nreserved_seats[i];
                    JList list = new JList(nreserved_seatz); 
                    JPanel panel = new JPanel();
                    panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS)); 

                    list.setFont(new Font("Arial", Font.BOLD, 20));
                    list.setFixedCellHeight(38);
                    list.setFixedCellWidth(38);
                    list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
                    list.setLayoutOrientation(JList.HORIZONTAL_WRAP);
                    list.setVisibleRowCount(8);
                    panel.add(list);

                    //αφού βάλαμε τη λίστα θα βάλουμε και το κουμπί
                    create2_b = new JButton("OK");
                    panel.add(create2_b, BorderLayout.SOUTH);
                    //εδώ θα εμφανιστούν (σε νέο παράθυρο) οι διαθέσιμες θέσεις σε checkboxes, ο χρήστης θα επιλέξει κάποιες θέσεις και στη συνέχεια
                    //ο server θα του πει να γράψει τα στοιχεία του για να ολοκληρώσει την διαδικασία (με 2 λεπτά όριο)
                    JFrame frame = new JFrame("Select seat numbers to reserve, Ctrl+Click for multiple selection");
                    frame.add(panel);
                    frame.setVisible(true);
                    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE); //δε θέλουμε να κλείσει η εφαρμογή αν κλείσει το νέο παράθυρο αλλά μόνο το παράθυρο
                    frame.pack();

                    //listener για το κουμπί το οποίο δείχνει ποιές θέσεις θέλει να δεσμεύσει ο client
                    create2_b.addActionListener(new ActionListener() {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            //τώρα ο client στέλνει στον σερβερ, καλώντας την ίδια μέθοδο με παράμετρο=1
                            //η 3η παράμετρος είναι τα στοιχεία που επέλεξε ο χρήστης
                            try {
                                frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING)); //κλείνουμε το παράθυρο όταν πατηθεί το ΟΚ
                                LocateRegistry.getRegistry("ReservationService");
                                AirReservation air = (AirReservation) LocateRegistry.getRegistry("192.168.1.67").lookup("ReservationService");
                                //παίρνουμε τις θέσεις που επέλεξε ο χρήστης από τη λίστα και τις στέλνουμε στον σερβερ
                                //από τη στιγμή που ο σερβερ θα απαντήσει έχουμε 2 λεπτά να κάνουμε τη νέα καταχώριση
                                ArrayList<Integer> nlist = new ArrayList<>(list.getSelectedValuesList());
                                //αν δε στείλει τίποτα ο χρήστης πετάμε exception
                                if (nlist.isEmpty()) {
                                    throw new NullPointerException();
                                }
                                air.reserve(id, 1, nlist, null);
                                //θα δημιουργηθεί ένα JFrame πάλι στο οποίο θα γράψουμε τα στοιχεία μας, επειδή για να γίνει η καταχώριση πρέπει να πατηθεί το κουμπί,
                                //ο χρήστης μπορεί να ακυρώσει τη διαδικασία χωρίς να συμβεί κάτι στα δεδομένα του σερβερ, πρέπει όμως να απελευθερωθούν οι θέσεις που επέλεξε

                                //δημιουργία του panel
                                JPanel panel2 = new JPanel();
                                panel2.setLayout(new GridLayout(3, 2));
                                //ο πελάτης δίνει όνομα και επώνυμο ως στοιχεία
                                panel2.add(new JLabel("Name:"));
                                JTextField new_name = new JTextField(25);
                                panel2.add(new_name);

                                panel2.add(new JLabel("Last Name:"));
                                JTextField new_lname = new JTextField(25);
                                panel2.add(new_lname);

                                JButton new_ok = new JButton("OK");
                                JButton new_clear = new JButton("Clear Data");
                                panel2.add(new_ok);
                                panel2.add(new_clear);

                                JFrame frame = new JFrame("Please insert your details");
                                frame.add(panel2);
                                frame.setVisible(true);
                                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                                frame.pack();

                                //listeners για τα 2 κουμπιά
                                
                                //καθαρισμός
                                new_clear.addActionListener(new ActionListener() {
                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        new_name.setText("");
                                        new_lname.setText("");
                                    }
                                });
                                //μόλις πατηθεί το ΟΚ, η καταχώριση θα γίνει επιτυχώς στον σερβερ και οι αντίστοιχες θέσεις για τη συγκεκριμένη πτήση στον σερβερ θα έχουν τιμή true
                                //δηλαδή θα δηλωθούν ότι είναι δεσμευμένες
                                new_ok.addActionListener(new ActionListener() {
                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        try {
                                            frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING)); //κλείνουμε το παράθυρο όταν πατηθεί το ΟΚ
                                            ArrayList<String> names = new ArrayList<>();
                                            names.add(new_name.getText());
                                            names.add(new_lname.getText());
                                            //αν είναι άδεια τα ονόματα τότε σφάλμα
                                            if (new_name.getText().isEmpty() || new_lname.getText().isEmpty()) {
                                                throw new NullPointerException();
                                            }
                                            air.reserve(id, 2, nlist, names); //προσθήκη της κράτησης
                                            JOptionPane.showMessageDialog(jtp, "Successfully added your reservation", "Success", JOptionPane.INFORMATION_MESSAGE);
                                        } catch (RemoteException ex) {
                                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                                        } catch (NullPointerException npe) {
                                            JOptionPane.showMessageDialog(jtp, "Name or Last Name can't be empty", "Error", JOptionPane.ERROR_MESSAGE);
                                        }
                                    }
                                });
                            } catch (RemoteException | NotBoundException ex) {
                                Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                                //αν η λίστα είναι κενή απλώς γράφουμε στον χρήστη πως δεν επέλεξε κάτι (σφάλμα)
                            } catch (NullPointerException npe) {
                                JOptionPane.showMessageDialog(jtp, "Please select your seat numbers", "Error", JOptionPane.ERROR_MESSAGE);
                            }
                        }
                    });

                } catch (RemoteException | NotBoundException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        //όταν πατηθεί το κουμπί για εμφάνιση στοιχείων
        display_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e
            ) {
                try {
                    LocateRegistry.getRegistry("ReservationService");
                    AirReservation air = (AirReservation) LocateRegistry.getRegistry("192.168.1.67").lookup("ReservationService");
                    String result = air.displayReservationData(display_tf_name.getText(), display_tf_lname.getText(), Integer.parseInt(display_tf_id.getText()));
                    //θα εμφανίσουμε το αποτέλεσμα σε ένα νέο παράθυρο

                    JPanel panel3 = new JPanel();
                    //JTextArea που θα περιέχει το αποτέλεσμα της αναζήτησης του σερβερ
                    JTextArea jta2 = new JTextArea(20, 40);
                    jta2.setEditable(false); //εφόσον αρχικοποιηθεί, δεν επιτρέπουμε την αλλαγή του αφού είναι read only
                    JScrollPane jsp = new JScrollPane(jta2);
                    jta2.setText(result);
                    panel3.add(jta2);
                    
                    JFrame frame3 = new JFrame("Your reservations details");
                    frame3.add(panel3);
                    frame3.setVisible(true);
                    frame3.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                    frame3.pack();

                } catch (RemoteException | NotBoundException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NumberFormatException nfe) {
                    JOptionPane.showMessageDialog(jtp, "ID must be number", "Error ", JOptionPane.ERROR_MESSAGE);
                }
            }

        }
        );

        //καθαρισμός πεδίων, απλώς θέτουμε κενό string στα πεδία
        clear_check.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                check_tf_dest.setText("");
                check_tf_dep.setText("");
                check_tf_date.setText("");
            }
        });

        clear_display.addActionListener( new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                display_tf_name.setText("");
                display_tf_lname.setText("");
                display_tf_id.setText("");
            }
        });

        clear_reserve.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                reserve_tf_id.setText("");
            }
        });
    }
}
