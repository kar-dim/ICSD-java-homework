/* Dimitris Karatzas icsd13072
   Nikolaos Katsiopis icsd13076
   Christos Papakostas icsd13143
 */
package sec3;

import org.apache.commons.codec.binary.Base64;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.WindowEvent;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

public class MainMenu extends JPanel {
    private final JTabbedPane jtp;
    private JPanel j1, j2, j3, j4, j5;
    private JTextField username_r_tf, name_r_tf, lname_r_tf, username_l_tf, date_tf_cr, value_tf_cr, publish_tf_date, edit_tf_date;
    private JPasswordField password_r_pf, password_l_pf;
    private JTextArea text;
    private JScrollPane scroll;
    private final ButtonGroup bg, bg2;
    private final JRadioButton income, expense, income2, expense2;
    private JLabel username_r_lb, password_r_lb, name_r_lb, lname_r_lb, username_l_lb, password_l_lb, date_l_cr, description_l_cr, value_l_cr;
    private JButton register_b, login_b, publish_b, insert_b, edit_b, edit2_b, edit3_b, clear_register, clear_login;
    private final PublicKey publicKey;
    private final PrivateKey privateKey;
    private static String logged_in_username_path; //το (σχετικό) μονοπάτι προς τον φάκελο, στην ουσία είναι της μορφής "./username_fixed/" ώπου fixed το εξηγούμε πιο κάτω στο register
    private String income_expense; //ανάλογα το radio button, η τιμή θα αλλάζει

    public MainMenu() {
        super(new GridLayout(1, 1));
        //έλεγχος κάθε φορά αν τα Keys υπάρχουν, αν δεν υπάρχουν τότε θα τα δημιουργήσουμε και θα τα πάρουμε στο πρόγραμμα
        if (!areKeysPresent()) {
            generateKeys();
            publicKey = getPublicKey();
            privateKey = getPrivateKey();
        } else {
            //αν υπάρχουν τότε απλώς τα παίρνουμε
            publicKey = getPublicKey();
            privateKey = getPrivateKey();
        }
        //radio buttons, επειδή θέλουμε τα radiobuttons να είναι σε 2 διαφορετικά containers, αναγκαστικά πρέπει να δημιουργήσουμε διαφορετικά αντικείμενα
        //(και άρα διαφορετικά listeners που κάνουν την ίδια δουλειά), διοτι αν προστεθεί ένα αντικείμενο σε ένα container 2 φορές, θα "φύγει" από το προηγούμενο
        income_expense = "Income"; //αρχικά η τιμή είναι ίση με Income Καθώς επίσης και το προεπιλεγμένο button είναι στο Income, οπότε δεν υπάρχει πιθανότητα για Null
        income = new JRadioButton("Income");
        expense = new JRadioButton("Expense");
        income2 = new JRadioButton("Income");
        expense2 = new JRadioButton("Expense");
        income.setSelected(true); //να μην υπάρχει περίπτωση να μη επιλεχθεί τίποτα, οπότε εξ ορισμού επιλέγουμε Income
        income2.setSelected(true); //να μην υπάρχει περίπτωση να μη επιλεχθεί τίποτα, οπότε εξ ορισμού επιλέγουμε Income
        bg = new ButtonGroup();
        bg.add(income);
        bg.add(expense);
        bg2 = new ButtonGroup();
        bg2.add(income2);
        bg2.add(expense2);
        //δημιουργία tabs
        jtp = new JTabbedPane(JTabbedPane.TOP);
        jtp.addTab("Register", createRegisterPanel());
        jtp.addTab("Login", createLoginPanel());
        jtp.addTab("Insert record", createInsertPanel());
        jtp.addTab("Edit record", createEditPanel());
        jtp.addTab("Publish Report", createPublishPanel());

        //αρχικά μόνο register επιτρέπεται και login
        jtp.setEnabledAt(0, true);
        jtp.setEnabledAt(1, true);
        jtp.setEnabledAt(2, false);
        jtp.setEnabledAt(3, false);
        jtp.setEnabledAt(4, false);

        //προσθήκη listeners για τα κουμπιά και radio buttons
        setListeners();
        add(jtp);
    }

    //μεθόδοι που φτιάχνουν τα στοιχεία του κάθε tab, μόνο το γραφικό κομμάτι, η λειτουργικότητα δημιουργείται μετά την εκτέλεση των παρακάτω "create*Panel()" συναρτήσεων
    //εδώ απλώς δημιουργούμε τα Labels, text fields κτλ
    private JPanel createRegisterPanel() {
        j1 = new JPanel();
        j1.setLayout(new GridLayout(5, 2));

        //labels και textfields 
        username_r_lb = new JLabel("Username:");
        j1.add(username_r_lb);
        username_r_tf = new JTextField(25);
        j1.add(username_r_tf);
        password_r_lb = new JLabel("Password:");
        j1.add(password_r_lb);
        password_r_pf = new JPasswordField(25);
        j1.add(password_r_pf);
        name_r_lb = new JLabel("Name:");
        j1.add(name_r_lb);
        name_r_tf = new JTextField(25);
        j1.add(name_r_tf);
        lname_r_lb = new JLabel("Last name:");
        j1.add(lname_r_lb);
        lname_r_tf = new JTextField(25);
        j1.add(lname_r_tf);

        //κουμπιά
        register_b = new JButton("Register");
        clear_register = new JButton("Clear Data");

        j1.add(register_b);
        j1.add(clear_register);
        return j1;
    }

    private JPanel createLoginPanel() {
        j2 = new JPanel();
        j2.setLayout(new GridLayout(3, 2));
        username_l_lb = new JLabel("Username:");
        j2.add(username_l_lb);
        username_l_tf = new JTextField(25);
        j2.add(username_l_tf);
        password_l_lb = new JLabel("Password:");
        j2.add(password_l_lb);
        password_l_pf = new JPasswordField(25);
        j2.add(password_l_pf);

        login_b = new JButton("Login");
        clear_login = new JButton("Clear Data");
        j2.add(login_b);
        j2.add(clear_login);

        return j2;
    }

    private JPanel createInsertPanel() {
        j3 = new JPanel();
        j3.setLayout(new GridLayout(5, 1));

        JPanel upper = new JPanel();
        upper.setLayout(new GridLayout(1, 2));
        //προσθήκη jlabels και Jtextfields στο upper level
        date_l_cr = new JLabel("Transaction Date: (dd-MM-yyyy:");
        upper.add(date_l_cr);
        date_tf_cr = new JTextField(25);
        upper.add(date_tf_cr);

        JPanel upper2 = new JPanel();
        upper2.setLayout(new GridLayout(1, 2));
        value_l_cr = new JLabel("Value:");
        upper2.add(value_l_cr);
        value_tf_cr = new JTextField(25);
        upper2.add(value_tf_cr);

        JPanel med = new JPanel();
        med.setLayout(new GridLayout(1, 2));
        description_l_cr = new JLabel("Transaction description:");
        med.add(description_l_cr);
        text = new JTextArea();
        scroll = new JScrollPane(text);
        med.add(scroll);

        JPanel lower = new JPanel();
        lower.setLayout(new GridLayout(1, 2));
        lower.add(income);
        lower.add(expense);

        JPanel button_panel = new JPanel();
        insert_b = new JButton("Create Transaction");
        button_panel.add(insert_b);

        j3.add(upper);
        j3.add(upper2);
        j3.add(med);
        j3.add(lower);
        j3.add(button_panel);
        return j3;
    }

    private JPanel createEditPanel() {
        j4 = new JPanel();

        j4.setLayout(new FlowLayout());

        JPanel top = new JPanel();
        top.setLayout(new FlowLayout());
        top.add(new JLabel("Type the date (dd-MM-yyyy):"));
        edit_tf_date = new JTextField(10);
        top.add(edit_tf_date);

        JPanel med = new JPanel();
        med.setLayout(new FlowLayout());
        med.add(income2);
        med.add(expense2);

        JPanel button_panel = new JPanel();
        button_panel.setLayout(new FlowLayout(FlowLayout.LEFT));
        edit_b = new JButton("Edit");
        button_panel.add(edit_b);

        j4.add(top);
        j4.add(med);
        j4.add(button_panel);

        return j4;
    }

    private JPanel createPublishPanel() {
        j5 = new JPanel();
        j5.setLayout(new FlowLayout());

        j5.add(new JLabel("Type the month number(1-12"));
        publish_tf_date = new JTextField(2);
        j5.add(publish_tf_date);

        publish_b = new JButton("Publish");
        j5.add(publish_b);
        return j5;
    }

    //μέθοδος που θέτει τους διάφορους listeners 
    private void setListeners() {

        //όταν πατηθεί το register, θα γίνει το hash του κωδικού με βάση τον αλγόριθμο sha256
        register_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    ObjectInputStream ois_check;
                    User user_to_check;
                    //αν δεν υπάρχει το αρχείο τότε δημιουργία
                    if (!isUsersFilePresent()) {
                        createUsersFile();
                    }
                    try {
                        ois_check = new ObjectInputStream(new FileInputStream("users.bin"));
                        while ((user_to_check = (User) ois_check.readObject()) != null) {
                            String username_to_check = user_to_check.getUsername();
                            if (username_to_check.equals(username_r_tf.getText())) {
                                //δεν επιτρέπουμε να δημιουργηθεί account αν το username που δώθηκε
                                //είναι ίδιο με κάποιο από τους χρήστες που υπάρχουν ήδη
                                throw new UserExistsException();
                            }
                        }
                    } catch (EOFException eofe) {
                        //φτάσαμε στο τέλος του αρχείου και δε βρέθηκε χρήστης με το username αυτό
                        //οπότε όλα καλά (δε θα εκτελεστεί κάποια ενέργεια, απλώς θα συνεχίσει η ροή κανονικά)
                    }
                    //για register, δημιουργούμε το τυχαίο salt, το βάζουμε μετά από τον κωδικό κα το κάνουμε hash 
                    //όλο μαζί μετον αλγόριθμο sha256 
                    SecureRandom random = new SecureRandom();
                    //20 random bytes (salt)
                    byte[] bytes = new byte[20];
                    random.nextBytes(bytes);
                    String salt = new String(Base64.encodeBase64(bytes));

                    //αν ο κωδικός είναι μικρότερος από 6 χαρακτήρες τότε σφάλμα
                    if (new String(password_r_pf.getPassword()).length() < 6) {
                        throw new PasswordTooShortException();
                    }
                    //πρόσθεση του salt στον κωδικό
                    String pass = new String(password_r_pf.getPassword()) + salt;
                    //System.out.println("Password +salt: " + pass);

                    //τέλος, hash με τον αλγόριθμο sha256
                    MessageDigest digest;
                    StringBuffer sb = new StringBuffer();
                    digest = MessageDigest.getInstance("SHA-256");
                    digest.update(pass.getBytes());
                    byte bytedata[] = digest.digest();
                    for (int i = 0; i < bytedata.length; i++) {
                        sb.append(Integer.toString((bytedata[i] & 0xff) + 0x100, 16).substring(1));
                    }
                    //System.out.println("hash: " + sb.toString());
                    //sb έχει το hash -> sha256_hash(password+salt)
                    //πρέπει τώρα να κρυπτογραφήσουμε με τον RSA, επειδή κάνουμε REGISTER ->ENCRYPT χρησιμοποιούμε μόνο το public key
                    //cipher_data = κρυπτογραφημένη σύνοψη, string cipher_data = σε μορφή string
                    byte[] cipher_data = encrypt(sb.toString(), publicKey);
                    //System.out.println("encrypted bytes (λογικά κινέζικα): " + new String(cipher_data));

                    //τωρα θα δημιουρήσουμε τον φάκελο για αυτόν τον χρήστη
                    //ώπου ο χρήστης έχει βάλει στο username ακατάλληλα γράμματα για όνομα αρχείου (Windows/Unix)
                    //θα το αλλάζουμε σε κάτω παύλα, π.χ dim?kar:17* -> dim_kar_17_
                    String pathName = username_r_tf.getText().replace('<', '_').replace('>', '_').replace(':', '_').replace('/', '_').replace('\\', '_').replace('|', '_').replace('?', '_').replace('*', '_');
                    boolean new_user = new File("./" + pathName).mkdir();
                    //αν επιτύχει η δημιουργία του φακέλου τότε θέτουμε το όνομα του σε μια ιδιότητα του αντικειμένου user
                    if (new_user) {
                        //τέλος θα κρυπτογραφήσουμε ένα νέο συμμετρικό κλειδί (AES) για τον χρήστη, χρησιμοποιόντας τον RSA-2048
                        //και θα το αποθηκεύσουμε στο αρχείο "pathName[με τις αλλαγες πανω]/encrypted.aeskey"
                        //πρώτα δημιυργούμε το συμμετρικό κλειδί
                        KeyGenerator keygen = KeyGenerator.getInstance("AES");
                        keygen.init(256);
                        SecretKey key = keygen.generateKey(); //παράγεται αυτόματα κάποιο κλειδί
                        //Cipher αντικείμενο για κρυπτογράφηση
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
                        //System.out.println("Secret key: " + encodedkey);
                        //τώρα αφύ δημιουργήσαμε το κλειδί, πρέπει να το κρυπτογραφήσουμε
                        byte[] encoded_aes_key = cipher.doFinal(key.getEncoded());
                        //αποθήκευση στο αρχείο (και αν υπάρχει overwrite) encrypted.aeskey
                        boolean file = new File("./" + pathName + "/" + "encrypted.aeskey").createNewFile();
                        if (file) {
                            //γράψιμο τα bytes στο αρχείο encrypted.aeskey
                            FileOutputStream fos = new FileOutputStream("./" + pathName + "/" + "encrypted.aeskey");
                            fos.write(encoded_aes_key);
                            fos.flush();
                            fos.close();

                            //γράψιμο στο αρχείο users.bin τα στοιχεία του χρήστη
                            ObjectOutputStream oos;
                            oos = new ObjectOutputStream(new FileOutputStream("users.bin"));
                            oos.writeObject(new User(username_r_tf.getText(), cipher_data, name_r_tf.getText(), lname_r_tf.getText(), salt, pathName)); //γράφουμε στο αρχείο το object
                            //αν δε πιάσουν τα catch σημαίνει πως γράφτηκε στο αρχείο επιτυχημένα το object οπότε μπορούμε να κλείσουμε το stream
                            oos.flush();
                            oos.close();
                            //αφού επιτύχει το register θα εμφανίσουμε μήνυμα επιτυχίας και θα προτείνουμε να γίνει login
                            JOptionPane.showMessageDialog(jtp, "Successfully registered! Please select the Login tab to login", "Success", JOptionPane.INFORMATION_MESSAGE);
                        } else {
                            JOptionPane.showMessageDialog(jtp, "Cannot register, application error", "Error", JOptionPane.ERROR_MESSAGE);
                        }
                    } //αν δε μπορεί να δημιουργήσει το φάκελο σημαίνει πς υπάρχει ήδη και άρα δε μπορεί να γίνει register
                    else {
                        throw new UserExistsException();
                    }

                } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                    JOptionPane.showMessageDialog(jtp, "Cannot register, application error", "Error", JOptionPane.ERROR_MESSAGE);
                } catch (UserExistsException uee) {
                    JOptionPane.showMessageDialog(jtp, "Could not create account,there is already a user with this username", "Error creating account", JOptionPane.ERROR_MESSAGE);
                } catch (PasswordTooShortException pts) {
                    JOptionPane.showMessageDialog(jtp, "Could not create account,password too short, must be greater than 5 characters", "Error creating account", JOptionPane.ERROR_MESSAGE);
                } catch (NoSuchPaddingException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        });
        //listener για το login, έλεγχος username και password, αυθεντικοποίηση χρήστη
        login_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //Ο χρήστης δίνει username και password
                //πρέπει να ελέγξουμε καταρχήν αν υπάρχει τέτοιο username στο αρχείο
                ObjectInputStream ois;
                User user_to_check;
                if (!isUsersFilePresent()) {
                    createUsersFile();
                }
                boolean done = false;
                try {
                    ois = new ObjectInputStream(new FileInputStream("users.bin"));
                    while ((user_to_check = (User) ois.readObject()) != null) {
                        if (user_to_check.getUsername().equals(username_l_tf.getText())) {
                            //αν βρεθεί το username, πρέπει να ελέγξουμε και τον κωδικό
                            //εδώ πρέπει να αποκρυπτογραφήσουμε, χρησιμοποιούμε το private key
                            //παίρνουμε τα bytes του κωδικού που έδωσε ο χρήστης (encrypted bytes)

                            //τώρα decrypt τον κωδικό
                            String decrypted = decrypt(user_to_check.getPassword(), privateKey);
                            //Decrypted = αποκρυπτογραφημενο password
                            //πρέπει να πάρουμε το salt από το αρχείο και να το προσθέσουμε στο input password που έδωσε ο χρήστης
                            //θα κάνουμε hash με τον ίδιο αλγόριθμο sha256 και θα ελέγξουμε αν το hash είναι ίδιο με το hash του αρχείου

                            String password_to_check = new String(password_l_pf.getPassword()) + user_to_check.getSalt();
                            //hash με τον αλγόριθμο sha256 (ίδια διαδικασία όπως στο register)
                            MessageDigest digest;
                            StringBuffer sb = new StringBuffer();
                            digest = MessageDigest.getInstance("SHA-256");
                            digest.update(password_to_check.getBytes());
                            byte bytedata[] = digest.digest();
                            for (int i = 0; i < bytedata.length; i++) {
                                sb.append(Integer.toString((bytedata[i] & 0xff) + 0x100, 16).substring(1));
                            }
                            //System.out.println("User input pass: "+password_to_check);
                            //System.out.println("User input hash: "+sb.toString());
                            //πήραμε το hash, θα ελέγξουμε αν είναι ίδιο με αυτό του αρχείου
                            if (decrypted.equals(sb.toString())) {
                                //επιτυχές Login
                                JOptionPane.showMessageDialog(jtp, "Successfully logged in", "Success", JOptionPane.INFORMATION_MESSAGE);
                                //ενεργοποίηση των tabs αν επιτύχει το login
                                jtp.setEnabledAt(2, true);
                                jtp.setEnabledAt(3, true);
                                jtp.setEnabledAt(4, true);
                                //disable το tab για Login αν γίνει Login, πρώτα όμως disable τα κουμπιά και textfields
                                //διότι αν απενεργοποιήσουμε το tab μπορεί ακόμα να πατήσει κουμπιά πριν αλλάξει tab
                                //είναι ανούσιο να γίνεται συνεχώς login
                                login_b.setEnabled(false);
                                clear_login.setEnabled(false);
                                username_l_tf.setEnabled(false);
                                password_l_pf.setEnabled(false);
                                jtp.setEnabledAt(1, false);
                                done = true;
                                //θέτουμε στη μεταβλητή το path του φακέλου του χρήστη που μόλις συνδέθηκε, χρειάζεται για τις άλλες λειτουργίες, μόνο ένας logged in
                                //χρήστης μπορεί να κάνει οποιαδήποτε ενέργεια
                                logged_in_username_path = "./" + username_l_tf.getText().replace('<', '_').replace('>', '_').replace(':', '_').replace('/', '_').replace('\\', '_').replace('|', '_').replace('?', '_').replace('*', '_') + "/";
                                //  π.χ θα είναι "./dim_kar/" οπότε ό,τι αρχείο/φάκελος δημιουργείται σε αυτό το directory απλώς θα χρησιμοποιεί το όνομα της μεταβλητής + το όνομα του νέου φακέλου/αρχείου

                                //αφού το login έγινε εποτυχημένα, τώρα θα γίνει ο έλεγχος της ψηφιακής υπογραφής
                                //όμως όταν ο χρήστης κάνει 1η φορά register δεν υπάρχει αρχείο για ψηφιακή υπογραφή οπότε αν δεν υπάρχει το αρχείο σημαίνει πως
                                //έχει κάνει register και δεν έχει κλείσει την εφαρμογή (για να δημιουργηθεί η signature) είτε κάποιος διέγραψε το αρχείο
                                //οπότε αν δε βρεθεί το αρχείο δεν ελέγχουμε για την υπογραφή και ενημερώνουμε τον χρήστη
                                Signature sign = Signature.getInstance("SHA256withRSA");
                                //αρχικοποίηση με το public key
                                sign.initVerify(publicKey);
                                //παίρνουμε από το αρχείο την υπογραφή
                                byte[] sign_bytes_on_file = Files.readAllBytes(new File(logged_in_username_path + "signature.dat").toPath());
                                //πρέπει να πάρουμε τα δεδομένα για τα αρχεία income και expense (όπως στη κλάση MainMenu) και θα ελέγξουμε αν τα δεδομένα επαληθεύουν την υπογραφή

                                boolean expense_file_exists = new File(logged_in_username_path + "expenses.dat").exists();
                                boolean income_file_exists = new File(logged_in_username_path + "income.dat").exists();
                                byte[] expense_bytes = null;
                                byte[] income_bytes = null;
                                byte[] original_bytes = null;
                                //θα πάρουμε τα bytes όλου του αρχείου και θα τα υπογράψουμε
                                if (expense_file_exists) {
                                    expense_bytes = Files.readAllBytes(new File(logged_in_username_path + "expenses.dat").toPath());
                                    original_bytes = new byte[expense_bytes.length];
                                    System.arraycopy(expense_bytes, 0, original_bytes, 0, expense_bytes.length);
                                }
                                //ίδια διαδικασία και για τα έσοδα
                                if (income_file_exists) {
                                    income_bytes = Files.readAllBytes(new File(logged_in_username_path + "income.dat").toPath());
                                    //concat αν υπαρχει ηδη το expense file
                                    if (original_bytes != null) {
                                        original_bytes = new byte[expense_bytes.length + income_bytes.length];
                                        System.arraycopy(expense_bytes, 0, original_bytes, 0, expense_bytes.length);
                                        System.arraycopy(income_bytes, 0, original_bytes, expense_bytes.length, income_bytes.length);
                                        //αν δεν υπάρχει το expense αρχείο τότε παίρνουμε τα bytes του αρχείου income μόνο
                                    } else {
                                        original_bytes = new byte[income_bytes.length];
                                        System.arraycopy(income_bytes, 0, original_bytes, 0, income_bytes.length);
                                    }
                                }
                                //τώρα θα ελέγξουμε αν η υπογραφή μπορεί να επαληθευτεί από τα bytes που πήραμε από τα αρχεία
                                //αν δε μπορεί, τότε σφάλμα
                                if (original_bytes != null) {
                                    sign.update(original_bytes);

                                    if (!sign.verify(sign_bytes_on_file)) {
                                        JOptionPane.showMessageDialog(jtp, "Critical Error! Could not verify your data integrity, someone may have edited your files, or your files may be corrupted", "Warning", JOptionPane.ERROR_MESSAGE);
                                    } //αν όντως επαληθεύονται τα δεδομένα δε βγάζουμε κάποιο μήνυμα λάθους
                                }
                                //περιπτωση που υπαρχει signature file αλλα οχι income/outcomes (δε πρεπει να συμβαινει ποτε αυτο υπο νορμαλ συνθηκες)
                                else
                                    JOptionPane.showMessageDialog(jtp, "Critical Error! Could not verify your data integrity, someone may have edited your files, or your files may be corrupted", "Warning", JOptionPane.ERROR_MESSAGE);


                            } else {
                                //λάθος κωδικός
                                JOptionPane.showMessageDialog(jtp, "Cannot login, wrong password", "Failure", JOptionPane.ERROR_MESSAGE);
                                done = true;
                            }
                        }
                    }

                } catch (EOFException eofe) {
                    //αν δε βρεθεί χρήστης με το συγκεκριμένο username τότε λάθος
                    if (done == false) {
                        JOptionPane.showMessageDialog(jtp, "No username found with the username specified", "Error", JOptionPane.ERROR_MESSAGE);
                    }
                    //αν δε βρεθεί η υπογραφή 
                } catch (NoSuchFileException nsfe) {
                    JOptionPane.showMessageDialog(jtp, "Could not find your digital signature file, if this is the first time you use the application ignore the error", "Error", JOptionPane.ERROR_MESSAGE);
                } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException | SignatureException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        //όταν πατηθεί το κουμπί για την αναφορά, θα ανοίξουμε τα 2 αρχεία, και κάθε αντικείμενο που υπάρχει (sealed) θα το αποκρυπτογραφήσουμε
        //στη συνέχεια για κάθε αντικείμενο θα πάρουμε τη τιμή και μετά θα προσθέσουμε τις τιμές που έχουν (και για έξοδα και για έσοδα)
        //και θα τα εμφανίσουμε σε ένα νέο παράθυρο
        publish_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    //για κάθε είδος οικονομικών στοιχείων έχουμε 2 διαφορετικά text areas
                    JTextArea jt_expenses = new JTextArea();
                    JTextArea jt_income = new JTextArea();
                    jt_expenses.setText("Your Expenses for this month\n\n");
                    jt_income.setText("Your Income for this month\n\n");
                    JScrollPane jp_expenses;
                    JScrollPane jp_income;
                    JPanel panel = new JPanel();
                    panel.setLayout(new GridLayout(1, 2));
                    //παίρνουμε το Date αντικείμενο από τον χρήστη, με έλεγχο και μηνύματα σφάλματος αν δεν είναι σωστή η ημερομηνία
                    SimpleDateFormat ft = new SimpleDateFormat("MM");
                    Date date = ft.parse(publish_tf_date.getText());
                    //παίρνουμε το μήνα
                    int month = date.getMonth() - 1;
                    //ανοίγουμε πρώτα το αρχείο με τα έξοδα
                    boolean expensesfile = new File(logged_in_username_path + "expenses.dat").exists();
                    boolean incomefile = new File(logged_in_username_path + "income.dat").exists();
                    //αν δεν υπάρχει τότε δεν εμφανίζουμε κάποιο αποτέλεσμα
                    if (!expensesfile) {
                        jt_expenses.append("Nothing found!");
                        jt_expenses.setEditable(false);
                        jp_expenses = new JScrollPane(jt_expenses);
                        panel.add(jp_expenses);

                    } else {
                        double total = 0;
                        try {
                            //τα αντικείμενα είναι sealed (κρυπτογραφημένα) θα χρειαστεί να τα αποκρυπτογραφήσουμε με βάση το συμμετρικό AES key
                            //οπότε θα ανοίξουμε το αρχείο με το συμμετρικό κλειδί για να το πάρουμε
                            File keyfile = new File(logged_in_username_path + "encrypted.aeskey");
                            SecretKey originalKey;
                            if (keyfile.exists()) {
                                //το κρυπτογραφημένο AES key έχει ακριβώς 256bytes (RSA-2048 κρυπτογραφεί σε 256 bytes)
                                byte[] aes_encrypted = Files.readAllBytes(keyfile.toPath());
                                //αποκρυπτογράφηση με το ιδιωτικό κλειδί της εφαρμογής
                                Cipher cipher = Cipher.getInstance("RSA");
                                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                                byte[] decoded_key_bytes = cipher.doFinal(aes_encrypted);
                                //μετατροπή των bytes σε SecretKey
                                originalKey = new SecretKeySpec(decoded_key_bytes, 0, decoded_key_bytes.length, "AES");
                            } else {
                                throw new FileNotFoundException();
                            }
                            //αφού έχουμε το AES κλειδί, θα αποκρυπτογραφήσουμε κάθε αντικείμενο με βάση αυτό το κλειδί
                            Cipher cipher2 = Cipher.getInstance("AES");
                            cipher2.init(Cipher.DECRYPT_MODE, originalKey);
                            //ανοίγουμε το object stream και διαβάζουμε τα αντικείμενα ένα-ένα και τα προσθέτουμε στο textfield αν ο μήνας συναλλαγής ήταν ο ίδιος με τον μήνα που έδωσε ο χρήστης
                            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(logged_in_username_path + "expenses.dat"));
                            Expense expense;
                            SealedObject sealed;
                            while ((sealed = (SealedObject) ois.readObject()) != null) {
                                expense = (Expense) sealed.getObject(cipher2);
                                //πρέπει να ελέγξουμε αν ο μήνας είναι ίδιος με τον μήνα που επέλεξε ο χρήστης, getMonth() επιστρεφει απο 0-11 οποτε πρεπει να προσθεσουμε 1
                                if ((month + 1) == expense.getMonth()) {
                                    System.out.print(expense.getMonth());
                                    //για κάθε δαπάνη απλώς την εμφανίζουμε (toString() ) καθώς επίσης προσθέτουμε στον counter τη τιμή της
                                    jt_expenses.append(expense.toString() + "\n\n");
                                    total += expense.getValue();
                                }
                            }

                        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ClassNotFoundException ex) {
                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (EOFException eofe) { //αν φτάσει στο τέλος του αρχείου δεν κάνουμε κάτι
                        } catch (FileNotFoundException ex) {
                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IOException ex) {
                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        //μετά το EOFException, η ροή συνεχίζεται εδώ, οπότε τώρα απλώς προσθετουμε στο πανελ τα δεδομενα που μολις πηραμε απο το αρχειο
                        jt_expenses.append("Total Expenses: " + total);
                        jt_expenses.setEditable(false);
                        jp_expenses = new JScrollPane(jt_expenses);
                        panel.add(jp_expenses);

                    }

                    //ανοίγουμε τώρα το αρχείο με τα έσοδα, ίδια διαδικασία
                    if (!incomefile) {
                        jt_income.append("Nothing found!");
                        jt_income.setEditable(false);
                        jp_income = new JScrollPane(jt_income);
                        panel.add(jp_income);

                    } else {
                        double total = 0;
                        try {
                            //τα αντικείμενα είναι sealed (κρυπτογραφημένα) θα χρειαστεί να τα αποκρυπτογραφήσουμε με βάση το συμμετρικό AES key
                            //οπότε θα ανοίξουμε το αρχείο με το συμμετρικό κλειδί για να το πάρουμε
                            File keyfile = new File(logged_in_username_path + "encrypted.aeskey");
                            SecretKey originalKey;
                            if (keyfile.exists()) {
                                //το κρυπτογραφημένο AES key έχει ακριβώς 256bytes (RSA-2048 κρυπτογραφεί σε 256 bytes)
                                byte[] aes_encrypted = Files.readAllBytes(keyfile.toPath());
                                //αποκρυπτογράφηση με το ιδιωτικό κλειδί της εφαρμογής
                                Cipher cipher = Cipher.getInstance("RSA");
                                cipher.init(Cipher.DECRYPT_MODE, privateKey);
                                byte[] decoded_key_bytes = cipher.doFinal(aes_encrypted);
                                //μετατροπή των bytes σε SecretKey
                                originalKey = new SecretKeySpec(decoded_key_bytes, 0, decoded_key_bytes.length, "AES");
                            } else {
                                throw new FileNotFoundException();
                            }
                            //αφού έχουμε το AES κλειδί, θα αποκρυπτογραφήσουμε κάθε αντικείμενο με βάση αυτό το κλειδί
                            Cipher cipher = Cipher.getInstance("AES");
                            cipher.init(Cipher.DECRYPT_MODE, originalKey);
                            //ανοίγουμε το object stream και διαβάζουμε τα αντικείμενα ένα-ένα και τα προσθέτουμε στο textfield
                            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(logged_in_username_path + "income.dat"));
                            Income income;
                            SealedObject sealed;
                            while (true) {
                                sealed = (SealedObject) ois.readObject();
                                income = (Income) sealed.getObject(cipher);
                                if ((month + 1) == income.getMonth()) {
                                    //για κάθε έσοδο απλώς το εμφανίζουμε (toString() ) καθώς επίσης προσθέτουμε στον counter τη τιμή της
                                    jt_income.append(income.toString() + "\n\n");
                                    total += income.getValue();
                                }
                            }

                        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ClassNotFoundException ex) {
                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (EOFException eofe) { //αν φτάσει στο τέλος του αρχείου δεν κάνουμε κάτι
                        } catch (FileNotFoundException ex) {
                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (IOException ex) {
                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                        }
                        //μετά το EOFException, η ροή συνεχίζεται εδώ, οπότε τώρα απλώς προσθετουμε στο πανελ τα δεδομενα που μολις πηραμε απο το αρχειο
                        jt_income.append("Total Income: " + total);
                        jt_income.setEditable(false);
                        jp_income = new JScrollPane(jt_income);
                        panel.add(jp_income);
                    }
                    //τώρα θα εμφανίσουμε τα δεδομένα σε ένα νέο παράθυρο
                    JFrame frame = new JFrame("Results");
                    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                    frame.setVisible(true);
                    frame.add(panel);
                    frame.pack();

                } catch (ParseException ex) {
                    JOptionPane.showMessageDialog(jtp, "Wrong month number, must be 1-12, example: 1=January, 2=February", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        //listener για το κουμπί για την αλλαγή μιας συναλλαγής
        //η λογική είναι η εξής: ο χρήστης πάλι επιλέγει Expense ή Income ώστε να τροποποιήσει συγκεκριμένο είδος συναλλαγής, και επίσης γράφει την ημερομηνία
        //στη συνέχεια του εμφανίζεται ένα νέο παράθυρο στο οποίο θα υπάρχουν όλες οι συναλλαγές της συγκεκριμένης ημερομηνίας, θα εμφανιστούν σε Labels/Textfields/TextAreas
        //(τροποποίησημα τα 2 τελευταία) ώστε ο χρήστης όταν πατήσει το κουμπί "ΟΚ" θα γραφτούν όλες οι συναλλαγές στο αρχείο. Εδώ ο χρήστης μπορεί να κάνει πολλές αλλαγές
        //δηλαδή να πειράξει πάνω από 1 συναλλαγή
        edit_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                //ανοίγουμε πρώτα το αρχείο με τα έξοδα
                boolean expensesfile = new File(logged_in_username_path + "expenses.dat").exists();
                boolean incomefile = new File(logged_in_username_path + "income.dat").exists();
                //αν δεν υπάρχει τότε δεν εμφανίζουμε κάποιο αποτέλεσμα
                try {
                    //αρχικά παίρνουμε την ημερομηνία και ελέγχουμε αν είναι σωστή
                    SimpleDateFormat ft = new SimpleDateFormat("dd-MM-yyyy");
                    Date date = ft.parse(edit_tf_date.getText());
                    //τώρα θα ψάξουμε στο κατάλληλο αρχείο με βάση το radio button
                    //αρχικά για κάθε αρχείο πρέπει να αποκρυπτογραφήσουμε τα δεδομένα (SealedObject αντικείμενα) και έπειτα
                    //θα τα προσθέσουμε σε ένα GUI ώπου μπορεί ο χρήστης να αλλάξει τα δεδομένα για όλες τις συναλλαγές
                    //αν δεν πειράξει τίποτα (και πατήσει ΟΚ) θα πρέπει η εφαρμογή να γράφει στο αρχείο ακριβώς τις ίδιες πληροφορίες

                    //τώρα θα πάρουμε το AES κλειδί του χρήστη (είναι κρυπτογραφημένο στον φάκελο το με όνομα encryptes.aeskey
                    File keyfile = new File(logged_in_username_path + "encrypted.aeskey");
                    SecretKey originalKey;
                    if (keyfile.exists()) {
                        //το κρυπτογραφημένο AES key έχει ακριβώς 256bytes (RSA-2048 κρυπτογραφεί σε 256 bytes)
                        byte[] aes_encrypted = Files.readAllBytes(keyfile.toPath());
                        //αποκρυπτογράφηση με το ιδιωτικό κλειδί της εφαρμογής
                        Cipher cipher = Cipher.getInstance("RSA");
                        cipher.init(Cipher.DECRYPT_MODE, privateKey);
                        byte[] decoded_key_bytes = cipher.doFinal(aes_encrypted);
                        //μετατροπή των bytes σε SecretKey
                        originalKey = new SecretKeySpec(decoded_key_bytes, 0, decoded_key_bytes.length, "AES");
                    } else {
                        throw new FileNotFoundException();
                    }
                    Cipher cipher = Cipher.getInstance("AES");
                    cipher.init(Cipher.DECRYPT_MODE, originalKey);
                    //οι λίστες που θα έχουν τις καταχωρήσεις που έχουν την ίδια ημερομηνία
                    ArrayList<Expense> e_list = new ArrayList<>();
                    ArrayList<Income> i_list = new ArrayList<>();
                    //οι λίστες που θα έχουν τις καταχωρήσεις που δε θα έχουν την ίδια ημερομηνία, χρειάζονται διότι αφού κάνουμε overwrite το αρχείο
                    //πρέπει να ξαναγράψουμε τα αντικείμενα αυτά πάλι αλλιώς θα χαθούν
                    ArrayList<Expense> ne_list = new ArrayList<>();
                    ArrayList<Income> ni_list = new ArrayList<>();
                    //ανάλογα την επιλογή του χρήστη, θα ψάξουμε και θα εμφανίσουμε τα κατάλληλα records
                    if (income_expense.equals("Expense")) {
                        if (!expensesfile) {
                            //αν δεν υπάρχει τα αρχείο δεν μπορεί να γίνει τροποποίηση
                            JOptionPane.showMessageDialog(jtp, "No expenses records found, please select \"Insert record\" tab to insert a record", "Error", JOptionPane.ERROR_MESSAGE);
                        } else {
                            //αλλιώς αν υπάρχει παίρνουμε τις εγγραφές, θέλουμε και άλλον έναν έλεγχο, αν υπάρχει το αρχείο αλλά είναι άδειο
                            try {
                                //κάθε εγγραφή έχει κρυπτογραφηθεί, οπότε απλώς την αποκρυπτογραφούμε με βάση το privatekey
                                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(logged_in_username_path + "expenses.dat"));
                                SealedObject sealed;
                                Expense expense;
                                while (true) {
                                    sealed = (SealedObject) ois.readObject();
                                    expense = (Expense) sealed.getObject(cipher);
                                    if (expense.getTransactionDate().equals(date)) {
                                        e_list.add(expense); //προσθήκη στη λίστα μόνο αν οι ημερομηνίες είναι ίδιες, αλλιώς προσθήκη στην άλλη λίστα
                                    } else {
                                        ne_list.add(expense);
                                    }
                                }
                            } catch (EOFException eofe) {
                            }
                            if (e_list.isEmpty()) {
                                JOptionPane.showMessageDialog(jtp, "Could not find any records, please check your date", "Error", JOptionPane.ERROR_MESSAGE);
                            } else {
                                //μετά το EOF συνεχίζεται η ροή εδώ, οπότε αφού έχουμε τη λίστα με τις δαπάνες, θα δημιουργήσουμε το GUI στο οποίο θα εμφανίζονται όλες οι δαπάνες
                                JPanel edit_gui = new JPanel();
                                //λίστες με fields/textareas με βάση τον αριθμό των στοιχείων
                                JTextField[] date_tf_edit = new JTextField[e_list.size()];
                                JTextField[] value_tf_edit = new JTextField[e_list.size()];
                                JTextArea[] text_edit = new JTextArea[e_list.size()];

                                edit_gui.setLayout(new GridLayout(e_list.size() + 1, 1, 1, 5)); //+1 γραμμή για κουμπί (2η παράμετρος, οι άλλες 2 είναι για τα κενά ανάμεσα στα στοιχεία)
                                for (int i = 0; i < e_list.size(); i++) {
                                    //προσθήκη των γραφικών στοιχείων σε ένα πανελ το οποίο αντιστοιχεί σε μια record, στην επόμενη επανάληψη πάλι δημιουργούμε
                                    //τα ίδια πεδία και θέτουμε αντίστοιχα τις τιμές
                                    JPanel one_record = new JPanel();
                                    one_record.setLayout(new GridLayout(1, 6));
                                    one_record.add(new JLabel("Date:"));
                                    date_tf_edit[i] = new JTextField(25);
                                    //μετατροπή του Date σε string της μορφής dd-MM-yyyy
                                    Calendar cal = Calendar.getInstance();
                                    cal.setTime(date);
                                    int day = cal.get(Calendar.DAY_OF_MONTH);
                                    int month = cal.get(Calendar.MONTH) + 1;
                                    int year = cal.get(Calendar.YEAR);

                                    date_tf_edit[i].setText(day + "-" + month + "-" + year); //θέτουμε την τιμή που είχε
                                    one_record.add(date_tf_edit[i]);

                                    one_record.add(new JLabel("Value:"));
                                    value_tf_edit[i] = new JTextField(25);
                                    value_tf_edit[i].setText(Double.toString(e_list.get(i).getValue())); //θέτουμε την τιμή που είχε
                                    one_record.add(value_tf_edit[i]);

                                    one_record.add(new JLabel("Description:"));
                                    text_edit[i] = new JTextArea();
                                    text_edit[i].setText(e_list.get(i).getDescription());
                                    one_record.add(text_edit[i]);

                                    edit_gui.add(one_record);
                                }
                                //αφού δημιουργηθούν όλες οι παραπάνω εγγραφές, πρέπει να βάλουμε και το κουμπί στο τέλος
                                JPanel button_panel = new JPanel();
                                edit2_b = new JButton("OK");
                                button_panel.add(edit2_b);
                                edit_gui.add(button_panel);
                                //δημιουργία νέου παραθύρου
                                JFrame frame = new JFrame("Edit");
                                frame.add(edit_gui);
                                frame.setVisible(true);
                                frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                                frame.pack();
                                //τώρα για να τροποποιηθεί η λίστα, πρέπει ο χρήστης να πατήσει το κουμπί edit2_b του παραθύρου αυτουνού, οπότε
                                //στον listener θα γίνει η τελική τροποποίηση
                                edit2_b.addActionListener(new ActionListener() {
                                    @Override
                                    public void actionPerformed(ActionEvent e) {
                                        try {
                                            frame.dispatchEvent(new WindowEvent(frame, WindowEvent.WINDOW_CLOSING)); //κλείσιμο το παράθυρο δε το χρειαζόμαστε πλέον

                                            //αυτό που πρέπει να κάνουμε είναι να πάρουμε τα δεδομένα που έβαλε ο χρήστης και να τα γράψουμε στο αρχείο
                                            //το ιδιωτικό κλειδί το έχουμε ήδη οπότε απλώς γράφουμε τα sealed objects στο αρχείο με το κλειδί αυτό
                                            //θα κάνουμε overwrite το αρχείο, διότι παίρνουμε τα ανανεωμένα δεδομένα από τον χρήστη, προφανώς ο χρήστης μάλλον δε θα έχει αλλάξει
                                            //όλα τα records οπότε θα κάνουμε μερικά άσκοπα writes στον δίσκο, αφού γράφουμε όλη τη λίστα
                                            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(logged_in_username_path + "expenses.dat"));
                                            //επειδή στην επιλογή αυτή (τροποποίηση) ο χρήστης δεν αφαιρεί ή δημιουργεί νέες καταχωρήσεις, το μέγεθος θα είναι ίσο με το μέγεθος των 2 λιστών
                                            //πρώτα θα βάλουμε τις μη αλλαγμένες καταχωρίσεις

                                            cipher.init(Cipher.ENCRYPT_MODE, originalKey); //θέτουμε λειτουργία encrypt

                                            for (int i = 0; i < ne_list.size(); i++) {
                                                oos.writeObject(new SealedObject(ne_list.get(i), cipher));
                                            }
                                            oos.flush();
                                            //έπειτα τις αλλαγμένες, πρώτα όμως πρέπει να ενημερώσουμε τη λίστα με τις νέες αλλαγές του χρήστη

                                            for (int i = 0; i < e_list.size(); i++) {
                                                e_list.get(i).setDescription(text_edit[i].getText());

                                                Date date_to_add = ft.parse(date_tf_edit[i].getText());
                                                e_list.get(i).setTransactionDate(date_to_add);

                                                e_list.get(i).setValue(Double.parseDouble(value_tf_edit[i].getText()));
                                                //γράψιμο στο stream το κρυπτογραφημένο αντικείμενο
                                                oos.writeObject(new SealedObject(e_list.get(i), cipher));
                                            }
                                            oos.flush();
                                            oos.close();
                                            //αν δε πιάσουν τα exception  σημαίνει πως γράφτηκαν σωστά τα αντικείμενα
                                            JOptionPane.showMessageDialog(jtp, "Successfully updated your transactions", "Success", JOptionPane.INFORMATION_MESSAGE);
                                        } catch (IOException | IllegalBlockSizeException | InvalidKeyException ex) {
                                            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                                        } catch (ParseException ex) {
                                            JOptionPane.showMessageDialog(jtp, "Wrong date format, must be in dd-MM-yyyy, example: 10-10-2010", "Error", JOptionPane.ERROR_MESSAGE);
                                        }

                                    }
                                });
                            }
                        }
                    } //ακριβώς η ίδια διαδικασία και για την επιλογή εσόδων
                    else if (!incomefile) {
                        //αν δεν υπάρχει τα αρχείο δεν μπορεί να γίνει τροποποίηση
                        JOptionPane.showMessageDialog(jtp, "No income records found, please select \"Insert record\" tab to insert a record", "Error", JOptionPane.ERROR_MESSAGE);
                    } else {
                        //αλλιώς αν υπάρχει παίρνουμε τις εγγραφές, θέλουμε και άλλον έναν έλεγχο, αν υπάρχει το αρχείο αλλά είναι άδειο
                        try {
                            //κάθε εγγραφή έχει κρυπτογραφηθεί, οπότε απλώς την αποκρυπτογραφούμε με βάση το privatekey
                            ObjectInputStream ois = new ObjectInputStream(new FileInputStream(logged_in_username_path + "income.dat"));
                            SealedObject sealed;
                            Income income;
                            while (true) {
                                sealed = (SealedObject) ois.readObject();
                                income = (Income) sealed.getObject(cipher);
                                if (income.getTransactionDate().equals(date)) {
                                    i_list.add(income); //προσθήκη στη λίστα μόνο αν οι ημερομηνίες είναι ίδιες, αλλιώς τίποτα
                                } else {
                                    ni_list.add(income);
                                }
                            }
                        } catch (EOFException eofe) {
                        }
                        if (i_list.isEmpty()) {
                            JOptionPane.showMessageDialog(jtp, "Could not find any records, please check your date", "Error", JOptionPane.ERROR_MESSAGE);
                        } else {
                            //μετά το EOF συνεχίζεται η ροή εδώ, οπότε αφού έχουμε τη λίστα με τις δαπάνες, θα δημιουργήσουμε το GUI στο οποίο θα εμφανίζονται όλα τα έσοδα
                            JPanel edit_gui = new JPanel();
                            //λίστες με fields/textareas με βάση τον αριθμό των στοιχείων
                            JTextField[] date_tf_edit = new JTextField[i_list.size()];
                            JTextField[] value_tf_edit = new JTextField[i_list.size()];
                            JTextArea[] text_edit = new JTextArea[i_list.size()];

                            edit_gui.setLayout(new GridLayout(i_list.size() + 1, 1, 1, 5)); //+1 γραμμή για κουμπί (2η παράμετρος, οι άλλες 2 είναι για τα κενά ανάμεσα στα στοιχεία)
                            for (int i = 0; i < i_list.size(); i++) {
                                //προσθήκη των γραφικών στοιχείων σε ένα πανελ το οποίο αντιστοιχεί σε μια record, στην επόμενη επανάληψη πάλι δημιουργούμε
                                //τα ίδια πεδία και θέτουμε αντίστοιχα τις τιμές
                                JPanel one_record = new JPanel();
                                one_record.setLayout(new GridLayout(1, 6));
                                one_record.add(new JLabel("Date:"));
                                date_tf_edit[i] = new JTextField(25);
                                //μετατροπή του Date σε string της μορφής dd-MM-yyyy
                                Calendar cal = Calendar.getInstance();
                                cal.setTime(date);
                                int day = cal.get(Calendar.DAY_OF_MONTH);
                                int month = cal.get(Calendar.MONTH) + 1;
                                int year = cal.get(Calendar.YEAR);

                                date_tf_edit[i].setText(day + "-" + month + "-" + year); //θέτουμε την τιμή που είχε
                                one_record.add(date_tf_edit[i]);

                                one_record.add(new JLabel("Value:"));
                                value_tf_edit[i] = new JTextField(25);
                                value_tf_edit[i].setText(Double.toString(i_list.get(i).getValue())); //θέτουμε την τιμή που είχε
                                one_record.add(value_tf_edit[i]);

                                one_record.add(new JLabel("Description:"));
                                text_edit[i] = new JTextArea(10, 20);
                                text_edit[i].setText(i_list.get(i).getDescription());
                                one_record.add(text_edit[i]);

                                edit_gui.add(one_record);
                            }
                            //αφού δημιουργηθούν όλες οι παραπάνω εγγραφές, πρέπει να βάλουμε και το κουμπί στο τέλος
                            JPanel button_panel = new JPanel();
                            edit3_b = new JButton("OK");
                            button_panel.add(edit2_b);
                            edit_gui.add(button_panel);
                            //δημιουργία νέου παραθύρου
                            JFrame frame = new JFrame("Edit");
                            frame.add(edit_gui);
                            frame.setVisible(true);
                            frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
                            frame.pack();
                            //τώρα για να τροποποιηθεί η λίστα, πρέπει ο χρήστης να πατήσει το κουμπί edit3_b του παραθύρου αυτουνού, οπότε
                            //στον listener θα γίνει η τελική τροποποίηση (γράψιμο στο αρχείο)
                            edit3_b.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    try {
                                        //αυτό που πρέπει να κάνουμε είναι να πάρουμε τα δεδομένα που έβαλε ο χρήστης και να τα γράψουμε στο αρχείο
                                        //το ιδιωτικό κλειδί το έχουμε ήδη οπότε απλώς γράφουμε τα sealed objects στο αρχείο με το κλειδί αυτό
                                        //θα κάνουμε overwrite το αρχείο, διότι παίρνουμε τα ανανεωμένα δεδομένα από τον χρήστη, προφανώς ο χρήστης μάλλον δε θα έχει αλλάξει
                                        //όλα τα records οπότε θα κάνουμε μερικά άσκοπα writes στον δίσκο, αφού γράφουμε όλη τη λίστα, καθώς επίσης και τα μη πειραγμένα (διαφορετική ημερομηνία) δεδομένα
                                        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(logged_in_username_path + "income.dat"));
                                        //επειδή στην επιλογή αυτή (τροποποίηση) ο χρήστης δεν αφαιρεί ή δημιουργεί νέες καταχωρήσεις, το μέγεθος θα είναι ίσο με το μέγεθος των 2 λιστών
                                        //πρώτα θα βάλουμε τις μη αλλαγμένες καταχωρίσεις 

                                        cipher.init(Cipher.ENCRYPT_MODE, originalKey); //θέτουμε λειτουργία encrypt

                                        //πρώτα γράφουμε τις μη πειραγμένες
                                        for (int i = 0; i < ni_list.size(); i++) {
                                            oos.writeObject(new SealedObject(ni_list.get(i), cipher));
                                        }
                                        oos.flush();
                                        //έπειτα τις αλλαγμένες, πρώτα όμως πρέπει να ενημερώσουμε τη λίστα με τις νέες αλλαγές του χρήστη

                                        for (int i = 0; i < i_list.size(); i++) {
                                            i_list.get(i).setDescription(text_edit[i].getText());

                                            Date date_to_add = ft.parse(date_tf_edit[i].getText());
                                            i_list.get(i).setTransactionDate(date_to_add);

                                            i_list.get(i).setValue(Double.parseDouble(value_tf_edit[i].getText()));
                                            //γράψιμο στο stream το κρυπτογραφημένο αντικείμενο
                                            oos.writeObject(new SealedObject(i_list.get(i), cipher));
                                        }
                                        oos.flush();
                                        //αν δε πιάσουν τα exception  σημαίνει πως γράφτηκαν σωστά τα αντικείμενα
                                        JOptionPane.showMessageDialog(jtp, "Successfully updated your transactions", "Success", JOptionPane.INFORMATION_MESSAGE);
                                        oos.close();
                                    } catch (IOException | IllegalBlockSizeException | InvalidKeyException ex) {
                                        Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                                    } catch (ParseException ex) {
                                        JOptionPane.showMessageDialog(jtp, "Wrong date format, must be in dd-MM-yyyy, example: 10-10-2010", "Error", JOptionPane.ERROR_MESSAGE);
                                    }

                                }
                            });
                        }
                    }
                } catch (ParseException ex) {
                    JOptionPane.showMessageDialog(jtp, "Wrong date format, must be in dd-MM-yyyy, example: 10-10-2010", "Error", JOptionPane.ERROR_MESSAGE);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IOException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
        //listeners για τα Radio buttons (expense ή income)
        //απλώς αλλάζουν τη τιμή του string ανάλογα την επιλογή
        income.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                income_expense = "Income";
            }
        });
        expense.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                income_expense = "Expense";
            }
        });
        income2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                income_expense = "Income";
            }
        });
        expense2.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                income_expense = "Expense";
            }
        });
        //όταν πατηθεί το κουμπί για δημιουργία μιας αναφοράς
        insert_b.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    //αυτό που θα κάνει η εφαρμογή είναι να πάρει τα δεδομένα (ημερομηνία/περιγραφή/τύπος/ποσό) και καταρχήν θα ελέγξει για κενές τιμές
                    if (date_tf_cr.getText().isEmpty() || value_tf_cr.getText().isEmpty() || text.getText().isEmpty()) {
                        throw new NullPointerException();
                    }
                    //αφού κανένα δεν είναι empty τώρα, ελέγχουμε αν η ημερομηνία είναι όντως σε σωστή μορφή καθώς επίσης και η τιμή να είναι αριθμός                    
                    SimpleDateFormat ft = new SimpleDateFormat("dd-MM-yyyy");
                    Date date = ft.parse(date_tf_cr.getText());
                    double value = Double.parseDouble(value_tf_cr.getText());
                    if (income_expense.equals("Expense")) {
                        //πρώτα πρέπει να κρυπτογραφήσουμε τα δεδομένα με το συμμετρικό κλειδί
                        //το συμμετρικό κλειδί έχει κρυπτογραφηθεί με τον RSA-2048, οπότε το ανοίγουμε (encrypted.aeskey), το αποκρυπτογραφούμε και στη συνέχεια κρυπτογραφούμε τα δεδομένα των δαπανών
                        //και τέλος τα γράφουμε στο αρχείο
                        File keyfile = new File(logged_in_username_path + "encrypted.aeskey");
                        if (keyfile.exists()) {
                            //το κρυπτογραφημένο AES key έχει ακριβώς 256bytes (RSA-2048 κρυπτογραφεί σε 256 bytes)
                            byte[] aes_encrypted = Files.readAllBytes(keyfile.toPath());
                            //αποκρυπτογράφηση με το ιδιωτικό κλειδί της εφαρμογής
                            Cipher cipher = Cipher.getInstance("RSA");
                            cipher.init(Cipher.DECRYPT_MODE, privateKey);
                            byte[] decoded_key_bytes = cipher.doFinal(aes_encrypted);
                            //μετατροπή των bytes σε SecretKey
                            SecretKey originalKey = new SecretKeySpec(decoded_key_bytes, 0, decoded_key_bytes.length, "AES");
                            //αφού πήραμε το κλειδί μπορούμε να κρυπτογραφήσουμε τα δεδομένα, στη συνέχεια θα τα γράψουμε στο αρχείο
                            //πρώτα όμως θα δημιουργήσουμε το αντικείμενο για τα έξοδα
                            Expense expense = new Expense(value, text.getText(), date);
                            //κρυπτογράφηση με το AES κλειδί, για να κρυπτογραφήσουμε ένα αντικείμενο πρέπει να χρησιμοποιήσουμε την κλάση SealedObject
                            Cipher cipher2 = Cipher.getInstance("AES");
                            cipher2.init(Cipher.ENCRYPT_MODE, originalKey);
                            SealedObject sealed = new SealedObject(expense, cipher2);
                            //το αντικείμενο sealed είναι κρυπτογραφημένο οπότε αυτό θα γράψουμε στο αρχείο, πρώτα ελέγχουμε αν υπάρχει, αν δεν υπάρχει τότε δημιουργία νέου
                            //αλλιώς overwrite
                            boolean expensefile = new File(logged_in_username_path + "expenses.dat").exists();
                            if (!expensefile) {
                                //αν δεν υπάρχει το δημιουργούμε
                                new File(logged_in_username_path + "expenses.dat").createNewFile();
                                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(logged_in_username_path + "expenses.dat"))) {
                                    oos.writeObject(sealed);
                                    oos.flush();
                                    oos.close();
                                }
                            } else {
                                //αν υπάρχει το αρχείο, τότε απλώς προσθέτουμε μια νέα καταχώριση στο τέλος του αρχείου (append)
                                //χρήση του constructor FileOutputStream(filename, APPEND=true)
                                new File(logged_in_username_path + "expenses.dat").createNewFile();
                                try (ObjectOutputStream oos = new AppendableObjectOutputStream(new FileOutputStream(logged_in_username_path + "expenses.dat", true))) {
                                    oos.writeObject(sealed);
                                    oos.flush();
                                    oos.close();
                                }
                            }
                            //αν δε πεταχτεί κάποιο exception Η εκτέλεση θα συνεχιστεί εδώ οπότε σημαίνει πως γράφτηκε σωστά
                            JOptionPane.showMessageDialog(jtp, "Successfully added your expense record to the file", "Success", JOptionPane.INFORMATION_MESSAGE);

                        } else {
                            throw new FileNotFoundException();
                        }

                    } else {
                        //ίδια διαδικασία
                        File keyfile = new File(logged_in_username_path + "encrypted.aeskey");
                        if (keyfile.exists()) {
                            //το κρυπτογραφημένο AES key έχει ακριβώς 256bytes (RSA-2048 κρυπτογραφεί σε 256 bytes)
                            byte[] aes_encrypted = Files.readAllBytes(keyfile.toPath());
                            //αποκρυπτογράφηση με το ιδιωτικό κλειδί της εφαρμογής
                            Cipher cipher = Cipher.getInstance("RSA");
                            cipher.init(Cipher.DECRYPT_MODE, privateKey);
                            byte[] decoded_key_bytes = cipher.doFinal(aes_encrypted);
                            //μετατροπή των bytes σε SecretKey
                            SecretKey originalKey = new SecretKeySpec(decoded_key_bytes, 0, decoded_key_bytes.length, "AES");
                            //αφού πήραμε το κλειδί μπορούμε να κρυπτογραφήσουμε τα δεδομένα, στη συνέχεια θα τα γράψουμε στο αρχείο
                            //πρώτα όμως θα δημιουργήσουμε το αντικείμενο για τα έξοδα
                            Income income = new Income(value, text.getText(), date);
                            //κρυπτογράφηση με το AES κλειδί, για να κρυπτογραφήσουμε ένα αντικείμενο πρέπει να χρησιμοποιήσουμε την κλάση SealedObject
                            Cipher cipher2 = Cipher.getInstance("AES");
                            cipher2.init(Cipher.ENCRYPT_MODE, originalKey);
                            SealedObject sealed = new SealedObject(income, cipher2);
                            //το αντικείμενο sealed είναι κρυπτογραφημένο οπότε αυτό θα γράψουμε στο αρχείο, πρώτα ελέγχουμε αν υπάρχει, αν δεν υπάρχει τότε δημιουργία νέου
                            //αλλιώς overwrite
                            boolean incomefile = new File(logged_in_username_path + "income.dat").exists();
                            if (!incomefile) {
                                //αν δεν υπάρχει το δημιουργούμε
                                new File(logged_in_username_path + "income.dat").createNewFile();
                                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(logged_in_username_path + "income.dat"))) {
                                    oos.writeObject(sealed);
                                    oos.flush();
                                    oos.close();
                                }
                            } else {
                                //αν υπάρχει το αρχείο, τότε απλώς προσθέτουμε μια νέα καταχώριση στο τέλος του αρχείου (append)
                                //χρήση του constructor FileOutputStream(filename, APPEND=true)
                                new File(logged_in_username_path + "income.dat").createNewFile();
                                try (ObjectOutputStream oos = new AppendableObjectOutputStream(new FileOutputStream(logged_in_username_path + "income.dat", true))) {
                                    oos.writeObject(sealed);
                                    oos.flush();
                                    oos.close();
                                }
                            }
                            //αν δε πεταχτεί κάποιο exception Η εκτέλεση θα συνεχιστεί εδώ οπότε σημαίνει πως γράφτηκε σωστά
                            JOptionPane.showMessageDialog(jtp, "Successfully added your income record to the file", "Success", JOptionPane.INFORMATION_MESSAGE);

                        } else {
                            throw new FileNotFoundException();
                        }

                    }
                } catch (NullPointerException npe) {
                    JOptionPane.showMessageDialog(jtp, "Some fields are empty, please check your data", "Error", JOptionPane.ERROR_MESSAGE);
                } catch (ParseException ex) {
                    JOptionPane.showMessageDialog(jtp, "Wrong date format, must be in dd-MM-yyyy, example: 10-10-2010", "Error", JOptionPane.ERROR_MESSAGE);
                } catch (FileNotFoundException ex) {
                    JOptionPane.showMessageDialog(jtp, "Cannot find encryption key!", "Critical error", JOptionPane.ERROR_MESSAGE);
                } catch (NumberFormatException nfe) {
                    JOptionPane.showMessageDialog(jtp, "Value must be a number", "Error", JOptionPane.ERROR_MESSAGE);
                } catch (IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                    Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });

        //καθαρισμός των πεδίων
        clear_login.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                username_l_tf.setText("");
                password_l_pf.setText("");
            }
        });

        clear_register.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                username_r_tf.setText("");
                password_r_pf.setText("");
                name_r_tf.setText("");
                lname_r_tf.setText("");
            }
        });
    }

    //συνάρτηση που δημιουργεί τα κλειδιά
    private void generateKeys() {
        try {
            //RSA-2048
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            //παίρνουμε το ζεύγος private/public keys
            final KeyPair key = keyGen.generateKeyPair();

            File privateKeyFile = new File("private.key");
            File publicKeyFile = new File("public.key");

            // δημιουργία των αρχείων που θα κρατήσουν τα κλειδιά
            //δεν έχουμε βάλει ακόμα τα κλειδιά, απλώς δημιυργούμε τα αρχεία
            if (privateKeyFile.getParentFile() != null) {
                privateKeyFile.getParentFile().mkdirs();
            }
            privateKeyFile.createNewFile();

            if (publicKeyFile.getParentFile() != null) {
                publicKeyFile.getParentFile().mkdirs();
            }
            publicKeyFile.createNewFile();

            try ( // σώζουμε στα αρχεία τα κλειδιά
                    ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream(publicKeyFile))) {
                publicKeyOS.writeObject(key.getPublic());
            }

            try (ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream(privateKeyFile))) {
                privateKeyOS.writeObject(key.getPrivate());
            }

        } catch (NoSuchAlgorithmException | IOException e) {
            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, e);
        }
    }

    //μέθοδος που ελέγχει αν τα κλειδιά υπάρχουν
    private boolean areKeysPresent() {
        File prKey = new File("private.key");
        File pubKey = new File("public.key");
        return prKey.exists() && pubKey.exists();
    }

    //Μέθοδος που κρυπτογραφεί ένα string με βάση το public key
    private byte[] encrypt(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            // κρυπτογράφηση
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, e);
        }
        return cipherText;
    }

    //αποκρυπτοράφηση byte[] δεδομένων με βάση το private key
    private String decrypt(byte[] text, PrivateKey key) {
        byte[] decryptedText = null;
        try {
            final Cipher cipher = Cipher.getInstance("RSA");
            //αποκρυπτογράφηση
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedText = cipher.doFinal(text);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new String(decryptedText);
    }

    //μεθόδοι για να πάρουμε τα κλειδιά, απλώς ανοίγουν τα αντίστοιχα αρχεία και παίρνουν τα αντικείμενα των κλειδιών
    //και τα επιστρέφουν
    private PublicKey getPublicKey() {
        ObjectInputStream ois = null;
        PublicKey pubKey = null;
        try {
            ois = new ObjectInputStream(new FileInputStream("public.key"));
            pubKey = (PublicKey) ois.readObject();
            ois.close();
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
        }
        return pubKey;
    }

    public static PrivateKey getPrivateKey() {
        ObjectInputStream ois = null;
        PrivateKey prKey = null;
        try {
            ois = new ObjectInputStream(new FileInputStream("private.key"));
            prKey = (PrivateKey) ois.readObject();
            ois.close();
        } catch (IOException | ClassNotFoundException ex) {
            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
        }
        return prKey;
    }

    //έλεγχος αν υπάρχει το αρχείο "users.bin"
    private boolean isUsersFilePresent() {
        return (new File("users.bin").exists());
    }

    //δημιουργία του αρχείου χρηστών
    private void createUsersFile() {
        try {
            File users_file = new File("users.bin");
            if (users_file.getParentFile() != null) {
                users_file.getParentFile().mkdirs();
            }
            users_file.createNewFile();
        } catch (IOException ex) {
            Logger.getLogger(MainMenu.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //επιστρέφει τη διαδρομή του loggedin χρήστη, θα χρησιμοποιηθεί από την Main κλάση για να πάρει τον logged in χρήστη
    public static String getLoggedInUsernamePath() {
        return logged_in_username_path;
    }

}
//κλάση που χρησιμοποιούμε για να κάνουμε append, απλώς τη μέθοδος writeStreamHeader() τη κάνουμε override ώστε να μη κάνει τίποτα,
//δηλαδή να μη γράφει στην αρχή του αρχείου διάφορα Headers του stream, έτσι δε θα γίνεται Overwrite το αρχείο

class AppendableObjectOutputStream extends ObjectOutputStream {

    public AppendableObjectOutputStream(OutputStream out) throws IOException {
        super(out);
    }

    @Override
    protected void writeStreamHeader() throws IOException {
    }
}
