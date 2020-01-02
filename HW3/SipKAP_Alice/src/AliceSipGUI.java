//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.sound.sampled.AudioSystem;
import javax.sound.sampled.Clip;
import javax.sound.sampled.LineUnavailableException;
import javax.sound.sampled.UnsupportedAudioFileException;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;

public class AliceSipGUI extends AliceEncryptedConnection {

    private boolean logged;
    private final JFrame frame;
    private JFrame registerframe;
    private JFrame loginframe;
    private final JPanel screenPanel;
    private final JPanel buttonPanel;
    private final JTextArea screen;
    private final JScrollPane scroll;
    private final JButton register;
    private final JButton login;
    private final JButton call;
    private final JButton register_r;
    private final JButton clear_r;
    private final JButton clear_l;
    private final JButton login_l;
    private final JMenuBar menubar;
    private final JMenu menu;
    private final JMenuItem credits;
    private final JMenuItem about;
    private final JTextField username_r;
    private final JPasswordField password_r;
    private final JTextField username_l;
    private final JPasswordField password_l;
    private User logged_in;
    //τα παρακάτω 6 χρειάζονται ώστε ο client Να μπορεί να δέχεται ασύγχρονα connections
    private ServerSocket ssock_passive, ssock_active;
    private ObjectOutputStream oos_passive, oos_active;
    private ObjectInputStream ois_passive, ois_active;
    //i2p server/client
    private I2PServer i2pserver_passive, i2pserver_active, i2pserver_direct;
    private I2PClient i2preceiver_direct;
    //i2p streams
    private ObjectInputStream i2p_inputstream_active, i2p_inputstream_passive, i2p_direct_input;
    private ObjectOutputStream i2p_outputstream_active, i2p_outputstream_passive, i2p_direct_output;

    public AliceSipGUI(ObjectInputStream ois, ObjectOutputStream oos, SecretKey secret, IvParameterSpec iv, String token, Mac hmac) {
        logged = false; //Αρχικά δεν είναι logged in ο χρήστης
        this.mac = hmac;
        symmetricKey = secret;
        this.iv = iv;
        this.inputstream = ois;
        this.outputstream = oos;
        this.token = token;
        username_r = new JTextField(20);
        password_r = new JPasswordField(20);
        username_l = new JTextField(20);
        password_l = new JPasswordField(20);
        frame = new JFrame("Alice VoIP Caller");
        frame.setLayout(new BorderLayout());
        frame.setVisible(true);
        frame.setResizable(false);
        frame.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        menubar = new JMenuBar();
        menu = new JMenu("Menu");
        about = new JMenuItem("About");
        credits = new JMenuItem("Credits");
        menu.add(about);
        menu.add(credits);
        menubar.add(menu);
        frame.setJMenuBar(menubar);
        screenPanel = new JPanel(new BorderLayout());
        screen = new JTextArea();
        screen.setEditable(false);
        screen.setFont(new Font("Arial", Font.PLAIN, 18));
        scroll = new JScrollPane(screen);
        scroll.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED);
        screenPanel.add(scroll);
        buttonPanel = new JPanel(new FlowLayout());
        register = new JButton("Register");
        login = new JButton("Login");
        call = new JButton("Call");
        buttonPanel.add(register);
        buttonPanel.add(login);
        buttonPanel.add(call);
        frame.add(screenPanel);
        frame.add(buttonPanel, BorderLayout.PAGE_END);
        frame.setSize(new Dimension(300, 400));
        frame.setLocationRelativeTo(null);
        register_r = new JButton("OK");
        login_l = new JButton("OK");
        clear_r = new JButton("Clear");
        clear_l = new JButton("Clear");
        setListeners();
    }

    private void setListeners() {
        about.addActionListener((ActionEvent e) -> {
            JOptionPane.showMessageDialog(frame, "Source: University of the Aegean\nDepartment: ICSD\n"
                    + "Class: Network Security 2017-2018\nPurpose: SIP protocol privacy and anonymity", "About", JOptionPane.INFORMATION_MESSAGE);
        });

        credits.addActionListener((ActionEvent e) -> {
            JOptionPane.showMessageDialog(frame, "Developers:\n\nName: Nikolaos Katsiopis\nRN: icsd13076\nStatus: Undergraduate"
                    + "\n\nName: Dimitrios Karatzas\nRN: icsd13072\nStatus: Undergraduate", "Credits", JOptionPane.INFORMATION_MESSAGE);
        });
        register.addActionListener((ActionEvent e) -> {
            registerframe = new JFrame("Register");
            registerframe.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            registerframe.setVisible(true);
            registerframe.setResizable(true);
            JPanel row1 = new JPanel(new GridLayout(1, 2));
            JPanel row2 = new JPanel(new GridLayout(1, 2));
            JPanel buttonRow = new JPanel(new FlowLayout());
            JPanel rowIncluder = new JPanel(new GridLayout(3, 1));
            row1.add(new JLabel("Username:"));
            row1.add(username_r);
            row2.add(new JLabel("Password:"));
            row2.add(password_r);
            buttonRow.add(register_r);
            buttonRow.add(clear_r);
            rowIncluder.add(row1);
            rowIncluder.add(row2);
            rowIncluder.add(buttonRow);
            registerframe.add(rowIncluder);
            registerframe.setSize(new Dimension(220, 150));
            registerframe.setLocationRelativeTo(AliceSipGUI.this.frame);
        });
        //καθαρισμός των username/password στο "register" window
        clear_r.addActionListener((ActionEvent e) -> {
            password_r.setText("");
            username_r.setText("");
        });
        //καθαρισμός των username/password στο "login" window
        clear_l.addActionListener((ActionEvent e) -> {
            password_l.setText("");
            username_l.setText("");
        });
        //πατιέται το "ΟΚ" στο register window
        register_r.addActionListener((ActionEvent e) -> {
            this.registerframe.setVisible(false);
            this.registerframe.dispose();
            //πρώτα ελέγχουμε αν κάτι είναι κενό οπότε αμέσως σφάλμα
            if (username_r.getText().isEmpty() || password_r.getPassword().length == 0) {
                updateScreen("Empty register name or password...");
                return;
            }
            try {

                //στέλνουμε "REGISTER"
                outputstream.writeObject(encrypt("REGISTER"));
                outputstream.flush();
                //δημιουργία ενός USER με τα στοιχεια που δόθηκαν, το στελνουμε στο stream
                User to_register = new User(username_r.getText(), new String(password_r.getPassword()), this.token, this.HMAC_Sign(username_r.getText() + this.token));
                outputstream.writeObject(encryptUser(username_r.getText(), new String(password_r.getPassword())));
                outputstream.flush();
                //περιμένουμε απάντηση από server, αν μπορέσαμε να κάνουμε register τότε μας στέλνει "REGISTER_OK"
                Message got = (Message) decrypt((SealedObject) inputstream.readObject());
                checkMessage(got);
                if (got.getMessage().equals("REGISTER_OK")) {
                    updateScreen("REGISTERED!");
                    //κάνουμε αυτόματα login
                    logged = true;
                    login.setEnabled(false); //αφού γίνει το login Δεν επιτρέπεται πάλι login ή register
                    register.setEnabled(false);
                    logged_in = new User(to_register.getUsername(), to_register.getPassword(), this.token, this.HMAC_Sign(username_r.getText() + this.token));

                    makeClientAvailable();

                } else if (got.getMessage().equals("REGISTER_FAIL")) {
                    updateScreen("FAILED TO REGISTER");
                }
                //κλείσιμο του mini παραθύρου
                this.username_r.setText("");
                this.password_r.setText("");

            } catch (IOException ex) {
                Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ConnectionNotSafeException ex) {
                Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        });

        login.addActionListener((ActionEvent e) -> {
            loginframe = new JFrame("Login");
            loginframe.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
            loginframe.setVisible(true);
            loginframe.setResizable(true);
            JPanel row1 = new JPanel(new GridLayout(1, 2));
            JPanel row2 = new JPanel(new GridLayout(1, 2));
            JPanel buttonRow = new JPanel(new FlowLayout());
            JPanel rowIncluder = new JPanel(new GridLayout(3, 1));
            row1.add(new JLabel("Username:"));
            row1.add(username_l);
            row2.add(new JLabel("Password:"));
            row2.add(password_l);
            buttonRow.add(login_l);
            buttonRow.add(clear_l);
            rowIncluder.add(row1);
            rowIncluder.add(row2);
            rowIncluder.add(buttonRow);
            loginframe.add(rowIncluder);
            loginframe.setSize(new Dimension(220, 150));
            loginframe.setLocationRelativeTo(AliceSipGUI.this.frame);
        });

        //πατιεται το "ΟΚ" στο login window
        login_l.addActionListener((ActionEvent e) -> {
            this.loginframe.setVisible(false);
            this.loginframe.dispose();
            //πρώτα ελέγχουμε αν κάτι είναι κενό οπότε αμέσως σφάλμα
            if (username_l.getText().isEmpty() || password_l.getPassword().length == 0) {
                updateScreen("Empty register name or password...");
                return;
            }
            try {
                //στέλνουμε "LOGIN"
                outputstream.writeObject(encrypt("LOGIN"));
                outputstream.flush();
                //δημιουργία ενός USER με τα στοιχεια που δόθηκαν, το στελνουμε στο stream
                outputstream.writeObject(encryptUser(username_l.getText(), new String(password_l.getPassword())));
                outputstream.flush();
                Message got = (Message) decrypt((SealedObject) inputstream.readObject());
                checkMessage(got);
                if (got.getMessage().equals("LOGIN_OK")) {
                    updateScreen("LOGGED IN!");
                    logged = true;
                    logged_in = new User(login_l.getText(), new String(password_l.getPassword()), this.token, this.HMAC_Sign(login_l.getText() + this.token));
                    login.setEnabled(false); //αφού γίνει το login Δεν επιτρέπεται πάλι login ή register
                    register.setEnabled(false);

                    //άνοιγμα socket και αναμονή για κάποια σύνδεση
                    makeClientAvailable();

                } else if (got.getMessage().equals("LOGIN_FAIL")) {
                    updateScreen("FAILED TO LOGIN!");
                }
                this.username_l.setText("");
                this.password_l.setText("");
                this.loginframe.dispose();
            } catch (IOException ex) {
                Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ConnectionNotSafeException ex) {
                Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
            }
        });

        call.addActionListener((ActionEvent e) -> {
            if (!logged) {
                updateScreen("YOU MUST BE LOGGED IN TO CALL...");
            } else {
                synchronized (this) {
                    Runnable client_wait = () -> {
                        try {
                            updateScreen("CALLING");
                            call.setEnabled(false);
                            //τώρα επικοινωνεί ο client με τον proxy, στέλνει το πρώτο SIP μήνυμα (INVITE), ο proxy το προωθεί στον επόμενο proxy και αμέσως στέλνει TRYING
                            //το πρόγραμμα επειδή είναι εξομοίωση δουλεύει μόνο για δυο usernames: alice και bob
                            SIPMessage invite = new SIPMessage(Sip.INVITE, logged_in.getContact(), "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign(logged_in.getContact() + this.token));
                            this.outputstream.writeObject(encryptSip(invite));
                            this.outputstream.flush();
                            //τώρα λαμβάνουμε μήνυμα αν ο άλλος client είναι online, αν δεν είναι τότε εμφανίζουμε σχετικό μήνυμα
                            Message is_online = (Message) decrypt((SealedObject) inputstream.readObject());

                            if (is_online.getMessage().equals("USER_ONLINE")) {
                                ssock_active = new ServerSocket(8003); //8003 port -> (active) Alice, 8004 (active) port -> Bob
                                Socket conn = ssock_active.accept();
                                //τώρα που συνδέθηκε ο Proxy μαζί μας, σημαίνει πως έχει απάντηση από τον άλλον Client
                                ois_active = new ObjectInputStream(conn.getInputStream());
                                oos_active = new ObjectOutputStream(conn.getOutputStream());

                                //δημιουργία του I2PServer, στέλνουμε destination string στον proxy
                                i2pserver_active = new I2PServer();
                                oos_active.writeObject(encrypt(i2pserver_active.getDestinationString()));
                                oos_active.flush();
                                //αναμονή σύνδεσης
                                i2pserver_active.accept();
                                //παραγωγή των i2p streams
                                this.i2p_inputstream_active = i2pserver_active.getI2PInputStream();
                                this.i2p_outputstream_active = i2pserver_active.getI2POutputStream();

                                updateScreen("WAITING FOR \"TRYING\"");
                                //αναμένουμε TRYING
                                SIPMessage trying = (SIPMessage) decrypt((SealedObject) this.i2p_inputstream_active.readObject());
                                checkSipMessage(trying);
                                if (!trying.getType().equals(Sip.TRYING)) {
                                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                                }
                                updateScreen("GOT \"TRYING\"");

                                updateScreen("WAITING FOR \"RINGING\"");
                                //επίσης αναμένουμε RINGING
                                SIPMessage ringing = (SIPMessage) decrypt((SealedObject) this.i2p_inputstream_active.readObject());
                                checkSipMessage(ringing);
                                if (!ringing.getType().equals(Sip.RINGING)) {
                                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                                }
                                updateScreen("GOT \"RINGING\"");

                                //τέλος, αναμένουμε ΟΚ
                                updateScreen("WAITING FOR \"OK\"");
                                SIPMessage ok = (SIPMessage) decrypt((SealedObject) this.i2p_inputstream_active.readObject());
                                checkSipMessage(ok);
                                if (!ok.getType().equals(Sip.OK)) {
                                    updateScreen("BOB REJECTED YOUR CALL");
                                } else {
                                    updateScreen("GOT \"OK\"");
                                    //αν μας έστειλε ΟΚ τότε θα δεχτούμε το I2P Destination String του άλλου client ώστε να επικοινωνήσουμε μέσω I2P
                                    Message got_i2p_dest = (Message) decrypt((SealedObject) this.i2p_inputstream_active.readObject());
                                    checkMessage(got_i2p_dest);
                                    //σύνδεση μέσω I2P τώρα και στέλνουμε το μήνυμα SIP ACK μέσω I2P
                                    this.i2preceiver_direct = new I2PClient(got_i2p_dest.getMessage());
                                    this.i2preceiver_direct.accept();
                                    //παραγωγή streams
                                    this.i2p_direct_input = this.i2preceiver_direct.getI2PInputStream();
                                    this.i2p_direct_output = this.i2preceiver_direct.getI2POutputStream();
                                    //στέλνουμε ACK και τέλος
                                    this.i2p_direct_output.writeObject(new SIPMessage(Sip.ACK, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", null, null));
                                    this.i2p_direct_output.flush();
                                    updateScreen("SENDING \"ACK\"");

                                    /* RTP ΕΔΩ */ 
                                    
                                    this.i2preceiver_direct.close();
                                }

                                //εδώ τελείωσε το πρωτόκολλο SIP!!
                                updateScreen("SIP SESSION FINISHED!");
                                this.call.setEnabled(true);

                            } else {
                                updateScreen("USER IS OFFLINE");
                                this.call.setEnabled(true);
                            }
                            //κλείσιμο του serversocket ώστε να μπορεί να ξαναγίνει σύνδεση

                            ois_active.close();
                            oos_active.close();
                            ssock_active.close();
                        } catch (IOException ex) {
                            Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (ClassNotFoundException ex) {
                            Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (ConnectionNotSafeException ex) {
                            Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                        } catch (UnknownProtocolCommandException ex) {
                            System.err.println("SIP Message type error");
                        }
                    };
                    Thread clientThread = new Thread(client_wait);
                    clientThread.start();
                }
            }
        });
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (JOptionPane.showConfirmDialog(frame, "Are you sure you want to exit ?", "Exit", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
                    frame.dispose();
                    System.exit(0);
                }
            }
        });
    }

    //This method appends the inputed text to the screen
    public void updateScreen(String text) {
        SwingUtilities.invokeLater(() -> {
            screen.append(text + "\n");
        });
    }

    //μέθοδος που ανοίγει sockets ώστε να συνδεθεί ο proxy του για να δεχτεί κλήση
    private void makeClientAvailable() {
        //new Thread για αναμονή σύνδεσης (ο Client εφόσον κάνει LOGIN μπορεί και να δεχτεί CALL από κάποιον άλλον)
        synchronized (this) {
            Runnable client_wait = () -> {
                while (true) {
                    try {
                        ssock_passive = new ServerSocket(8001); //8001 port -> Alice, 8002 port -> Bob
                        //αυτός που θα συνδεθεί τώρα μαζι μας θα είναι ο proxy για να μας ειδοποιήσει πως κάποιος μας καλεί
                        Socket conn = ssock_passive.accept();
                        ois_passive = new ObjectInputStream(conn.getInputStream());
                        oos_passive = new ObjectOutputStream(conn.getOutputStream());

                        //δημιουργία του I2PServer, στέλνουμε destination string στον proxy
                        i2pserver_passive = new I2PServer();
                        oos_passive.writeObject(encrypt(i2pserver_passive.getDestinationString()));
                        oos_passive.flush();
                        //αναμονή σύνδεσης
                        i2pserver_passive.accept();
                        //παραγωγή των i2p streams
                        this.i2p_inputstream_passive = i2pserver_passive.getI2PInputStream();
                        this.i2p_outputstream_passive = i2pserver_passive.getI2POutputStream();

                        //αναμένουμε το MODE, αν mode==false σημαίνει πως στειλαμε εμείς CALL οπότε τα μηνύματα θα είναι της μορφής "ο proxy μας στέλνει TRYING, RINGING και ΟΚ"
                        //αλλιώς σημαίνει πως μας έστειλαν CALL οπότε εμείς πρέπει να στείλουμε
                        Message mmode = (Message) decrypt((SealedObject) this.i2p_inputstream_passive.readObject());
                        String mode = mmode.getMessage();
                        if (mode.equals("false")) {
                            updateScreen("WAITING FOR \"TRYING\"");
                            //αναμένουμε TRYING
                            SIPMessage trying = (SIPMessage) decrypt((SealedObject) this.i2p_inputstream_passive.readObject());
                            checkSipMessage(trying);
                            if (!trying.getType().equals(Sip.TRYING)) {
                                throw new UnknownProtocolCommandException("SIP Message type is not valid");
                            }
                            updateScreen("GOT \"TRYING\"");

                            updateScreen("WAITING FOR \"RINGING\"");
                            //επίσης αναμένουμε RINGING
                            SIPMessage ringing = (SIPMessage) decrypt((SealedObject) this.i2p_inputstream_passive.readObject());
                            checkSipMessage(ringing);
                            if (!ringing.getType().equals(Sip.RINGING)) {
                                throw new UnknownProtocolCommandException("SIP Message type is not valid");
                            }
                            updateScreen("GOT \"RINGING\"");

                            //τέλος, αναμένουμε ΟΚ
                            updateScreen("WAITING FOR \"OK\"");
                            SIPMessage ok = (SIPMessage) decrypt((SealedObject) this.i2p_inputstream_passive.readObject());
                            checkSipMessage(ok);
                            if (!ok.getType().equals(Sip.OK)) {
                                updateScreen("BOB REJECTED YOUR CALL");

                            } else {
                                updateScreen("GOT \"OK\"");
                                //αν μας έστειλε ΟΚ τότε θα δεχτούμε το I2P Destination String του άλλου client ώστε να επικοινωνήσουμε μέσω I2P
                                Message got_i2p_dest = (Message) decrypt((SealedObject) this.i2p_inputstream_passive.readObject());
                                checkMessage(got_i2p_dest);
                                //σύνδεση μέσω I2P τώρα και στέλνουμε το μήνυμα SIP ACK μέσω I2P
                                this.i2preceiver_direct = new I2PClient(got_i2p_dest.getMessage());
                                this.i2preceiver_direct.accept();
                                //παραγωγή streams
                                this.i2p_direct_input = this.i2preceiver_direct.getI2PInputStream();
                                this.i2p_direct_output = this.i2preceiver_direct.getI2POutputStream();
                                //στέλνουμε ACK και τέλος
                                this.i2p_direct_output.writeObject(new SIPMessage(Sip.ACK, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", null, null));
                                this.i2p_direct_output.flush();
                                updateScreen("SENDING \"ACK\"");

                                /* RTP ΕΔΩ */
                                
                                this.i2preceiver_direct.close();
                            }
                            //εδώ τελείωσε το πρωτόκολλο SIP!!
                            updateScreen("SIP SESSION FINISHED!");
                            this.call.setEnabled(true);

                        } else {
                            //αναμένουμε INVITE από τον proxy

                            SIPMessage prx_invite = (SIPMessage) decrypt((SealedObject) this.i2p_inputstream_passive.readObject());
                            checkSipMessage(prx_invite);
                            if (!prx_invite.getType().equals(Sip.INVITE)) {
                                throw new UnknownProtocolCommandException("SIP Message type is not valid");
                            }
                            updateScreen("GOT AN INVITE!");

                            //στέλνουμε RINGING
                            this.i2p_outputstream_passive.writeObject(encryptSip(new SIPMessage(Sip.RINGING, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:alice@proxyA.com>" + this.token))));
                            this.i2p_outputstream_passive.flush();
                            updateScreen("SENDING \"RINGING\"");

                            //παίζουμε ήχο κλήσης
                            Clip clip = AudioSystem.getClip();
                            clip.open(AudioSystem.getAudioInputStream(new File("sounds\\call.wav")));
                            clip.start();
                            clip.loop(Clip.LOOP_CONTINUOUSLY);

                            //στέλνουμε ΟΚ ή UNAUTHORIZED
                            int reply = JOptionPane.showConfirmDialog(AliceSipGUI.this.frame, prx_invite.getFrom() + "is calling! Accept?", "Call", JOptionPane.YES_NO_OPTION);
                            if (reply == JOptionPane.YES_OPTION) {
                                this.i2p_outputstream_passive.writeObject(encryptSip(new SIPMessage(Sip.OK, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:alice@proxyA.com>" + this.token))));
                                this.i2p_outputstream_passive.flush();
                                updateScreen("SENDING \"OK\"");
                                clip.stop();
                                //αν πατηθεί ΟΚ τότε πρέπει να στείλουμε την I2P Διεύθυνση μας μετά το ΟΚ , ώστε να μας στείλει ACK απευθείας (χωρίς τους proxy)
                                this.i2pserver_direct = new I2PServer();
                                this.i2p_outputstream_passive.writeObject(encrypt(this.i2pserver_direct.getDestinationString()));
                                this.i2p_outputstream_passive.flush();
                                updateScreen("SENDING I2P SESSION STRING");
                                //παραγωγή των streams και αναμονή του ACK
                                this.i2pserver_direct.accept();
                                this.i2p_direct_output = this.i2pserver_direct.getI2POutputStream();
                                this.i2p_direct_input = this.i2pserver_direct.getI2PInputStream();

                                //λαμβάνουμε το ACK
                                SIPMessage ack = (SIPMessage) this.i2p_direct_input.readObject();
                                if (!ack.getType().equals(Sip.ACK)) {
                                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                                }
                                updateScreen("GOT ACK");

                                /* RTP ΕΔΩ */
                                
                                this.i2pserver_direct.close();

                            } else {
                                this.i2p_outputstream_passive.writeObject(encryptSip(new SIPMessage(Sip.UNAUTHORIZED, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:alice@proxyA.com>" + this.token))));
                                this.i2p_outputstream_passive.flush();
                                updateScreen("SENDING \"UNAUTHORIZED\"");
                                clip.stop();
                            }

                            //εδώ τελείωσε το πρωτόκολλο SIP!!
                            updateScreen("SIP SESSION FINISHED!");
                            this.call.setEnabled(true);
                        }
                        //κλείσιμο του serversocket ώστε να μπορεί να ξαναγίνει σύνδεση

                        ois_passive.close();
                        oos_passive.close();
                        ssock_passive.close();

                    } catch (IOException ex) {
                        Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (ClassNotFoundException ex) {
                        Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (ConnectionNotSafeException ex) {
                        Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (UnknownProtocolCommandException ex) {
                        System.err.println("SIP Message type error");
                    } catch (LineUnavailableException ex) {
                        Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                    } catch (UnsupportedAudioFileException ex) {
                        Logger.getLogger(AliceSipGUI.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }
            };
            Thread clientThread = new Thread(client_wait);
            clientThread.start();
        }
    }
}
