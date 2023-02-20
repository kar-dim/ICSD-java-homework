//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//κλάση που υλοποιεί τις κοινές μεθόδους για τις κλάσεις client/server
public abstract class BobProxyEncryptedConnection {

    protected SecretKey symmetricKey, symmetricKey_prx; //το συμμετρικό κλειδί που παράγεται (symmetricKey) μεταξύ client-proxy και μεταξύ proxies (symmetricKey_prx)
    protected String token, token_prx; //χρησιμοποιείται για να αποτρέψουμε τα replay attacks
    protected IvParameterSpec iv;
    protected Mac mac, mac_prx;
    protected Socket connection, connection_prx;
    protected ObjectInputStream inputstream, inputstream_prx;
    protected ObjectOutputStream outputstream, outputstream_prx;
    protected KeyStore keystore;
    protected KeyStore truststore;
    protected PublicKey received_pubkey; //αυτό που λαμβάνει 
    protected PublicKey received_dh_pubkey; //DH public key που λαμβάνουμε
    protected Signature sig;
    protected String i2p_string_client, i2p_string_proxy;
    protected SecureRandom random;
    protected KeyAgreement keyagree;
    protected PrivateKey privkey;
    protected KeyPair keypair_dh, keypair_dh2; //τα DH KeyPairs, το πρώτο είναι το keypair μεταξύ client-proxy και το 2ο μεταξύ proxy-proxy
    protected BigInteger p, g, p2, g2; //παράμετροι p,g, τους παράγει ο client και τους στέλνει στον "server" πριν ξεκινήσει η διαδικασία
    //p2,g2 είναι για τον STS μεταξύ proxy1-proxy2
    protected User logged_in;
    protected String mode;
    //τα "active" είναι στη περίπτωση που ο proxy Συνδέεται στον client (για να του προωθήσει το INVITE του άλλου client)
    protected ObjectOutputStream i2p_client_oos, i2p_client_active_oos, i2p_proxy_oos;
    protected ObjectInputStream i2p_client_ois, i2p_client_active_ois, i2p_proxy_ois;
    protected I2PServer i2pserver_to_client, i2pserver_to_proxy;
    protected I2PClient i2pclient_to_proxy, i2pclient_to_client;

    //μέθοδος που όταν καλείται ανοίγει τη πόρτα 2313 -> περιμένει έναν proxy να συνδεθεί σε αυτόν
    //αυτό γίνεται ΜΟΝΟ όταν ο αντίστοιχος client έχει κάνει LOGIN (ή REGISTER, αφού αν γίνει register κάνουμε login αυτόματα)
    //και αφού συνδεθεί, ανταλλάσει κλειδιά
    protected synchronized void makeProxyAvailable() {

        Runnable serverTask = () -> {
            while (true) {
                try {
                    System.out.println("Waiting for (proxy) connections...");
                    ServerSocket ssock_prx = new ServerSocket(2313);
                    connection_prx = ssock_prx.accept();

                    System.out.println("Proxy " + connection_prx.getInetAddress() + " connected!");
                    inputstream_prx = new ObjectInputStream(connection_prx.getInputStream());
                    outputstream_prx = new ObjectOutputStream(connection_prx.getOutputStream());
                    //ανταλλαγή κλειδιών
                    if (this.mode.equals("RSA")) {
                        this.whileConnected("RSA", "proxy", "keys\\skey_proxy.key", outputstream_prx, inputstream_prx, false, false);
                    } else {
                        this.whileConnected("STS", "proxy", "keys\\skey_proxy.key", outputstream_prx, inputstream_prx, false, false);
                    }
                    //κλείσιμο των sockets σχετικά με την ανταλλαγή κλειδιών, δεν χρειάζονται πλέον αφού δουλεύουμε με I2P
                    outputstream_prx.close();
                    inputstream_prx.close();
                    connection_prx.close();
                    ssock_prx.close();
                    //εφόσον γίνει η ανταλλαγή κλειδιών, θα καλέσουμε τη μέθοδο που είναι ηκύρια μέθοδος της άσκησης, δηλαδή η επικοινωνία με SIP μηνύματα
                    this.call(true);

                } catch (IOException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                    System.err.println("Alice is calling but an unexpected error occured...!");

                } catch (InvalidKeyException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        };
        Thread serverThread = new Thread(serverTask);
        serverThread.start();

    }

//μέθοδος που ανταλλάσει κλειδιά μεταξύ των proxies (client πάτησε CALL)
    protected synchronized void keyExchangeProxies(String mode) {

        Runnable serverTask = () -> {
            while (true) {
                try {
                    //πρώτα αναμένουμε INVITE από client
                    SIPMessage invite = (SIPMessage) decrypt((SealedObject) this.i2p_client_ois.readObject(), "client");
                    checkSipMessage(invite, false); //έλεγχος με την hmac proxy-client
                    if (!invite.getType().equals(Sip.INVITE)) {
                        throw new UnknownProtocolCommandException("SIP Message type is not valid");
                    }
                } catch (IOException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ClassNotFoundException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (ConnectionNotSafeException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (UnknownProtocolCommandException ex) {
                    System.err.println("SIP Message type error");
                }

                try {
                    connection_prx = new Socket("localhost", 1313);
                    outputstream_prx = new ObjectOutputStream(connection_prx.getOutputStream());
                    inputstream_prx = new ObjectInputStream(connection_prx.getInputStream());
                    //ανταλλαγή κλειδιών
                    if (this.mode.equals("RSA")) {
                        this.whileConnected("RSA", "proxy", "keys\\skey_proxy.key", outputstream_prx, inputstream_prx, true, false);
                    } else {
                        this.whileConnected("STS", "proxy", "keys\\skey_proxy.key", outputstream_prx, inputstream_prx, true, false);
                    }
                    //κλείσιμο των "_prx" socket, δεν χρειάζονται πλέον αφού δουλεύουμε με I2P
                    outputstream_prx.close();
                    inputstream_prx.close();
                    connection_prx.close();
                    //εφόσον γίνει η ανταλλαγή κλειδιών, θα καλέσουμε τη μέθοδο που είναι ηκύρια μέθοδος της άσκησης, δηλαδή η επικοινωνία με SIP μηνύματα
                    this.call(false);
                } catch (IOException ex) {
                    //ενημέρωση του χρήστη (που έκανε το CALL) ότι δε μπόρεσε να επιτευχθεί σύνδεση, που σημαίνει ότι ο proxy είναι offline
                    //και άρα δεν έχει κάνει login ο παραλήπτης
                    try {
                        outputstream.writeObject(encrypt("USER_OFFLINE", "client"));
                        outputstream.flush();
                        System.err.println("Alice is offline!");
                    } catch (IOException ex1) {
                        Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex1);
                    }
                } catch (InvalidKeyException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (IllegalBlockSizeException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (BadPaddingException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchProviderException ex) {
                    Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        };
        Thread serverThread = new Thread(serverTask);
        serverThread.start();

    }

    //mode == false: PROXY δέχεται INVITE από client (πάτησε CALL o client)
    //mode == true: δέχεται το INVITE από τον PROXY και το στέλνει στον client (γράφει στον proxy TRYING)
    protected void call(boolean mode) {

        if (!mode) {
            try {

                //στέλνουμε ότι ο user είναι online
                this.i2p_client_oos.writeObject(encrypt("USER_ONLINE", "client"));
                this.i2p_client_oos.flush();

                //στέλνουμε INVITE στον Client. Δε μπορούμε στο άκυρο απλώς να στείλουμε INVITE (το INVITE o client δε το περιμένει σε συγκεκριμένη στιγμή, πχ αν πατηθεί κάποιο
                //κουμπί ή οτιδήποτε), στην ουσία πρέπει να ανοιχτεί ένα νέο ServerStream από τη μεριά του και να συνδεθεί ο proxy με άλλα streams και sockets
                //σε άλλο thread το υλοποιεί ο client
                Socket client = new Socket();
                //2 λεπτά timeout (120000 milliseconds -> 2 mins)
                client.connect(new InetSocketAddress("localhost", 8004), 120000); //8003: η πύλη που περιμένει ο Client1 (Alice) ενώ 8004: η πύλη που περιμένει ο Bob//8001: η πύλη που περιμένει ο Client1 (Alice) ενώ 8002: η πύλη που περιμένει ο Bob
                ObjectOutputStream client_oos = new ObjectOutputStream(client.getOutputStream());
                ObjectInputStream client_ois = new ObjectInputStream(client.getInputStream());

                //δεχόμαστε το i2p destination string του client
                Message client_dest_msg = (Message) decrypt((SealedObject) client_ois.readObject(), "client");
                this.i2p_string_client = client_dest_msg.getMessage();
                this.i2pclient_to_client = new I2PClient(this.i2p_string_client);

                //σύνδεση μέσω I2P
                this.i2pclient_to_client.accept();
                //παραγωγή των i2p streams
                this.i2p_client_active_oos = this.i2pclient_to_client.getI2POutputStream();
                this.i2p_client_active_ois = this.i2pclient_to_client.getI2PInputStream();

                //στέλνουμε αμέσως TRYING στον Client
                this.i2p_client_active_oos.writeObject(encryptSip(new SIPMessage(Sip.TRYING, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:alice@proxyA.com>" + this.token)), "client"));
                this.i2p_client_active_oos.flush();

                //προώθηση του INVITE στον 2ο proxy
                SIPMessage sipm = new SIPMessage(Sip.INVITE, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", this.token_prx, this.HMAC_SignProxy("<sips:alice@proxyA.com>" + this.token_prx));
                this.i2p_proxy_oos.writeObject(encryptSip(sipm, "proxy"));
                this.i2p_proxy_oos.flush();

                //αναμένουμε TRYING από τον 2o proxy
                SIPMessage trying = (SIPMessage) decrypt((SealedObject) this.i2p_proxy_ois.readObject(), "proxy");
                checkSipMessage(trying, true); //έλεγχος με την hmac proxy-proxy
                if (!trying.getType().equals(Sip.TRYING)) {
                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                }

                //αναμένουμε RINGING από τον 2o proxy
                SIPMessage ringing = (SIPMessage) decrypt((SealedObject) this.i2p_proxy_ois.readObject(), "proxy");
                checkSipMessage(ringing, true); //έλεγχος με την hmac proxy-proxy
                if (!ringing.getType().equals(Sip.RINGING)) {
                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                }

                //στέλνουμε RINGING στον Client
                this.i2p_client_active_oos.writeObject(encryptSip(new SIPMessage(Sip.RINGING, "<sips:proxyB@proxyB.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:proxyB@proxyB.com>" + this.token)), "client"));
                this.i2p_client_active_oos.flush();

                //αναμένουμε OK από τον 2o proxy ή UNAUTHORIZED
                boolean ok = false;
                SIPMessage ok_or_unauthorized = (SIPMessage) decrypt((SealedObject) this.i2p_proxy_ois.readObject(), "proxy");
                checkSipMessage(ok_or_unauthorized, true); //έλεγχος με την hmac proxy-proxy
                if (ok_or_unauthorized.getType().equals(Sip.OK)) {
                    ok = true;
                } else if (ok_or_unauthorized.getType().equals(Sip.UNAUTHORIZED)) {
                    ok = false;
                } else {
                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                }
                //στέλνουμε OK ή UNAUTHORIZED στον Client
                if (ok) {
                    this.i2p_client_active_oos.writeObject(encryptSip(new SIPMessage(Sip.OK, "<sips:proxyB@proxyB.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:proxyB@proxyB.com>" + this.token)), "client"));
                    this.i2p_client_active_oos.flush();
                    //αν έστειλε ΟΚ ο proxy, τότε μας στέλνει επίσης και το i2p destination string του άλλου client
                    Message receiver_dest = (Message) decrypt((SealedObject) this.i2p_proxy_ois.readObject(), "proxy");
                    //στέλνουμε την i2p διεύθυνση του άλλου client στον client μας
                    this.i2p_client_active_oos.writeObject(encrypt(receiver_dest.getMessage(), "client"));
                    this.i2p_client_active_oos.flush();
                } else {
                    this.i2p_client_active_oos.writeObject(encryptSip(new SIPMessage(Sip.UNAUTHORIZED, "<sips:proxyB@proxyB.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:proxyB@proxyB.com>" + this.token)), "client"));
                    this.i2p_client_active_oos.flush();
                }
                //εδώ τελείωσε το πρωτόκολλο SIP!!
                System.out.println("END!");
            } catch (IOException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ConnectionNotSafeException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnknownProtocolCommandException ex) {
                System.err.println("SIP Message type error");
            }
        } else {
            try {
                //INVITE από τον PROXY, στέλνουμε στον client το INVITE και στελνουμε στον proxy TRYING. Μετα περιμενουμε RINGING απο CLIENT και το στλενουμε στον PROXY. Τελος αναμενουμε οκ
                //απο CLIENT και το στελνουμε στον PROXY

                //αναμένουμε INVITE από τον 2o proxy
                SIPMessage invite = (SIPMessage) decrypt((SealedObject) this.i2p_proxy_ois.readObject(), "proxy");
                checkSipMessage(invite, true); //έλεγχος με την hmac proxy-proxy
                if (!invite.getType().equals(Sip.INVITE)) {
                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                }

                //στέλνουμε INVITE στον Client. Δε μπορούμε στο άκυρο απλώς να στείλουμε INVITE (το INVITE o client δε το περιμένει σε συγκεκριμένη στιγμή, πχ αν πατηθεί κάποιο
                //κουμπί ή οτιδήποτε), στην ουσία πρέπει να ανοιχτεί ένα νέο ServerStream από τη μεριά του και να συνδεθεί ο proxy με άλλα streams και sockets
                //σε άλλο thread το υλοποιεί ο client
                Socket client = new Socket();
                //2 λεπτά timeout (120000 milliseconds -> 2 mins)
                client.connect(new InetSocketAddress("localhost", 8002), 120000); //8001: η πύλη που περιμένει ο Client1 (Alice) ενώ 8002: η πύλη που περιμένει ο Bob
                ObjectOutputStream client_oos = new ObjectOutputStream(client.getOutputStream());
                ObjectInputStream client_ois = new ObjectInputStream(client.getInputStream());

                //δεχόμαστε το i2p destination string του client
                Message client_dest_msg = (Message) decrypt((SealedObject) client_ois.readObject(), "client");
                this.i2p_string_client = client_dest_msg.getMessage();
                this.i2pclient_to_client = new I2PClient(this.i2p_string_client);

                //σύνδεση μέσω I2P
                this.i2pclient_to_client.accept();
                //παραγωγή των i2p streams
                this.i2p_client_active_oos = this.i2pclient_to_client.getI2POutputStream();
                this.i2p_client_active_ois = this.i2pclient_to_client.getI2PInputStream();

                //πρώτα στέλνουμε το mode
                this.i2p_client_active_oos.writeObject(encrypt("true", "client"));
                this.i2p_client_active_oos.flush();

                //λέμε στον Client ότι τον καλεί κάποιος
                this.i2p_client_active_oos.writeObject(encryptSip(new SIPMessage(Sip.INVITE, "<sips:alice@proxyA.com>", "<sips:bob@proxyB.com>", this.token, this.HMAC_Sign("<sips:alice@proxyA.com>" + this.token)), "client"));
                this.i2p_client_active_oos.flush();

                //στέλνουμε TRYING στον Proxy
                this.i2p_proxy_oos.writeObject(encryptSip(new SIPMessage(Sip.TRYING, "<sips:proxyB@proxyB.com>", "<sips:proxyA@proxyA.com>", this.token_prx, this.HMAC_SignProxy("<sips:proxyB@proxyB.com>" + this.token_prx)), "proxy"));
                this.i2p_proxy_oos.flush();

                //αναμένουμε RINGING από τον client
                SIPMessage ringing = (SIPMessage) decrypt((SealedObject) this.i2p_client_active_ois.readObject(), "client");
                checkSipMessage(ringing, false); //έλεγχος με την hmac proxy-client
                if (!ringing.getType().equals(Sip.RINGING)) {
                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                }

                //στέλνουμε RINGING στον Proxy
                this.i2p_proxy_oos.writeObject(encryptSip(new SIPMessage(Sip.RINGING, "<sips:proxyB@proxyB.com>", "<sips:proxyA@proxyA.com>", this.token_prx, this.HMAC_SignProxy("<sips:proxyB@proxyB.com>" + this.token_prx)), "proxy"));
                this.i2p_proxy_oos.flush();

                //αναμένουμε OK ή UNAUTHORIZED από τον client 
                boolean ok = false;
                SIPMessage ok_or_unauthorized = (SIPMessage) decrypt((SealedObject) this.i2p_client_active_ois.readObject(), "client");
                checkSipMessage(ok_or_unauthorized, false); //έλεγχος με την hmac proxy-client
                if (ok_or_unauthorized.getType().equals(Sip.OK)) {
                    ok = true;
                } else if (ok_or_unauthorized.getType().equals(Sip.UNAUTHORIZED)) {
                    ok = false;
                } else {
                    throw new UnknownProtocolCommandException("SIP Message type is not valid");
                }

                //στέλνουμε OK ή UNAUTHORIZED στον proxy
                if (ok) {
                    this.i2p_proxy_oos.writeObject(encryptSip(new SIPMessage(Sip.OK, "<sips:proxyB@proxyB.com>", "<sips:proxyA@proxyA.com>", this.token_prx, this.HMAC_SignProxy("<sips:proxyB@proxyB.com>" + this.token_prx)), "proxy"));
                    this.i2p_proxy_oos.flush();
                    //αν έστειλε ΟΚ ο client, τότε δεχόμαστε τo I2P Destination String του και το πρωοθούμε στον άλλον proxy
                    Message client_dest = (Message) decrypt((SealedObject) this.i2p_client_active_ois.readObject(), "client");

                    //προώθηση στον 2ο proxy
                    this.i2p_proxy_oos.writeObject(encrypt(client_dest.getMessage(), "proxy"));
                    this.i2p_proxy_oos.flush();

                } else {
                    this.i2p_proxy_oos.writeObject(encryptSip(new SIPMessage(Sip.UNAUTHORIZED, "<sips:proxyB@proxyB.com>", "<sips:proxyA@proxyA.com>", this.token_prx, this.HMAC_SignProxy("<sips:proxyB@proxyB.com>" + this.token_prx)), "proxy"));
                    this.i2p_proxy_oos.flush();
                }
                //εδώ τελείωσε το πρωτόκολλο SIP!!
                System.out.println("END!");
            } catch (ConnectionNotSafeException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IOException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnknownProtocolCommandException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    //ένας PROXY δρα ως CLIENT (στέλνει πρώτος στον άλλον proxy -αν πατήσει CALL o client) και ως SERVER (περιμένει τον CLIENT ή και τον άλλον proxy)
    protected void whileConnected(String mode, String receiver, String keyname, ObjectOutputStream outputstream, ObjectInputStream inputstream, boolean first, boolean register_login) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        this.mode = mode;
        try {
            if (mode.equals("RSA")) {
                if (first == false) {
                    try {
                        //διαβασμα του "startsession"
                        if (!inputstream.readUTF().equals("StartSession")) {
                            throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                        }
                        //στελνουμε "ΟΚ"
                        outputstream.writeUTF("OK");
                        outputstream.flush();
                        //ελέγχουμε αν υπάρχει ήδη το συμμετρικό κλειδί. Αν ναι τότε δε χρειάζεται να παραχθεί ξανά το κλειδί
                        if (!new File(keyname).exists()) {
                            //λαμβάνουμε το certificate
                            X509Certificate cer_received = (X509Certificate) inputstream.readObject();

                            //Στέλνουμε ACK οτι το λάβαμε
                            outputstream.writeUTF("CertReceived");
                            outputstream.flush();
                            //Validate το certificate
                            if (!this.checkReceivedCertificate(cer_received)) {
                                throw new ConnectionNotSafeException("The certificate can't be verified!\n");
                            }
                            //extract public key από το certificate
                            received_pubkey = cer_received.getPublicKey();

                            //διάβασμα από το αρχείο
                            FileInputStream fis = new FileInputStream(new File("certificates/proxy2signed.cer"));
                            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
                            outputstream.writeObject(cert); //εδώ στέλνουμε το certificate
                            outputstream.flush();
                            //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
                            if (!inputstream.readUTF().equals("CertReceived")) {
                                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                            }
                            Cipher cipher = Cipher.getInstance("RSA", "BC");
                            cipher.init(Cipher.ENCRYPT_MODE, received_pubkey);
                            //παράγουμε το συμμετρικό AES key
                            if (receiver.equals("client")) {
                                this.symmetricKey = this.getAESkey();
                                //save το κλειδί ώστε να υπάρχει
                                try (OutputStream stream = new FileOutputStream("keys\\skey_client.key")) {
                                    stream.write(this.symmetricKey.getEncoded());
                                }
                                //encrypt το AES key (με το public του client) και στέλνουμε το encrypted AES KEY
                                outputstream.writeObject(new SealedObject(this.symmetricKey, cipher));
                                outputstream.writeObject(new SealedObject(javax.xml.bind.DatatypeConverter.
                                        printBase64Binary(this.iv.getIV()), cipher));
                            } else {
                                this.symmetricKey_prx = this.getAESkey();
                                try (OutputStream stream = new FileOutputStream("keys\\skey_proxy.key")) {
                                    stream.write(this.symmetricKey_prx.getEncoded());
                                }
                                outputstream.writeObject(new SealedObject(this.symmetricKey_prx, cipher));
                                outputstream.writeObject(new SealedObject(javax.xml.bind.DatatypeConverter.
                                        printBase64Binary(this.iv.getIV()), cipher));
                            }

                        } //αλλιώς αν υπάρχει τότε απλώς το παίρνουμε
                        else {
                            if (receiver.equals("client")) {
                                this.symmetricKey = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_client.key")), "AES");
                            } else {
                                this.symmetricKey_prx = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_proxy.key")), "AES");
                            }

                        }

                        //initialize το hmac
                        if (receiver.equals("client")) {
                            this.initializeHMACs(false);
                        } else {
                            this.initializeHMACs(true);
                        }

                    } catch (IOException ioe) {
                        System.err.println("The other client has left");
                        this.closeConnection();
                    } catch (ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchProviderException ex) {
                        System.err.println("Encryption error");
                        this.closeConnection();
                    } catch (UnknownProtocolCommandException ex) {
                        System.err.println("Unknown command\nExiting session...");
                    } catch (ConnectionNotSafeException cnse) {
                        System.err.println("Your connection is not secure!\nExiting session...");
                        this.closeConnection();
                    } catch (CertificateException ex) {
                        System.err.println("Not a certificate");
                        this.closeConnection();
                    }

                    //εδώ είναι η περίπτωση που ο proxy ξεκινάει πρώτος την ενθυλάκωση
                } else {
                    try {
                        //ξεκινάμε πρώτοι ως client και στέλνουμε StartSession για να ξεκινήσει η διαδικασία
                        outputstream.writeUTF("StartSession");
                        outputstream.flush();

                        //αν δεν μας απαντήσει ο "server" με ΟΚ τότε σφάλμα
                        if (!inputstream.readUTF().equals("OK")) {
                            throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                        }

                        if (!new File("keys\\skey_proxy.key").exists()) {
                            //Στέλνουμε το certificate μας
                            FileInputStream fis = new FileInputStream(new File("certificates/proxy2signed.cer"));
                            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
                            outputstream.writeObject(cert); //στέλνουμε το certificate μας
                            outputstream.flush();

                            //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
                            if (!inputstream.readUTF().equals("CertReceived")) {
                                System.err.println("Protocol error\nExiting session...");
                                throw new UnknownProtocolCommandException("Unknown command...");
                            }

                            //λαμβάνουμε certificate 
                            X509Certificate cer_received = (X509Certificate) inputstream.readObject();
                            outputstream.writeUTF("CertReceived");
                            outputstream.flush();

                            //Validate το certificate
                            if (!checkReceivedCertificate(cer_received)) {
                                throw new ConnectionNotSafeException("The certificate can't be verified!");
                            }

                            //λαμβάνουμε το συμμετρικό κλειδί 
                            SealedObject sobj_aes = (SealedObject) inputstream.readObject();
                            //αρχικοποίηση του cipher για αποκρυπτογράφηση του συμμετρικού κλειδιού
                            Cipher cipher = Cipher.getInstance("RSA", "BC");
                            cipher.init(Cipher.DECRYPT_MODE, privkey);
                            //aes key
                            symmetricKey_prx = (SecretKey) sobj_aes.getObject(cipher);
                            //save το κλειδί ώστε να υπάρχει 
                            try (OutputStream stream = new FileOutputStream("keys\\skey_proxy.key")) {
                                stream.write(this.symmetricKey_prx.getEncoded());
                            }
                        } //αλλιώς αν υπάρχει τότε απλώς το παίρνουμε
                        else {
                            if (receiver.equals("client")) {
                                this.symmetricKey = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_client.key")), "AES");
                            } else {
                                this.symmetricKey_prx = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_proxy.key")), "AES");
                            }
                        }
                        //initialize το hmac
                        if (receiver.equals("client")) {
                            this.initializeHMACs(false);
                        } else {
                            this.initializeHMACs(true);
                        }

                    } catch (IOException ex) {
                        Logger.getLogger(BobProxyEncryptedConnection.class
                                .getName()).log(Level.SEVERE, null, ex);

                    } catch (UnknownProtocolCommandException ex) {
                        Logger.getLogger(BobProxyEncryptedConnection.class
                                .getName()).log(Level.SEVERE, null, ex);

                    } catch (ClassNotFoundException ex) {
                        Logger.getLogger(BobProxyEncryptedConnection.class
                                .getName()).log(Level.SEVERE, null, ex);

                    } catch (CertificateException ex) {
                        Logger.getLogger(BobProxyEncryptedConnection.class
                                .getName()).log(Level.SEVERE, null, ex);

                    } catch (ConnectionNotSafeException ex) {
                        Logger.getLogger(BobProxyEncryptedConnection.class
                                .getName()).log(Level.SEVERE, null, ex);

                    } catch (NoSuchAlgorithmException ex) {
                        Logger.getLogger(BobProxyEncryptedConnection.class
                                .getName()).log(Level.SEVERE, null, ex);

                    } catch (NoSuchPaddingException ex) {
                        Logger.getLogger(BobProxyEncryptedConnection.class
                                .getName()).log(Level.SEVERE, null, ex);
                    }
                }
            } else if (mode.equals("STS")) {
                //"server mode", πρώτα στέλνει ο άλλος proxy (ή client)
                if (first == false) {
                    try {
                        //λαμβάνουμε πρώτα StartSession Και στέλνουμε ΟΚ
                        if (!inputstream.readUTF().equals("StartSession")) {
                            throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                        }
                        //στέλνουμε "ΟΚ"
                        outputstream.writeUTF("OK");
                        outputstream.flush();

                        //ελέγχουμε αν υπάρχει ήδη το συμμετρικό κλειδί. Αν ναι τότε δε χρειάζεται να παραχθεί ξανά το κλειδί
                        if (!new File(keyname).exists()) {
                            if (receiver.equals("client")) {
                                //λαμβάνουμε p,g 
                                this.p = (BigInteger) inputstream.readObject();
                                this.g = (BigInteger) inputstream.readObject();
                                //με βάση τα p,g παράγουμε τα DH public/private key μας
                                generateParameters(true, false); //true, false -> λαμβανουμε απο client
                            } else {
                                //λαμβάνουμε p,g 
                                this.p2 = (BigInteger) inputstream.readObject();
                                this.g2 = (BigInteger) inputstream.readObject();
                                //με βάση τα p,g παράγουμε τα DH public/private key μας
                                generateParameters(false, false); //false, false -> λαμβανουμε απο proxy
                            }
                            //στέλνουμε ack οτι τα πήραμε
                            outputstream.writeUTF("ParametersReceived");
                            outputstream.flush();

                            //μας στέλνει το Certificate οπότε εμείς το ελέγχουμε, δηλαδή αν έχει υπογραφτεί με την CA
                            //από το truststore μας
                            X509Certificate cer_received = (X509Certificate) inputstream.readObject();

                            outputstream.writeUTF("CertificateReceived");
                            outputstream.flush();

                            //Validate το certificate
                            if (!this.checkReceivedCertificate(cer_received)) {
                                throw new ConnectionNotSafeException("The certificate can't be verified!");
                            }

                            //Στέλνουμε το certificate μας
                            FileInputStream fis = new FileInputStream(new File("certificates/proxy2signed.cer"));
                            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
                            outputstream.writeObject(cert);
                            outputstream.flush();

                            //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
                            if (!inputstream.readUTF().equals("CertificateReceived")) {
                                System.err.println("Protocol error\nExiting session...");
                            }

                            //λαμβάνουμε το public dh key (Δηλαδή το g^x)
                            received_dh_pubkey = (PublicKey) inputstream.readObject();
                            //στέλνουμε ack ότι το πήραμε
                            outputstream.writeUTF("PublicDHKeyReceived");

                            //στέλνουμε το g^y μας. το g^y είναι το public dh key (server)
                            if (receiver.equals("client")) {
                                outputstream.writeObject(keypair_dh.getPublic());
                            } else {
                                outputstream.writeObject(keypair_dh2.getPublic());
                            }
                            outputstream.flush();
                            //αν δεν μας απαντήσει ο client με PublicDHKeyReceived τότε σφάλμα
                            if (!inputstream.readUTF().equals("PublicDHKeyReceived")) {
                                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                            }

                            /* 3: encrypted μήνυμα */
                            //τώρα παράγουμε το shared κλειδί. Αυτό το κλειδί θα πρέπει να είναι ίδιο με αυτό που παρήγαγε ο server
                            //ώστε να μας στείλει το encrypted και signed g^y, g^x. εμείς δεν κάνουμε τη λειτουργία (g^x)^y (client) ή (g^y)^x (server)
                            //αυτό γίνεται αυτόματα από το keyagree
                            if (receiver.equals("client")) {
                                keyagree.init(keypair_dh.getPrivate());
                            } else {
                                keyagree.init(keypair_dh2.getPrivate());
                            }
                            keyagree.doPhase(received_dh_pubkey, true);
                            Cipher cipher;
                            if (receiver.equals("client")) {
                                this.symmetricKey = keyagree.generateSecret("AES");
                                //αρχικοποίηση του cipher Με AES
                                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
                            } else {
                                this.symmetricKey_prx = keyagree.generateSecret("AES");
                                //αρχικοποίηση του cipher Με AES
                                cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                                cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey_prx, this.iv);
                            }
                            //αρχικοποίηση του signature
                            sig = Signature.getInstance("SHA256withRSA", "BC");
                            // στέλνουμε το signed ciphertext κρυπτογραφημένο μέσω του συμμετρικού κλειδιού
                            sig.initSign(this.privkey);
                            sig.update(this.keypair_dh.getPublic().getEncoded());
                            sig.update(this.received_dh_pubkey.getEncoded());
                            outputstream.writeObject(new SealedObject(javax.xml.bind.DatatypeConverter.printBase64Binary(sig.sign()), cipher));
                            outputstream.flush();
                            //αν δε το έλαβε, σφάλμα
                            if (!inputstream.readUTF().equals("SignedCiphertextReceived")) {
                                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                            }
                            if (receiver.equals("client")) {
                                cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);
                            } else {
                                cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey_prx, this.iv);
                            }
                            //τώρα λαμβάνουμε το signed ciphertext
                            SealedObject sobj = (SealedObject) inputstream.readObject();
                            //στέλνουμε ack ότι το λάβαμε
                            outputstream.writeUTF("SignedCiphertextReceived");
                            outputstream.flush();
                            //πρέπει να το κάνουμε verify
                            byte[] signed_ciphertext = javax.xml.bind.DatatypeConverter.parseBase64Binary((String) sobj.getObject(cipher));
                            //στη συνέχεια θα αποκρυπτογραφήσουμε με το συμμετρικό κλειδί την υπογραφή του server
                            sig = Signature.getInstance("SHA256withRSA", "BC");
                            sig.initVerify(cer_received);
                            sig.update(this.received_dh_pubkey.getEncoded());
                            sig.update(this.keypair_dh.getPublic().getEncoded());
                            if (!sig.verify(signed_ciphertext)) {
                                throw new ConnectionNotSafeException("Your connection is not secure!");
                            }
                            //save το κλειδί ώστε να υπάρχει 
                            if (receiver.equals("client")) {
                                try (OutputStream stream = new FileOutputStream("keys\\skey_client.key")) {
                                    stream.write(this.symmetricKey.getEncoded());
                                }
                            } else {
                                try (OutputStream stream = new FileOutputStream("keys\\skey_proxy.key")) {
                                    stream.write(this.symmetricKey_prx.getEncoded());
                                }

                            }
                        }//αλλιώς αν υπάρχει τότε απλώς το παίρνουμε
                        else {
                            if (receiver.equals("client")) {
                                this.symmetricKey = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_client.key")), "AES");
                            } else {
                                this.symmetricKey_prx = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_proxy.key")), "AES");
                            }

                        }

                        //initialize το hmac
                        if (receiver.equals("client")) {
                            this.initializeHMACs(false);
                        } else {
                            this.initializeHMACs(true);
                        }

                    } catch (UnknownProtocolCommandException ex) {
                        System.err.println("Unknown command\nExiting session...");
                        this.closeConnection();
                    } catch (IOException ioe) {
                        System.err.println("The other client has left");
                        this.closeConnection();
                    } catch (ClassNotFoundException | CertificateException | InvalidKeyException | IllegalStateException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchProviderException | SignatureException | IllegalBlockSizeException | BadPaddingException ex) {
                        System.err.println("Encryption error");
                        this.closeConnection();
                    } catch (ConnectionNotSafeException ex) {
                        System.err.println("Your connection is not secure!\nExiting session...");
                        this.closeConnection();
                    }

                    //εδώ είναι η περίπτωση που ο proxy ξεκινάει πρώτος το STS PROTOCOL
                } else {
                    try {
                        //ξεκινάμε πρώτοι ως client και στέλνουμε StartSession για να ξεκινήσει η διαδικασία
                        outputstream.writeUTF("StartSession");
                        outputstream.flush();

                        //αν δεν μας απαντήσει ο "server" με ΟΚ τότε σφάλμα
                        if (!inputstream.readUTF().equals("OK")) {
                            throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                        }

                        if (!new File("keys\\skey_proxy.key").exists()) {
                            //στη συνέχεια στέλνουμε τα p,g και IV στον "server"
                            outputstream.writeObject(p2);
                            outputstream.writeObject(g2);

                            outputstream.flush();
                            //αν δεν μας απαντήσει ο "server" με ParametersReceived τότε σφάλμα
                            if (!inputstream.readUTF().equals("ParametersReceived")) {
                                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                            }

                            //Στέλνουμε το certificate μας
                            FileInputStream fis = new FileInputStream(new File("certificates/proxy2signed.cer"));
                            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
                            outputstream.writeObject(cert);
                            outputstream.flush();

                            //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
                            if (!inputstream.readUTF().equals("CertificateReceived")) {
                                System.err.println("Protocol error\nExiting session...");
                                throw new UnknownProtocolCommandException("Unknown Command...");
                            }

                            //μας στέλνει το Certificate οπότε εμείς το ελέγχουμε, δηλαδή αν έχει υπογραφτεί με την CA
                            //από το truststore μας
                            X509Certificate cer_received = (X509Certificate) inputstream.readObject();

                            // στέλνουμε ACK ότι το πήραμε
                            outputstream.writeUTF("CertificateReceived");
                            outputstream.flush();

                            //Validate το certificate
                            if (!checkReceivedCertificate(cer_received)) {
                                throw new ConnectionNotSafeException("The certificate can't be verified!");
                            }

                            //στέλνουμε το g^x μας. το g^x είναι το public dh key (client)
                            outputstream.writeObject(keypair_dh.getPublic());
                            outputstream.flush();
                            //αν δεν μας απαντήσει ο "server" με PublicDHKeyReceived τότε σφάλμα
                            if (!inputstream.readUTF().equals("PublicDHKeyReceived")) {
                                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                            }

                            /* 2: public DH key (g^y) */
                            //λαμβάνουμε το public dh key (Δηλαδή το g^y)
                            received_dh_pubkey = (PublicKey) inputstream.readObject();
                            //στέλνουμε ack ότι το πήραμε
                            outputstream.writeUTF("PublicDHKeyReceived");
                            outputstream.flush();

                            /* 3: encrypted μήνυμα */
                            //τώρα παράγουμε το shared κλειδί. Αυτό το κλειδί θα πρέπει να είναι ίδιο με αυτό που παρήγαγε ο server
                            //ώστε να μας στείλει το encrypted και signed g^y, g^x. εμείς δεν κάνουμε τη λειτουργία (g^x)^y (client) ή (g^y)^x (server)
                            //αυτό γίνεται αυτόματα από το keyagree
                            keyagree.init(keypair_dh.getPrivate());
                            keyagree.doPhase(received_dh_pubkey, true);
                            symmetricKey_prx = keyagree.generateSecret("AES");

                            //αρχικοποίηση του cipher Με AES
                            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                            cipher.init(Cipher.DECRYPT_MODE, symmetricKey_prx, this.iv);

                            //λαμβάνουμε το signed ciphertext
                            SealedObject sobj = (SealedObject) inputstream.readObject();
                            //στέλνουμε ack ότι το λάβαμε
                            outputstream.writeUTF("SignedCiphertextReceived");
                            outputstream.flush();
                            byte[] signed_ciphertext = javax.xml.bind.DatatypeConverter.parseBase64Binary((String) sobj.getObject(cipher));
                            //στη συνέχεια θα αποκρυπτογραφήσουμε με το συμμετρικό κλειδί την υπογραφή του server
                            sig = Signature.getInstance("SHA256withRSA", "BC");
                            sig.initVerify(cer_received);
                            sig.update(this.received_dh_pubkey.getEncoded());
                            sig.update(this.keypair_dh.getPublic().getEncoded());
                            if (!sig.verify(signed_ciphertext)) {
                                throw new ConnectionNotSafeException("Your connection is not secure!");
                            }
                            cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
                            // στέλνουμε το signed ciphertext κρυπτογραφημένο μέσω του συμμετρικού κλειδιού
                            sig.initSign(this.privkey);
                            sig.update(this.keypair_dh.getPublic().getEncoded());
                            sig.update(this.received_dh_pubkey.getEncoded());
                            outputstream.writeObject(new SealedObject(javax.xml.bind.DatatypeConverter.printBase64Binary(sig.sign()), cipher));
                            outputstream.flush();
                            //αν δε το έλαβε, σφάλμα
                            if (!inputstream.readUTF().equals("SignedCiphertextReceived")) {
                                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
                            }

                            //save το κλειδί ώστε να υπάρχει 
                            if (receiver.equals("client")) {
                                try (OutputStream stream = new FileOutputStream("keys\\skey_client.key")) {
                                    stream.write(this.symmetricKey_prx.getEncoded());
                                }
                            } else {
                                try (OutputStream stream = new FileOutputStream("keys\\skey_proxy.key")) {
                                    stream.write(this.symmetricKey_prx.getEncoded());
                                }
                            }

                        } //αλλιώς αν υπάρχει τότε απλώς το παίρνουμε
                        else {
                            if (receiver.equals("client")) {
                                this.symmetricKey = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_client.key")), "AES");
                            } else {
                                this.symmetricKey_prx = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_proxy.key")), "AES");
                            }
                        }
                        //initialize το hmac
                        if (receiver.equals("client")) {
                            this.initializeHMACs(false);
                        } else {
                            this.initializeHMACs(true);
                        }

                    } catch (UnknownProtocolCommandException ex) {
                        System.err.println("Unknown command\nExiting session...");
                        this.closeConnection();
                    } catch (IOException ioe) {
                        System.err.println("The other client has left");
                        this.closeConnection();
                    } catch (ClassNotFoundException | CertificateException | InvalidKeyException | IllegalStateException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchProviderException | SignatureException | IllegalBlockSizeException | BadPaddingException ex) {
                        System.err.println("Encryption error");
                        this.closeConnection();
                    } catch (ConnectionNotSafeException ex) {
                        System.err.println("Your connection is not secure!\nExiting session...");
                        this.closeConnection();
                    }
                }
            }

            if (!first) {
                //παραγωγή του random token
                if (receiver.equals("client")) {
                    token = new TokenGenerator().generateToken();
                    //κρυπτογράφηση με AES και το στέλνουμε στο stream. Στην ουσία ο αλγόριθμος έχει τελειώσει αφού
                    //έχει παραχθεί το συμμετρικό κλειδί και στάλθηκε το πρώτο μήνυμα κρυπτογραφημένο με αυτό (το token)
                    outputstream.writeObject(encrypt(token, "client"));
                    outputstream.flush();
                } else {
                    token_prx = new TokenGenerator().generateToken();
                    //κρυπτογράφηση με AES και το στέλνουμε στο stream. Στην ουσία ο αλγόριθμος έχει τελειώσει αφού
                    //έχει παραχθεί το συμμετρικό κλειδί και στάλθηκε το πρώτο μήνυμα κρυπτογραφημένο με αυτό (το token)
                    outputstream.writeObject(encrypt(token_prx, "proxy"));
                    outputstream.flush();
                }

            } else {
                //παιρνουμε το session token (αποκρυπτογράφηση με το AES key τώρα)
                Message msg;
                if (receiver.equals("client")) {
                    msg = (Message) decrypt((SealedObject) inputstream.readObject(), "client");
                    token = msg.getToken();
                } else {
                    msg = (Message) decrypt((SealedObject) inputstream.readObject(), "proxy");
                    token_prx = msg.getToken();
                }
            }
            //στην ουσία εδώ έχει τελειώσει το key agreement

            //εδώ γίνεται η σύνδεση I2P και οι ανταλλαγές των session tokens
            //πρώτα μεταξύ client-proxy
            if (receiver.equals("client")) {

                //δημιουργία των I2PServer (δημιουργούμε και τον i2pserver για τον άλλον Proxy εδώ ώστε να δημιουργηθεί και αυτός
                i2pserver_to_client = new I2PServer();
                i2pserver_to_proxy = new I2PServer();

                //πρώτα στέλνουμε το i2p destination string στον clinet
                outputstream.writeObject(encrypt(i2pserver_to_client.getDestinationString(), "client")); //στέλνουμε destination string στον Client
                outputstream.flush();

                //περιμένουμε να συνδεθεί ο client
                i2pserver_to_client.accept();
                //παίρνουμε τα streams (i2p)
                this.i2p_client_oos = i2pserver_to_client.getI2POutputStream();
                this.i2p_client_ois = i2pserver_to_client.getI2PInputStream();
                //proxy-proxy
            } else {
                //στέλνουμε πρώτα και μετά λαμβάνουμε το Destination string του proxy. Στη συνέχεια περιμένουμε να συνδεθεί σε εμάς ο proxy
                if (first) {
                    outputstream.writeObject(encrypt(i2pserver_to_proxy.getDestinationString(), "proxy")); //στέλνουμε destination string στον proxy
                    outputstream.flush();
                    Message proxy_string_msg = (Message) decrypt((SealedObject) inputstream.readObject(), "proxy");
                    this.i2p_string_proxy = proxy_string_msg.getMessage();

                    i2pserver_to_proxy.accept();
                    //παίρνουμε τα streams (i2p)
                    this.i2p_proxy_oos = i2pserver_to_proxy.getI2POutputStream();
                    this.i2p_proxy_ois = i2pserver_to_proxy.getI2PInputStream();

                    //το ακριβώς ανάποδο (λαμβάνουμε και μετά στέλνουμε. Στη συνέχεια συνδεόμαστε στον άλλον proxy)
                } else {
                    Message proxy_string_msg = (Message) decrypt((SealedObject) inputstream.readObject(), "proxy");
                    this.i2p_string_proxy = proxy_string_msg.getMessage();
                    outputstream.writeObject(encrypt(i2pserver_to_proxy.getDestinationString(), "proxy")); //στέλνουμε destination string στον proxy
                    outputstream.flush();
                    this.i2pclient_to_proxy = new I2PClient(this.i2p_string_proxy);

                    i2pclient_to_proxy.accept();
                    //παίρνουμε τα streams (i2p)
                    this.i2p_proxy_ois = i2pclient_to_proxy.getI2PInputStream();
                    this.i2p_proxy_oos = i2pclient_to_proxy.getI2POutputStream();
                }
            }

            //έλεγχος των στοιχείων που στάλθηκαν για login ή register
            //πρώτα στέλνεται "LOGIN" ή "REGISTER" μήνυμα
            if (register_login) {
                registerOrLogin();
            }

        } catch (IOException ex) {
            System.err.println("Client Disconnected!");
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    //μέθοδος για encrypt ενός μηνύματος
    protected SealedObject encrypt(String msg, String mode) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            if (mode.equals("client")) {
                cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
                Message message = new Message(msg, token, this.HMAC_Sign(msg + this.token));
                return new SealedObject(message, cipher);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey_prx, this.iv);
                Message message = new Message(msg, token_prx, this.HMAC_SignProxy(msg + this.token_prx));
                return new SealedObject(message, cipher);
            }

        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException ex) {
            System.err.println("Encryption error");
            this.closeConnection();
        } catch (IOException ioe) {
            System.err.println("Could not send the message");
            this.closeConnection();
        }
        return null;
    }

    //μέθοδος για encrypt ενός SIP Message
    protected SealedObject encryptSip(SIPMessage msg, String mode) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            if (mode.equals("client")) {
                cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
            } else {
                cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey_prx, this.iv);
            }
            return new SealedObject(msg, cipher);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException ex) {
            System.err.println("Encryption error");
            this.closeConnection();
            System.exit(-1);
        } catch (IOException ioe) {
            System.err.println("Could not send the message");
            this.closeConnection();
            System.exit(-1);
        }
        return null;
    }

    //μέθοδος για decrypt (ανάλογα το mode -> symmetric key μεταξυ client-proxy ή proxy-proxy
    protected Object decrypt(SealedObject sobj, String mode) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            if (mode.equals("client")) {
                cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey_prx, this.iv);
            }
            return sobj.getObject(cipher);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException ex) {
            System.err.println("Decryption error");
            this.closeConnection();
        } catch (IOException ioe) {
            System.err.println("Could not decrypt the message");
            this.closeConnection();
        }
        return null;
    }

    //sign με HMAC (client-proxy)
    protected String HMAC_Sign(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data.getBytes()));
    }

    //sign με HMAC (proxy-proxy)
    protected String HMAC_SignProxy(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac_prx.doFinal(data.getBytes()));
    }

    //κλείνει τη σύνδεση
    protected void closeConnection() {
        try {
            if (this.outputstream != null && this.inputstream != null) {
                outputstream.close();
                inputstream.close();
            }
            connection.close();
        } catch (IOException ex) {
            System.err.println("Error while closing session....");
        }
    }

    //Μέθοδος που checkάρει αν το  certificate που στέλνεται έχει γίνει sign από την ca
    //Δηλαδή ελέγχουμε το truststore μας (που εμπεριέχει το certificate, και άρα το public key της CA)
    //έχει όντως κάνει sign το certificate που μας δίνεται
    protected boolean checkReceivedCertificate(X509Certificate cer) {
        try {
            //διάβασμα του certificate του CA από το truststore
            X509Certificate ca_cer = (X509Certificate) truststore.getCertificate("CAcer");
            //ελέγχουμε αν το certificate που δίνεται έχει υπογραφτεί από τον CA
            cer.verify(ca_cer.getPublicKey());
            return true;

        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class
                    .getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException | CertificateException ex) {
            System.err.println("Could not verify the certificate! Possibly dangerous condition\nExiting session...");
            closeConnection();
            Logger.getLogger(BobProxyEncryptedConnection.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    //μέθοδος που διαβάζει το keystore file
    protected void loadKeyStore(String key_store, char[] password, String type) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        File keystoreFile = new File(key_store);
        if (keystoreFile == null) {
            throw new IllegalArgumentException("No keystore found");
        }
        final URL keystoreUrl = keystoreFile.toURI().toURL();
        if (type.equals("keystore")) {
            keystore = KeyStore.getInstance("JKS"); //με keytool το φτιάξαμε σε JKS format
            InputStream is = null;
            try {
                is = keystoreUrl.openStream();
                keystore.load(is, password);
            } finally {
                if (null != is) {
                    is.close();
                }
            }
        } else if (type.equals("truststore")) {
            truststore = KeyStore.getInstance("JKS"); //με keytool το φτιάξαμε σε JKS format
            InputStream is = null;
            try {
                is = keystoreUrl.openStream();
                truststore.load(is, password);
            } finally {
                if (null != is) {
                    is.close();
                }
            }
        }
    }

    //hash με sha-256, επιστρέφει τη hex μορφή των bytes
    protected String SHA256_Hash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            //μετατροπή σε hex
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashed.length; i++) {
                sb.append(Integer.toString((hashed[i] & 0xff) + 0x100, 16).substring(1));
            }
            return sb.toString();

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    //παραγωγή της HMAC (val==false? τοτε παραγωγη hmac για client, αλλιως παραγωγη για proxy)
    protected void initializeHMACs(boolean val) {
        try {
            if (val == false) {
                mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(this.symmetricKey.getEncoded(), "HMACSHA256"));
            } else {
                mac_prx = Mac.getInstance("HmacSHA256");
                mac_prx.init(new SecretKeySpec(this.symmetricKey_prx.getEncoded(), "HMACSHA256"));

            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class
                    .getName()).log(Level.SEVERE, null, ex);

        } catch (InvalidKeyException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
    }

    //μέθοδος που ελέγχει το HMAC αλλά και το token (mode=0: client-proxy, mode=1: proxy-proxy)
    private void checkMessage(Message msg_received, boolean mode) throws ConnectionNotSafeException {
        String hmac_check = msg_received.getHMAC();
        //έλεγχος του hmac του μηνύματος
        if (mode == false) {
            if (!hmac_check.equals(this.HMAC_Sign(msg_received.toString()))) {
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        } else {
            if (!hmac_check.equals(this.HMAC_SignProxy(msg_received.toString()))) {
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        }

        //έλεγχος αν το token είναι σωστό! Ο έλεγχος γίνεται ως εξής:
        //αν HASH(ΜΗΝΥΜΑ_ΠΟΥ_ΣΤΑΛΘΗΚΕ+TOKEN_ΜΗΝΥΜΑΤΟΣ) = HASH(ΜΗΝΥΜΑ_ΠΟΥ_ΣΤΑΛΘΗΚΕ+TOKEN_ΔΙΚΟ_ΜΑΣ) τοτε
        //ειμαστε οκ, διοτι αυτό σημαίνει πως το TOKEN Δεν άλλαξε
        String hash = SHA256_Hash(msg_received.toString());
        if (mode == false) {
            if (!hash.equals(SHA256_Hash(msg_received.getMessage() + token))) {
                //άλλαξε το token = replay attack!
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        } else {
            if (!hash.equals(SHA256_Hash(msg_received.getMessage() + token_prx))) {
                //άλλαξε το token = replay attack!
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        }
    }

    //το ίδιο αλλά για ένα SIP μήνυμα
    protected void checkSipMessage(SIPMessage msg_received, boolean mode) throws ConnectionNotSafeException {
        String hmac_check = msg_received.getHMAC();
        if (mode == false) {
            if (!hmac_check.equals(this.HMAC_Sign(msg_received.getFrom() + token))) {
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        } else {
            System.out.println(msg_received.getFrom() + token_prx);
            if (!hmac_check.equals(this.HMAC_SignProxy(msg_received.getFrom() + token_prx))) {
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        }
        String hash = SHA256_Hash(msg_received.getFrom() + msg_received.getToken());
        if (mode == false) {
            if (!hash.equals(SHA256_Hash(msg_received.getFrom() + token))) {
                //άλλαξε το token = replay attack!
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        } else {
            if (!hash.equals(SHA256_Hash(msg_received.getFrom() + token_prx))) {
                //άλλαξε το token = replay attack!
                throw new ConnectionNotSafeException("Your connection is not secure!");
            }
        }
    }
    //μέθοδος που διαχειρίζεται τα login/registers στην εφαρμογή

    protected void registerOrLogin() {
        try_register_login:
        while (true) {
            //πρώτα στέλνεται από τον client ένα LOGIN ή REGISTER
            try {
                Message msg_received = (Message) this.decrypt((SealedObject) this.i2p_client_ois.readObject(), "client");
                this.checkMessage(msg_received, false);
                //έλεγχος αν υπάρχει το αρχείο, αν δεν υπάρχει τότε δημιουργία
                boolean exists_file = true;
                if (!new File("users\\users.dat").exists()) {
                    exists_file = false;
                    new File("users\\users.dat").getParentFile().mkdirs();
                    new File("users\\users.dat").createNewFile();
                }
                //αν έστειλε "REGISTER"
                if (msg_received.getMessage().equals("REGISTER")) {
                    //extract τον user που μας έστειλε ο client ώστε να ελέγξουμε αν μπορεί να γίνει register
                    User to_register = (User) decrypt((SealedObject) this.i2p_client_ois.readObject(), "client");
                    //αν δεν υπήρχε το αρχείο προφανώς δεν υπάρχει κανένας χρήστης μέσα
                    boolean exists = false;
                    if (exists_file) {
                        //άνοιγμα του αρχείου και έλεγχος αν υπάρχει ήδη ο χρήστης, αν ναι τότε δε μπορεί να γίνει register
                        try {
                            ObjectInputStream ois = new ObjectInputStream(new FileInputStream("users\\users.dat"));
                            while (true) {
                                User usr = (User) ois.readObject();
                                if (usr.getUsername().equals(to_register.getUsername())) {
                                    exists = true;
                                    break;
                                }
                            }
                        } catch (EOFException ef) {
                        }
                    }
                    //αν υπάρχει ήδη, ειδοποίηση ότι δε μπορεί να γίνει το register
                    if (exists) {
                        this.i2p_client_oos.writeObject(encrypt("REGISTER_FAIL", "client"));
                        this.i2p_client_oos.flush();
                    } //αλλιώς γράψιμο (append) στο αρχείο και ειδοποίηση πως έγινε success
                    else {
                        //βάζουμε τον κωδικό του χρήστη μαζί με ένα salt και όλο αυτό Hashed με sha-256
                        byte[] salt = new byte[16];
                        new SecureRandom().nextBytes(salt);
                        String base64salt = javax.xml.bind.DatatypeConverter.printBase64Binary(salt); //salt σε string μορφή
                        to_register.setSalt(base64salt);
                        to_register.setHashedPassword(SHA256_Hash(to_register.getPassword() + base64salt));
                        //τροποποίηση ώστε να μην υπάρχει το plaintext στο αρχείο
                        to_register.clearPassword();
                        //append στο αρχείο
                        //αν το αρχείο δεν έχει καμία καταχώρηση (δηλαδή δεν υπήρχε πριν ξεκινήσει το πρόγραμμα μας)
                        //τότε πρέπει να χρησιμοποιήσουμε ObjectOutputStream, αλλιώς AppendableObjectOutputStream
                        if (exists_file) {
                            synchronized (this) {
                                try (ObjectOutputStream oos = new AppendableObjectOutputStream(new FileOutputStream("users\\users.dat", true))) {
                                    oos.writeObject(to_register);
                                    oos.flush();

                                } catch (FileNotFoundException ex) {
                                    Logger.getLogger(BobProxyEncryptedConnection.class
                                            .getName()).log(Level.SEVERE, null, ex);

                                } catch (EOFException ef) { //αν τελειώσει το αρχείο να μη γίνει τίποτα
                                } catch (IOException ex) {
                                    Logger.getLogger(BobProxyEncryptedConnection.class
                                            .getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                        } else {
                            synchronized (this) {
                                try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("users\\users.dat"))) {
                                    oos.writeObject(to_register);
                                    oos.flush();

                                } catch (FileNotFoundException ex) {
                                    Logger.getLogger(BobProxyEncryptedConnection.class
                                            .getName()).log(Level.SEVERE, null, ex);

                                } catch (EOFException ef) { //αν τελειώσει το αρχείο να μη γίνει τίποτα
                                } catch (IOException ex) {
                                    Logger.getLogger(BobProxyEncryptedConnection.class
                                            .getName()).log(Level.SEVERE, null, ex);
                                }
                            }
                        }
                        //αν όλα πάνε καλά τότε στέλνουμε REGISTER_OK και κάνουμε αυτόματα login τον χρήστη
                        this.i2p_client_oos.writeObject(encrypt("REGISTER_OK", "client"));
                        this.i2p_client_oos.flush();
                        logged_in = new User(to_register.getUsername(), to_register.getHashedPassword(), to_register.getToken(), to_register.getHMAC());
                        //όταν επιτύχει το LOGIN τότε ο proxy είναι διαθέσιμος, δηλαδή μπορεί ένας άλλος proxy να του στείλει πχ ενα INVITE μήνυμα
                        makeProxyAvailable();
                        keyExchangeProxies(mode); //προσπαθεί να κελέσει τον άλλον proxy όταν πατηθεί το CALL button
                        break try_register_login;
                    }
                    //αν σταλεί LOGIN μήνυμα
                } else if (msg_received.getMessage().equals("LOGIN")) {
                    boolean can_login = false;
                    //διάβασμα του user
                    User to_check = (User) decrypt((SealedObject) this.i2p_client_ois.readObject(), "client");

                    //αν το αρχείο δεν είναι κενό τότε διαβάζουμε έναν-έναν χρήστη μέχρι να βρεθεί το username και στη συνέχεια
                    //ελέγχουμε αν το sha256(password_που_δοθηκε + salt) = κωδικος στο αρχειο
                    try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream("users\\users.dat"))) {
                        while (true) {
                            User usr = (User) ois.readObject();
                            if (usr.getUsername().equals(to_check.getUsername())) {
                                //έλεγχος του κωδικού
                                if (usr.getHashedPassword().equals(SHA256_Hash(to_check.getPassword() + usr.getSalt()))) {
                                    //success
                                    can_login = true;
                                    this.i2p_client_oos.writeObject(encrypt("LOGIN_OK", "client"));
                                    this.i2p_client_oos.flush();
                                    logged_in = new User(usr.getUsername(), usr.getHashedPassword(), usr.getToken(), usr.getHMAC());
                                    //όταν επιτύχει το LOGIN τότε ο proxy είναι διαθέσιμος, δηλαδή μπορεί ένας άλλος proxy να του στείλει πχ ενα INVITE μήνυμα
                                    makeProxyAvailable();
                                    keyExchangeProxies(mode); //προσπαθεί να κελέσει τον άλλον proxy όταν πατηθεί το CALL button
                                    break try_register_login;
                                }
                            }
                        }
                    } catch (EOFException ef) {
                        //αν τελειώσει το αρχείο και δεν ειναι can_login=true τότε δε μπόρεσε να κάνει login
                        if (!can_login) {
                            this.i2p_client_oos.writeObject(encrypt("LOGIN_FAIL", "client"));
                            this.i2p_client_oos.flush();
                        }
                    }
                }
            } catch (IOException ex) {
                System.err.println("Lost connection with the client");
                break; //ώστε να φύγουμε από το loop

            } catch (ClassNotFoundException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class
                        .getName()).log(Level.SEVERE, null, ex);

            } catch (ConnectionNotSafeException ex) {
                Logger.getLogger(BobProxyEncryptedConnection.class
                        .getName()).log(Level.SEVERE, null, ex);
            }
        }
        //εφόσον έχει βγει από το loop, σημαίνει πως έχει γίνει Login οπότε τώρα περιμένουμε μήνυμα CALL από Client (μέθοδος call)
    }

    //Method that creates the AES-256 Symmetric (SecretKey) and returns it
    protected SecretKey getAESkey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256, new SecureRandom());

        return keygen.generateKey();
    }

    //παράγει τα IV
    protected IvParameterSpec createIV() {
        int ivSize = 16;
        byte[] iv_bytes = new byte[ivSize];
        random = new SecureRandom();
        random.nextBytes(iv_bytes);
        iv = new IvParameterSpec(iv_bytes);
        return iv;
    }

    //παραγωγή των κλειδιών DH μέσω των p, g 
    protected void generateParameters(boolean client, boolean first) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            keyagree = KeyAgreement.getInstance("DiffieHellman");
            if (client) {
                if (first) {
                    p = BigInteger.probablePrime(2048, new SecureRandom());
                    g = BigInteger.probablePrime(256, new SecureRandom());
                }

                DHParameterSpec dhPS = new DHParameterSpec(p, g);
                keyPairGen.initialize(dhPS, this.random);
                keypair_dh = keyPairGen.generateKeyPair();
            } else {
                if (first) {
                    p2 = BigInteger.probablePrime(2048, new SecureRandom());
                    g2 = BigInteger.probablePrime(256, new SecureRandom());
                }
                DHParameterSpec dhPS = new DHParameterSpec(p2, g2);
                keyPairGen.initialize(dhPS, this.random);
                keypair_dh2 = keyPairGen.generateKeyPair();

            }
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
    }

    //διαβάζουμε τα IV από το αρχείο
    protected void reconstructIV() {
        try {
            byte[] fileData = new byte[16];
            DataInputStream dis = null;

            dis = new DataInputStream(new FileInputStream(new File("iv\\iv")));
            dis.readFully(fileData);
            if (dis != null) {
                dis.close();
            }
            iv = new IvParameterSpec(fileData);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //παράγει τo RSA private key, αυτο τα παίρνουμε από αρχεία (keystoreCL1 για "server" και keystoreCL2 για client)
    protected PrivateKey getPrivateKey(String username, String password) throws NoSuchAlgorithmException {
        try {
            //extract το private key μας από το keystore
            privkey = (PrivateKey) keystore.getKey(username, password.toCharArray());
            //επιστροφή του private key
            return privkey;

        } catch (KeyStoreException | UnrecoverableKeyException ex) {
            Logger.getLogger(BobProxyEncryptedConnection.class
                    .getName()).log(Level.SEVERE, null, ex);
        }
        return null;

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
}
