//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Server_RSA {

    private Socket connection;
    private String token; //χρησιμοποιείται για να αποτρέψουμε τα replay attacks
    private ObjectInputStream inputstream;
    private ObjectOutputStream outputstream;
    private SecretKey symmetricKey;
    private IvParameterSpec iv;
    private PrivateKey privkey;
    private PublicKey reveived_pubkey; //αυτό που λαμβάνει 
    private KeyStore keystore;
    private KeyStore truststore;
    private Scanner scan;
    private String outgoingMessage;
    private Mac mac;

    public Server_RSA(Socket connection, ObjectOutputStream outputstream, ObjectInputStream inputstream) {
        try {
            this.connection = connection;
            this.outputstream = outputstream;
            this.inputstream = inputstream;
            Security.addProvider(new BouncyCastleProvider());
            createIV(); //παράγουμε τυχαία τα IV parameters τα οποία θα χρησιμοποιηθούν στο CBC (AES Block Cipher)
            System.setProperty("javax.net.ssl.trustStore", "keystores/truststoreCL1");
            this.loadKeyStore("keystores/keystoreCL1", "password1".toCharArray(), "keystore"); //φορτώνουμε το keystore
            this.loadKeyStore("keystores/truststoreCL1", "password1".toCharArray(), "truststore"); //φορτώνουμε το truststore
            this.privkey = this.getPrivateKey();
            this.whileConnected();
        } catch (NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException | KeyStoreException | IOException | CertificateException ex) {
            System.err.println("An error occured\nExiting session.....");
        }
    }

    //Πρωτόκολλο
    /*
    SERVER                    CLIENT
       <-------StartSession------
       -----------OK------------>
       <------Certificate--------
       -------CertReceived------>
       -------Certificate------->
       <------CertReceived-------
       -----Encrypted AES Key--->
       -Encrypted token(με AES)->
    
        while(true){ //παράδειγμα είναι αυτό 
           <--μηνυμα--
           --μηνυμα-->
        }
     */
    private void whileConnected() throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        try {
            //διαβασμα του "startsession"
            if (!inputstream.readUTF().equals("StartSession")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }
            //στελνουμε "ΟΚ"
            this.outputstream.writeUTF("OK");
            this.outputstream.flush();

            //λαμβάνουμε το certificate
            X509Certificate cer_received = (X509Certificate) this.inputstream.readObject();

            //Στέλνουμε ACK οτι το λάβαμε
            this.outputstream.writeUTF("CertReceived");
            this.outputstream.flush();
            //Validate το certificate
            if (!this.checkReceivedCertificate(cer_received)) {
                throw new ConnectionNotSafeException("The certificate can't be verified!\n");
            }
            //extract public key από το certificate
            reveived_pubkey = cer_received.getPublicKey();

            //διάβασμα από το αρχείο
            FileInputStream fis = new FileInputStream(new File("certificates/client1signed.cer"));
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
            this.outputstream.writeObject(cert); //εδώ στέλνουμε το certificate
            this.outputstream.flush();
            //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
            if (!this.inputstream.readUTF().equals("CertReceived")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }
            //παράγουμε το συμμετρικό AES key
            this.symmetricKey = this.getAESkey();
            //initialize το hmac
            this.initializeHMAC();
            //encrypt το AES key (με το public του client) και στέλνουμε το encrypted AES KEY + IV params (base64 string τα bytes)
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, reveived_pubkey);
            this.outputstream.writeObject(new SealedObject(this.symmetricKey, cipher));
            this.outputstream.writeObject(new SealedObject(javax.xml.bind.DatatypeConverter.
                    printBase64Binary(this.iv.getIV()), cipher));
            this.outputstream.flush();

            //παραγωγή του random token
            token = new TokenGenerator().generateToken();
            //κρυπτογράφηση με AES και το στέλνουμε στο stream. Στην ουσία ο αλγόριθμος έχει τελειώσει αφού
            //έχει παραχθεί το συμμετρικό κλειδί και στάλθηκε το πρώτο μήνυμα κρυπτογραφημένο με αυτό (το token)
            this.outputstream.writeObject(encrypt(token));
            this.outputstream.flush();

            //παράδειγμα συνομιλίας
            scan = new Scanner(System.in);
            while (true) {
                //λαμβάνουμε μήνυμα 
                Message msg_received = this.decrypt((SealedObject) this.inputstream.readObject());
                String hmac_check = msg_received.getHMAC();
                //έλεγχος του hmac του μηνύματος
                if (!hmac_check.equals(this.HMAC_Sign(msg_received.toString()))) {
                    throw new ConnectionNotSafeException("Your connection is not secure!");
                }

                //έλεγχος αν το token είναι σωστό! Ο έλεγχος γίνεται ως εξής:
                //αν HASH(ΜΗΝΥΜΑ_ΠΟΥ_ΣΤΑΛΘΗΚΕ+TOKEN_ΜΗΝΥΜΑΤΟΣ) = HASH(ΜΗΝΥΜΑ_ΠΟΥ_ΣΤΑΛΘΗΚΕ+TOKEN_ΔΙΚΟ_ΜΑΣ) τοτε
                //ειμαστε οκ, διοτι αυτό σημαίνει πως το TOKEN Δεν άλλαξε
                String hash = SHA256_Hash(msg_received.toString());
                if (!hash.equals(SHA256_Hash(msg_received.getMessage() + token))) {
                    //άλλαξε το token = replay attack!
                    throw new ConnectionNotSafeException("Your connection is not secure!");
                }

                System.out.println("Client: " + msg_received.getMessage());
                 if (msg_received.getMessage().equals("EXIT")){
                    System.out.println("The other client has left");
                    this.closeConnection();
                    System.exit(0);
                }
                 
                //δημιουργία μηνύματος
                System.out.println("Type something: ");
                outgoingMessage = scan.nextLine();
                System.out.println("Server: " + this.outgoingMessage);
                //στέλνουμε το μήνυμα
                this.outputstream.writeObject(encrypt(this.outgoingMessage));
                this.outputstream.flush();
            }
        } catch (IOException ioe) {
            System.err.println("The other client has left");
            this.closeConnection();
            System.exit(0);
        } catch (ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchProviderException ex) {
            System.err.println("Encryption error");
            this.closeConnection();
            System.exit(-1);
        } catch (UnknownProtocolCommandException ex) {
            System.err.println("Unknown command\nExiting session...");
            System.exit(-1);
        } catch (ConnectionNotSafeException cnse) {
            System.err.println("Your connection is not secure!\nExiting session...");
            this.closeConnection();
            System.exit(-1);
        } catch (CertificateException ex) {
            System.err.println("Not a certificate");
            this.closeConnection();
            System.exit(-1);
        }
    }

    //παράγει τo RSA private key, αυτο τα παίρνουμε από αρχεία (keystoreCL1 για "server" και keystoreCL2 για client)
    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
        try {
            //extract το private key μας από το keystore
            privkey = (PrivateKey) keystore.getKey("client1", "password1".toCharArray());
            //επιστροφή του private key
            return privkey;
        } catch (KeyStoreException | UnrecoverableKeyException ex) {
            Logger.getLogger(Server_RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    //μέθοδος που διαβάζει το keystore file
    private KeyStore loadKeyStore(String key_store, char[] password, String type) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
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
            return keystore;
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
            return truststore;
        }
        return null;
    }

    //Method that creates the AES-256 Symmetric (SecretKey) and returns it
    private SecretKey getAESkey() throws NoSuchAlgorithmException {
        KeyGenerator keygen = KeyGenerator.getInstance("AES");
        keygen.init(256, new SecureRandom());

        return keygen.generateKey();
    }

    //hash με sha-256, επιστρέφει τη hex μορφή των bytes
    private String SHA256_Hash(String message) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashed = digest.digest(message.getBytes(StandardCharsets.UTF_8));
            //μετατροπή σε hex
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashed.length; i++) {
                sb.append(Integer.toString((hashed[i] & 0xff) + 0x100, 16).substring(1));
            }
            //επιστροφή του hash σε string
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Server_RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    //παράγει τα IV
    private IvParameterSpec createIV() {
        int ivSize = 16;
        byte[] iv_bytes = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv_bytes);
        iv = new IvParameterSpec(iv_bytes);
        return iv;
    }

    //Μέθοδος που checkάρει αν το  certificate που στέλνεται έχει γίνει sign από την ca
    //Δηλαδή ελέγχουμε το truststore μας (που εμπεριέχει το certificate, και άρα το public key της CA)
    //έχει όντως κάνει sign το certificate που μας δίνεται
    private boolean checkReceivedCertificate(X509Certificate cer) {
        try {
            //διάβασμα του certificate του CA από το truststore
            X509Certificate ca_cer = (X509Certificate) truststore.getCertificate("CAcer");
            //ελέγχουμε αν το certificate που δίνεται έχει υπογραφτεί από τον CA
            cer.verify(ca_cer.getPublicKey());
            return true;
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException ex) {
            Logger.getLogger(Server_RSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException | CertificateException ex) {
            System.err.println("Could not verify the certificate! Possibly dangerous condition\nExiting session...");
            this.closeConnection();
            System.exit(-1);
            Logger.getLogger(Server_RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    //κλείνει τη σύνδεση
    private void closeConnection() {
        try {
            if (this.outputstream != null && this.inputstream != null) {
                outputstream.close();
                inputstream.close();
            }
            connection.close();
            System.exit(-1);
        } catch (IOException ex) {
            System.err.println("Error while closing session....");
        }
    }

    //παραγωγή της HMAC
    private void initializeHMAC() {
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.symmetricKey.getEncoded(), "HMACSHA256"));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Server_RSA.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Server_RSA.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //sign με HMAC
    private String HMAC_Sign(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data.getBytes()));
    }

    //μέθοδος για encrypt ενός μηνύματος
    private SealedObject encrypt(String msg) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
            Message message = new Message(msg, token, this.HMAC_Sign(msg + this.token));
            return new SealedObject(message, cipher);
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

    //μέθοδος για decrypt
    private Message decrypt(SealedObject sobj) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);
            return (Message) sobj.getObject(cipher);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException ex) {
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
}
