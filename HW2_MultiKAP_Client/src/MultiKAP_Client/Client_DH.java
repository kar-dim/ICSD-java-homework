package MultiKAP_Client;//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client_DH {

    private PrivateKey priv;
    private PublicKey pub, pubExt; //pubExt = αυτό που λαμβάνει (public)
    private byte[] sec;
    private Socket connection;
    private ObjectOutputStream outputstream;
    private ObjectInputStream inputstream;
    private IvParameterSpec iv;
    private SecretKeySpec symmetricKey;
    private Mac mac;
    private String token;
    private String outgoingMessage;

    /*πρωτόκολλο
   SERVER                    CLIENT
     <-------PublicDHKey---------
     -------PublicDHKey--------->
     <-Encrypted Session Token-
    
     while(true){ //παράδειγμα είναι αυτό 
          <--μηνυμα--
          --μηνυμα-->
       }
    
     */
    public Client_DH(Socket socket, ObjectOutputStream oos, ObjectInputStream ois) {
        //παράγουμε τα κλειδιά DH
        generateKeys();
        //Initiator -> κάνει connect σε socket
        try {
            connection = socket;
            outputstream = oos;
            inputstream = ois;
            //αρχή επικοινωνίας, αρχικά ο Initiator στέλνει το public DH key
            outputstream.writeObject(pub);
            outputstream.flush();
            //στη συνέχεια λαμβάνει το public DH του Receiver και τα IV parameters
            pubExt = (PublicKey) inputstream.readObject();
            reconstructIV(javax.xml.bind.DatatypeConverter.parseBase64Binary((String) inputstream.readObject()));
            //τώρα έχουν ανταλλάξει public keys. Ο αλγόριθμος DH στη συνέχεια λέει πως πρέπει να παραχθεί
            //το SecretKey με βάση το public key που δέχτηκε (και το Private το δικό μας)
            generateSecretKey();
            //άρα τώρα ο αλγόριθμος έχει τελειώσει, τώρα μπορούμε να στέλνουμε μηνύματα στο δίκτυο
            //(κρυπτογραφημένα με το secretkey προφανώς)

            //αρχικοποίηση του Cipher για κρυπτογράφηση με AES
            this.symmetricKey = new SecretKeySpec(sec, "AES");
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            //αρχικοποίηση του hmac
            this.initializeHMAC();
            //ακολουθεί παράδειγμα μιας κρυπτογραφημένης συνομιλίας
            //(μπορεί να είναι οτιδήποτε απλώς εδώ δείχνουμε ένα παράδειγμα)

            //πρώτα στέλνουμε το SESSION TOKEN 
            //νέο session ID
            cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
            token = new TokenGenerator().generateToken();
            outputstream.writeObject(new SealedObject(token, cipher));
            outputstream.flush();

            Scanner scan = new Scanner(System.in);
            while (true) {
                //δημιουργία μηνύματος
                System.out.println("Type something: ");
                outgoingMessage = scan.nextLine();
                System.out.println("Client: " + this.outgoingMessage);

                //στέλνουμε το μήνυμα
                this.outputstream.writeObject(encrypt(this.outgoingMessage));
                this.outputstream.flush();

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
                System.out.println("Server: " + msg_received.getMessage());
                if (msg_received.getMessage().equals("EXIT")) {
                    System.out.println("The other client has left");
                    this.closeConnection();
                    System.exit(0);
                }
            }
        } catch (IOException ex) {
            System.err.println("The other client has left");
            this.closeConnection();
            System.exit(0);
        } catch (ConnectionNotSafeException ex) {
            System.err.println("Your connection is not safe");
            this.closeConnection();
            System.exit(-1);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | ClassNotFoundException | InvalidAlgorithmParameterException ex) {
            System.err.println("Encryption or decryption error");
            this.closeConnection();
            System.exit(-1);
        }
    }

    //κλείνει τη σύνδεση
    private void closeConnection() {
        try {
            this.inputstream.close();
            this.outputstream.close();
            this.connection.close();
        } catch (IOException ex) {
            Logger.getLogger(Client_DH.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //παράγουμε τα κλειδιά (private και public) μέσω Java API.
    private void generateKeys() {
        try {
            final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(2048);

            final KeyPair keyPair = keyPairGenerator.generateKeyPair();

            priv = keyPair.getPrivate();
            pub = keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    //secretkey Παράγεται με βάση το private (δικό μας) και το public του άλλου
    private void generateSecretKey() {
        try {
            final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(priv);
            keyAgreement.doPhase(pubExt, true);
            //σωστό μέγεθος (32bytes = 256bit) για το secret key
            final byte[] fixedSecKey = keyAgreement.generateSecret();
            sec = new byte[32];
            System.arraycopy(fixedSecKey, 0, sec, 0, sec.length);
        } catch (IllegalStateException | InvalidKeyException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    //επιστρέφει το publickey (χρειάζεται να μεταδοθεί το public key ΜΟΝΟ, και για αυτό δεν έχουμε και getPrivateKey)
    public PublicKey getPublicKey() {
        return pub;
    }

    //παράγουμε το IV με βάση τα bytes
    private void reconstructIV(byte[] bytes) {
        iv = new IvParameterSpec(bytes);
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
            return sb.toString();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client_DH.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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

    //παραγωγή της HMAC
    private void initializeHMAC() {
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.symmetricKey.getEncoded(), "HMACSHA256"));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client_DH.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Client_DH.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //sign με HMAC
    private String HMAC_Sign(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data.getBytes()));
    }
}
