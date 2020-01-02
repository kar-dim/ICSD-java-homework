//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Server_DH {

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

    public Server_DH(Socket connection, ObjectOutputStream outputstream, ObjectInputStream inputstream) {
        this.connection = connection;
        this.outputstream = outputstream;
        this.inputstream = inputstream;
        //παράγουμε τα κλειδιά
        generateKeys();
        //παράγουμε το iv
        this.createIV();
        //Receiver-> περιμένει client να συνδεθεί
        try {
            //αρχή επικοινωνίας, αρχικά ο Initiator στέλνει το public key του
            //οπότε το δεχόμαστε
            pubExt = (PublicKey) inputstream.readObject();
            //στη συνέχεια στέλνουμε το public μας στον Initiator καθώς και τα IV parameters
            outputstream.writeObject(pub);
            outputstream.writeObject(javax.xml.bind.DatatypeConverter.printBase64Binary(iv.getIV()));
            outputstream.flush();
            //τώρα έχουν ανταλλάξει public keys. Ο αλγόριθμος DH στη συνέχεια λέει πως πρέπει να παραχθεί
            //το SecretKey με βάση το public Κευ που δέχτηκε
            generateSecretKey();
            //άρα τώρα ο αλγόριθμος έχει τελειώσει, τώρα μπορούμε να στέλνουμε μηνύματα στο δίκτυο
            //(κρυπτογραφημένα με το secretkey προφανώς)

            //αρχικοποίηση του Cipher για κρυπτογράφηση με AES
            this.symmetricKey = new SecretKeySpec(sec, "AES");
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            //ακολουθεί παράδειγμα μιας κρυπτογραφημένης συνομιλίας
            //(μπορεί να είναι οτιδήποτε απλώς εδώ δείχνουμε ένα παράδειγμα)

            //αρχικοποίηση του hmac
            this.initializeHMAC();
            //πρώτα λαμβάνουμε το session ID
            cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);
            SealedObject seal = (SealedObject) inputstream.readObject();
            token = (String) seal.getObject(cipher);

            Scanner scan = new Scanner(System.in);
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

        } catch (IOException ex) {
            System.err.println("The other client has left");
            this.closeConnection();
            System.exit(0);
        } catch (ConnectionNotSafeException ex) {
            System.err.println("Your connection is not safe");
            this.closeConnection();
            System.exit(-1);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | ClassNotFoundException | InvalidAlgorithmParameterException ex) {
            System.err.println("Encryption or decryption error");
            this.closeConnection();
            System.exit(-1);
        }
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

    //παράγει τα IV
    private IvParameterSpec createIV() {
        int ivSize = 16;
        byte[] iv_bytes = new byte[ivSize];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv_bytes);
        iv = new IvParameterSpec(iv_bytes);
        return iv;
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
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //επιστρέφει το publickey (χρειάζεται να μεταδοθεί το public key ΜΟΝΟ, και για αυτό δεν έχουμε και getPrivateKey)
    public PublicKey getPublicKey() {
        return pub;
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
            Logger.getLogger(Server_DH.class.getName()).log(Level.SEVERE, null, ex);
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
            Logger.getLogger(Server_DH.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Server_DH.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //sign με HMAC
    private String HMAC_Sign(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data.getBytes()));
    }
}
