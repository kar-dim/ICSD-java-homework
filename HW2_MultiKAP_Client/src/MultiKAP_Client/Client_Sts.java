package MultiKAP_Client;//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
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
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client_Sts {

    private BigInteger p, g; //παράμετροι p,q, τους παράγει ο client και τους στέλνει στον "server" πριν ξεκινήσει η διαδικασία
    private Socket connection;
    private String token;
    private ObjectInputStream inputstream;
    private ObjectOutputStream outputstream;
    private PrivateKey privkey;
    private KeyPair keypair_dh; //τα DH public/private key μας
    private KeyAgreement keyagree;
    private PublicKey received_dh_pubkey; //DH public key που λαμβάνουμε
    private SecretKey symmetricKey;
    private KeyStore keystore;
    private KeyStore truststore;
    private IvParameterSpec iv;
    private Signature sig;
    private String outgoingMessage;
    private Scanner scan;
    private SecureRandom random;
    private Mac mac;

    public Client_Sts(Socket connection, ObjectOutputStream oos, ObjectInputStream ois) {
        try {
            Security.addProvider(new BouncyCastleProvider()); 
            System.setProperty("javax.net.ssl.trustStore", "keystores/truststoreCL2");
            this.loadKeyStore("keystores/keystoreCL2", "password2".toCharArray(), "keystore"); //φορτώνουμε το keystore
            this.loadKeyStore("keystores/truststoreCL2", "password2".toCharArray(), "truststore"); //φορτώνουμε το truststore
            this.connection = connection;
            this.outputstream = oos;
            this.inputstream = ois;
            this.privkey = this.getPrivateKey();
            //Πρώτα πρέπει να στείλουμε τα p και g, εφόσον είναι κοινά.
            //άρα παράγουμε πρώτα τα p και g
            this.createIV();
            this.generateParameters();
            this.whileConnected();
        } catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | IOException | CertificateException ex) {
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //κλείνει τη σύνδεση
    private void closeConnection() {
        try {
            outputstream.close();
            inputstream.close();
            connection.close();
        } catch (IOException ex) {
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //Πρωτόκολλο
    /*
            SERVER                    CLIENT
               <-------StartSession------
               ------------OK----------->
               <---------p,g,IV----------
               ----ParametersReceived--->
               <------Certificate--------
               ---CertificateReceived--->
               -------Certificate------->
               <--CertificateReceived----
               <---PublicDHKey_Client----
               ---PublicDHKeyReceived--->
               [Server generates SHARED KEY: (g^x)^y έστω Κ], x: client's private dh key, y: server's private dh key
               ----PublicDHKey_Server--->
               <---PublicDHKeyReceived---
               -----K(sign(g^y,g^x))---->
               [Client generates SHARED KEY: (g^y)^x έστω Κ
               <SignedCiphertextReceived-
               [Client VERIFY sig με shared]
               <----K(sign(g^x, g^y))----
               -SignedCiphertextReceived>
               [Server VERIFY sig με shared]
               -StartSymmetricEncryption->     -> τέλος αλγορίθμου, AES KEY: K
               -Encrypted token(με AES)->

                while(true){ //παράδειγμα είναι αυτό 
                   <--μηνυμα--
                   --μηνυμα-->
                }
     */
    private void whileConnected() throws InvalidKeyException {
        try {
            //ξεκινάμε πρώτοι ως client και στέλνουμε StartSession για να ξεκινήσει η διαδικασία
            this.outputstream.writeUTF("StartSession");
            this.outputstream.flush();

            //αν δεν μας απαντήσει ο "server" με ΟΚ τότε σφάλμα
            if (!this.inputstream.readUTF().equals("OK")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }
            //στη συνέχεια στέλνουμε τα p,g και IV στον "server"
            this.outputstream.writeObject(p);
            this.outputstream.writeObject(g);
            this.outputstream.writeObject(javax.xml.bind.DatatypeConverter.printBase64Binary(this.iv.getIV()));
            this.outputstream.flush();
            //αν δεν μας απαντήσει ο "server" με ParametersReceived τότε σφάλμα
            if (!this.inputstream.readUTF().equals("ParametersReceived")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }

            //Στέλνουμε το certificate μας
            FileInputStream fis = new FileInputStream(new File("certificates/client2signed.cer"));
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
            this.outputstream.writeObject(cert);
            this.outputstream.flush();

            //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
            if (!this.inputstream.readUTF().equals("CertificateReceived")) {
                System.err.println("Protocol error\nExiting session...");
                System.exit(-1);
            }

            //μας στέλνει το Certificate οπότε εμείς το ελέγχουμε, δηλαδή αν έχει υπογραφτεί με την CA
            //από το truststore μας
            X509Certificate cer_received = (X509Certificate) this.inputstream.readObject();

            // στέλνουμε ACK ότι το πήραμε
            this.outputstream.writeUTF("CertificateReceived");
            this.outputstream.flush();

            //Validate το certificate
            if (!this.checkReceivedCertificate(cer_received)) {
                throw new ConnectionNotSafeException("The certificate can't be verified!");
            }

            //στέλνουμε το g^x μας. το g^x είναι το public dh key (client)
            this.outputstream.writeObject(keypair_dh.getPublic());
            this.outputstream.flush();
            //αν δεν μας απαντήσει ο "server" με PublicDHKeyReceived τότε σφάλμα
            if (!this.inputstream.readUTF().equals("PublicDHKeyReceived")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }

            /* 2: public DH key (g^y) */
            //λαμβάνουμε το public dh key (Δηλαδή το g^y)
            received_dh_pubkey = (PublicKey) this.inputstream.readObject();
            //στέλνουμε ack ότι το πήραμε
            this.outputstream.writeUTF("PublicDHKeyReceived");
            this.outputstream.flush();

            /* 3: encrypted μήνυμα */
            //τώρα παράγουμε το shared κλειδί. Αυτό το κλειδί θα πρέπει να είναι ίδιο με αυτό που παρήγαγε ο server
            //ώστε να μας στείλει το encrypted και signed g^y, g^x. εμείς δεν κάνουμε τη λειτουργία (g^x)^y (client) ή (g^y)^x (server)
            //αυτό γίνεται αυτόματα από το keyagree
            keyagree.init(keypair_dh.getPrivate());
            keyagree.doPhase(received_dh_pubkey, true);
            this.symmetricKey = keyagree.generateSecret("AES");

            //αρχικοποίηση του cipher Με AES
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);

            //λαμβάνουμε το signed ciphertext
            SealedObject sobj = (SealedObject) this.inputstream.readObject();
            //στέλνουμε ack ότι το λάβαμε
            this.outputstream.writeUTF("SignedCiphertextReceived");
            this.outputstream.flush();

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
            this.outputstream.writeObject(new SealedObject(javax.xml.bind.DatatypeConverter.printBase64Binary(sig.sign()), cipher));
            this.outputstream.flush();
            //αν δε το έλαβε, σφάλμα
            if (!this.inputstream.readUTF().equals("SignedCiphertextReceived")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }

            cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);
            //αν  όλα πάνε καλά ο Server θα στείλει "StartSymmetricEncryption" encrypted με το AES κλειδί
            SealedObject seal_start = (SealedObject) this.inputstream.readObject();
            String start = (String) seal_start.getObject(cipher);
            if (!start.equals("StartSymmetricEncryption")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }
            //initialize το hmac
            this.initializeHMAC();
            //διάβασμα του session token (αποκρυπτογράφηση με το AES πρώτα)
            SealedObject seal = (SealedObject) this.inputstream.readObject();
            token = (String) seal.getObject(cipher);
            //στην ουσία εδώ έχει τελειώσει το key agreement
            //θεωρητικά (και πρακτικά) και οι δυο πλευρές έχουν το ίδιο AES key αφού για να έχουμε φτάσει ως εδώ
            //σημαίνει πως το token αποκρυπτογραφήθηκε οπότε το AES κλειδί είναι το ίδιο και στις 2 πλευρές

            //παράδειγμα συνομιλίας
            scan = new Scanner(System.in);
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
                if (!hmac_check.equals(this.HMAC_Sign(msg_received.toString()))){
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
                if (msg_received.getMessage().equals("EXIT")){
                    System.out.println("The other client has left");
                    this.closeConnection();
                    System.exit(0);
                }
            }

        } catch (IOException ioe) {
            System.err.println("The other client has left");
            this.closeConnection();
            System.exit(0);
        } catch (InvalidAlgorithmParameterException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException ex) {
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
        } catch (SignatureException ex) {
           System.err.println("Signature error");
            this.closeConnection();
            System.exit(-1);
        }
    }

    //παραγωγή p και g, γενικά για να είναι ασφαλείς οι p,g, πρέπει να είναι αρκετά μεγάλοι (όχι υπερβολικά
    //ώστε να μη καθυστερούν), μια ικανοποιητική τιμή είναι 2048bits για το p και 256bits για το g
    private void generateParameters() {
        try {
            p = BigInteger.probablePrime(2048, new SecureRandom());
            g = BigInteger.probablePrime(256, new SecureRandom());
            //παραγωγή των keyagree
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            keyagree = KeyAgreement.getInstance("DiffieHellman");
            DHParameterSpec dhPS = new DHParameterSpec(p, g);
            keyPairGen.initialize(dhPS, this.random);
            keypair_dh = keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //παράγει τα IV
    private IvParameterSpec createIV() {
        int ivSize = 16;
        byte[] iv_bytes = new byte[ivSize];
        random = new SecureRandom();
        random.nextBytes(iv_bytes);
        iv = new IvParameterSpec(iv_bytes);
        return iv;
    }

    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
        try {
            //extract το private key μας
            privkey = (PrivateKey) keystore.getKey("client2", "password2".toCharArray());
            //επιστροφή του private key
            return privkey;
        } catch (KeyStoreException | UnrecoverableKeyException ex) {
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException | CertificateException ex) {
            System.err.println("Could not verify the certificate! Possibly dangerous condition\nExiting session...");
            System.exit(-1);
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    //μέθοδος για διάβασμα ενός keystore
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
        } catch (IOException ioe){
            System.err.println("Could not send the message");
            this.closeConnection();
            System.exit(-1);
        }
        return null;
    }
    //μέθοδος για decrypt
    private Message decrypt(SealedObject sobj){
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);
            return (Message) sobj.getObject(cipher);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException ex) {
            System.err.println("Encryption error");
            this.closeConnection();
            System.exit(-1);
        } catch (IOException ioe){
            System.err.println("Could not send the message");
            this.closeConnection();
            System.exit(-1);
        }
        return null;
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
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    //παραγωγή της HMAC

    private void initializeHMAC() {
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.symmetricKey.getEncoded(), "HMACSHA256"));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Client_Sts.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //sign με HMAC
    private String HMAC_Sign(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data.getBytes()));
    }
}
