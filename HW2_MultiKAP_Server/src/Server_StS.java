//Nikolaos Katsiopis icsd13076
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
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
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
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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

public class Server_StS {

    private BigInteger p, g; //παράμετροι p,g, τους παράγει ο client και τους στέλνει στον "server" πριν ξεκινήσει η διαδικασία
    private String token;
    private ObjectInputStream inputstream;
    private ObjectOutputStream outputstream;
    private PrivateKey privkey;
    private KeyPair keypair_dh; //τα DH keypair_dh
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
    private Socket connection;
    private Mac mac;

    public Server_StS(Socket connection, ObjectOutputStream outputstream, ObjectInputStream inputstream) {

        try {
            this.connection = connection;
            this.outputstream = outputstream;
            this.inputstream = inputstream;
            Security.addProvider(new BouncyCastleProvider());
            System.setProperty("javax.net.ssl.trustStore", "keystores/truststoreCL1");
            this.loadKeyStore("keystores/keystoreCL1", "password1".toCharArray(), "keystore"); //φορτώνουμε το keystore
            this.loadKeyStore("keystores/truststoreCL1", "password1".toCharArray(), "truststore"); //φορτώνουμε το truststore
            this.privkey = this.getPrivateKey();
            this.whileConnected();
        } catch (NoSuchAlgorithmException | KeyStoreException | IOException | CertificateException ex) {
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
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
               [Client generates SHARED KEY: (g^y)^x (επειδή g^x^y = g^y^x το shared key ειναι ιδιο)
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
    private void whileConnected() {
        try {
            //λαμβάνουμε πρώτα StartSession Και στέλνουμε ΟΚ
            if (!inputstream.readUTF().equals("StartSession")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }
            //στέλνουμε "ΟΚ"
            this.outputstream.writeUTF("OK");
            this.outputstream.flush();

            //λαμβάνουμε p,g και IV από client
            this.p = (BigInteger) this.inputstream.readObject();
            this.g = (BigInteger) this.inputstream.readObject();
            reconstructIV(javax.xml.bind.DatatypeConverter.parseBase64Binary((String) this.inputstream.readObject()));
            //στέλνουμε ack οτι τα πήραμε
            this.outputstream.writeUTF("ParametersReceived");
            this.outputstream.flush();

            //με βάση τα p,g παράγουμε τα DH public/private key μας
            this.generateParameters();
            //μας στέλνει το Certificate οπότε εμείς το ελέγχουμε, δηλαδή αν έχει υπογραφτεί με την CA
            //από το truststore μας
            X509Certificate cer_received = (X509Certificate) this.inputstream.readObject();

            this.outputstream.writeUTF("CertificateReceived");
            this.outputstream.flush();

            //Validate το certificate
            if (!this.checkReceivedCertificate(cer_received)) {
                throw new ConnectionNotSafeException("The certificate can't be verified!");
            }

            //Στέλνουμε το certificate μας
            FileInputStream fis = new FileInputStream(new File("certificates/client1signed.cer"));
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
            this.outputstream.writeObject(cert);
            this.outputstream.flush();

            //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
            if (!this.inputstream.readUTF().equals("CertificateReceived")) {
                System.err.println("Protocol error\nExiting session...");
                System.exit(-1);
            }

            //λαμβάνουμε το public dh key (Δηλαδή το g^x)
            received_dh_pubkey = (PublicKey) this.inputstream.readObject();
            //στέλνουμε ack ότι το πήραμε
            this.outputstream.writeUTF("PublicDHKeyReceived");

            //στέλνουμε το g^y μας. το g^y είναι το public dh key (server)
            this.outputstream.writeObject(keypair_dh.getPublic());
            this.outputstream.flush();
            //αν δεν μας απαντήσει ο client με PublicDHKeyReceived τότε σφάλμα
            if (!this.inputstream.readUTF().equals("PublicDHKeyReceived")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }

            /* 3: encrypted μήνυμα */
            //τώρα παράγουμε το shared κλειδί. Αυτό το κλειδί θα πρέπει να είναι ίδιο με αυτό που παρήγαγε ο server
            //ώστε να μας στείλει το encrypted και signed g^y, g^x. εμείς δεν κάνουμε τη λειτουργία (g^x)^y (client) ή (g^y)^x (server)
            //αυτό γίνεται αυτόματα από το keyagree
            keyagree.init(keypair_dh.getPrivate());
            keyagree.doPhase(received_dh_pubkey, true);
            this.symmetricKey = keyagree.generateSecret("AES");

            //αρχικοποίηση του cipher Με AES
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
            //αρχικοποίηση του signature
            sig = Signature.getInstance("SHA256withRSA", "BC");
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
            //τώρα λαμβάνουμε το signed ciphertext
            SealedObject sobj = (SealedObject) this.inputstream.readObject();
            //στέλνουμε ack ότι το λάβαμε
            this.outputstream.writeUTF("SignedCiphertextReceived");
            this.outputstream.flush();
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
            //εφόσον κάναμε verify, μπορούμε να στείλουμε το πρώτο μήνυμα με AES, το "StartSymmetricEncryption"
            //στη συνέχεια θα στείλουμε το token

            //παραγωγή του random token
            token = new TokenGenerator().generateToken();
            cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
            //στέλνουμε το μήνυμα + token
            this.outputstream.writeObject(new SealedObject("StartSymmetricEncryption", cipher));
            this.outputstream.writeObject(new SealedObject(token, cipher));
            this.outputstream.flush();
            //στην ουσία εδώ έχει τελειώσει το key agreement
            //θεωρητικά (και πρακτικά) και οι δυο πλευρές έχουν το ίδιο AES key αφού για να έχουμε φτάσει ως εδώ
            //σημαίνει πως το token αποκρυπτογραφήθηκε οπότε το AES κλειδί είναι το ίδιο και στις 2 πλευρές

            //παραγωγή της HMAC
            this.createHMAC();
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
                if (msg_received.getMessage().equals("EXIT")) {
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
        } catch (UnknownProtocolCommandException ex) {
            System.err.println("Unknown command\nExiting session...");
            this.closeConnection();
            System.exit(-1);
        } catch (IOException ioe) {
            System.err.println("The other client has left");
            this.closeConnection();
            System.exit(0);
        } catch (ClassNotFoundException | CertificateException | InvalidKeyException | IllegalStateException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchProviderException | SignatureException | IllegalBlockSizeException | BadPaddingException ex) {
            System.err.println("Encryption error");
            this.closeConnection();
            System.exit(-1);
        } catch (ConnectionNotSafeException ex) {
            System.err.println("Your connection is not secure!\nExiting session...");
            this.closeConnection();
            System.exit(-1);
        }
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
    private void createHMAC() {
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.symmetricKey.getEncoded(), "HMACSHA256"));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    //sign με HMAC
    private String HMAC_Sign(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data.getBytes()));
    }

    //παράγουμε το IV με βάση τα bytes
    private void reconstructIV(byte[] bytes) {
        iv = new IvParameterSpec(bytes);
        random = new SecureRandom();
        random.nextBytes(bytes);
    }

    //παραγωγή των κλειδιών DH μέσω των p, g που δεχτήκαμε από client 
    private void generateParameters() {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("DiffieHellman");
            keyagree = KeyAgreement.getInstance("DiffieHellman");
            DHParameterSpec dhPS = new DHParameterSpec(p, g);
            keyPairGen.initialize(dhPS, this.random);
            keypair_dh = keyPairGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException ex) {
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
        }
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
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
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
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException | CertificateException ex) {
            System.err.println("Could not verify the certificate! Possibly dangerous condition\nExiting session...");
            System.exit(-1);
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
        }
        return false;
    }

    //παράγει τα RSA keys, αυτά τα παίρνουμε από αρχεία (keystoreCL1 για "server" και keystoreCL2 για client)
    private PrivateKey getPrivateKey() throws NoSuchAlgorithmException {
        try {
            //extract το private key μας από το keystore
            privkey = (PrivateKey) keystore.getKey("client1", "password1".toCharArray());
            //επιστροφή του private key
            return privkey;
        } catch (KeyStoreException | UnrecoverableKeyException ex) {
            Logger.getLogger(Server_StS.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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
}
