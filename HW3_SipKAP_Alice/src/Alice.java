//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Alice extends AliceEncryptedConnection {

    private BigInteger p, g; //παράμετροι p,q, τους παράγει ο client και τους στέλνει στον "server" πριν ξεκινήσει η διαδικασία
    private KeyPair keypair_dh; //τα DH public/private key μας
    private KeyAgreement keyagree;
    private PublicKey received_dh_pubkey; //DH public key που λαμβάνουμε
    private String session; //I2p session (i2p server address)
    private Signature sig;
    private I2PClient i2pclient;
    private ObjectOutputStream i2p_oos;
    private ObjectInputStream i2p_ois;

    public Alice(Socket connection, ObjectOutputStream oos, ObjectInputStream ois, String mode) {
        try {

            Security.addProvider(new BouncyCastleProvider());
            System.setProperty("javax.net.ssl.trustStore", "keystores/truststoreCL1");
            super.loadKeyStore("keystores/keystoreCL1", "password1".toCharArray(), "keystore"); //φορτώνουμε το keystore
            super.loadKeyStore("keystores/truststoreCL1", "password1".toCharArray(), "truststore"); //φορτώνουμε το truststore
            this.privkey = getPrivateKey("client1", "password1");
            this.connection = connection;
            this.outputstream = oos;
            this.inputstream = ois;
            this.reconstructIV();
            
            if (mode.equals("STS")) {
                //Πρώτα πρέπει να στείλουμε τα p και g, εφόσον είναι κοινά.
                //άρα παράγουμε πρώτα τα p και g καθώς και IV parameters για τον AES
                this.generateParameters();
                this.whileConnectedSTS();
            } else {
                this.whileConnectedRSA();
            }

        } catch (NoSuchAlgorithmException | InvalidKeyException | KeyStoreException | IOException | CertificateException ex) {
            Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
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
    
        while(true){ 
            SIP PROTOCOL
        }
     */
    private void whileConnectedRSA() throws InvalidKeyException {
        try {
            //ξεκινάμε πρώτοι ως client και στέλνουμε StartSession για να ξεκινήσει η διαδικασία
            this.outputstream.writeUTF("StartSession");
            this.outputstream.flush();

            //αν δεν μας απαντήσει ο "server" με ΟΚ τότε σφάλμα
            if (!this.inputstream.readUTF().equals("OK")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }
            //αν υπάρχει ήδη το κλειδί τότε δε χρειάζεται να ξανα αναπαραχθεί
            if (!new File("keys\\skey_client.key").exists()) {
                //Στέλνουμε το certificate μας
                FileInputStream fis = new FileInputStream(new File("certificates/client1signed.cer"));
                X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
                this.outputstream.writeObject(cert); //στέλνουμε το certificate μας
                this.outputstream.flush();

                //αν δε το έλαβε, τότε κλείνουμε το session διοτι μάλλον θα υπάρχει πρόβλημα
                if (!this.inputstream.readUTF().equals("CertReceived")) {
                    System.err.println("Protocol error\nExiting session...");
                    System.exit(-1);
                }

                //λαμβάνουμε certificate 
                X509Certificate cer_received = (X509Certificate) this.inputstream.readObject();
                this.outputstream.writeUTF("CertReceived");
                this.outputstream.flush();

                //Validate το certificate
                if (!this.checkReceivedCertificate(cer_received)) {
                    throw new ConnectionNotSafeException("The certificate can't be verified!");
                }

                //λαμβάνουμε το συμμετρικό κλειδί 
                SealedObject sobj_aes = (SealedObject) this.inputstream.readObject();
                //αρχικοποίηση του cipher για αποκρυπτογράφηση του συμμετρικού κλειδιού
                Cipher cipher = Cipher.getInstance("RSA", "BC");
                cipher.init(Cipher.DECRYPT_MODE, privkey);
                //aes key
                this.symmetricKey = (SecretKey) sobj_aes.getObject(cipher);
                //save το κλειδί ώστε να υπάρχει 
                try (OutputStream stream = new FileOutputStream("keys\\skey_client.key")) {
                    stream.write(this.symmetricKey.getEncoded());
                }
            } //αλλιώς αν υπάρχει τότε απλώς το παίρνουμε
            else {
                this.symmetricKey = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_client.key")), "AES");
            }
            //initialize το hmac
            this.initializeHMACs();
            //παιρνουμε το session token (αποκρυπτογράφηση με το AES key τώρα)
            Message msg = (Message) decrypt((SealedObject) inputstream.readObject());
            token = msg.getToken();
            //στην ουσία εδώ έχει τελειώσει το key agreement

             //διάβασμα του Session (I2P) String
            //πέρνουμε το destination string  απο τον server για να ξεκινήσει η επικοινωνία μέσω I2P
            Message session_msg = (Message) decrypt((SealedObject) inputstream.readObject());
            this.session = session_msg.getMessage();
            i2pclient = new I2PClient(this.session);

            //σύνδεση με τον σερβερ (i2p)
            i2pclient.accept();
            //μέσω GUI στέλνονται τα REGISTER/LOGIN

            this.i2p_ois = i2pclient.getI2PInputStream();
            this.i2p_oos = i2pclient.getI2POutputStream();
            AliceSipGUI gui = new AliceSipGUI(i2p_ois, i2p_oos, this.symmetricKey, this.iv, this.token, this.mac);
            gui.updateScreen("Connected to server!");

        } catch (IOException ioe) {
            System.err.println("The other client has left");
            this.closeConnection();
            System.exit(0);
        } catch (ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException ex) {
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
            // } catch (InvalidAlgorithmParameterException ex) {
            //     Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
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
               ---Encrypted Server URL-->
                while(true){ 
                    SIP PROTOCOL
                }
     */
    private void whileConnectedSTS() throws InvalidKeyException {
        try {
            //ξεκινάμε πρώτοι ως client και στέλνουμε StartSession για να ξεκινήσει η διαδικασία
            this.outputstream.writeUTF("StartSession");
            this.outputstream.flush();

            //αν δεν μας απαντήσει ο "server" με ΟΚ τότε σφάλμα
            if (!this.inputstream.readUTF().equals("OK")) {
                throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
            }

            if (!new File("keys\\skey_client.key").exists()) {
                //στη συνέχεια στέλνουμε τα p,g και IV στον "server"
                this.outputstream.writeObject(p);
                this.outputstream.writeObject(g);

                this.outputstream.flush();
                //αν δεν μας απαντήσει ο "server" με ParametersReceived τότε σφάλμα
                if (!this.inputstream.readUTF().equals("ParametersReceived")) {
                    throw new UnknownProtocolCommandException("Unknown command\nExiting session...");
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

                //save το κλειδί ώστε να υπάρχει 
                try (OutputStream stream = new FileOutputStream("keys\\skey_client.key")) {
                    stream.write(this.symmetricKey.getEncoded());
                }

            } //αλλιώς αν υπάρχει τότε απλώς το παίρνουμε
            else {
                this.symmetricKey = new SecretKeySpec(Files.readAllBytes(Paths.get("keys\\skey_client.key")), "AES");
            }

            //initialize το hmac
            this.initializeHMACs();
            //παιρνουμε το session token (αποκρυπτογράφηση με το AES key τώρα)
            Message msg = (Message) decrypt((SealedObject) inputstream.readObject());
            token = msg.getToken();
            //στην ουσία εδώ έχει τελειώσει το key agreement

            //διάβασμα του Session (I2P) String
            //πέρνουμε το destination string  απο τον server για να ξεκινήσει η επικοινωνία μέσω I2P
            Message session_msg = (Message) decrypt((SealedObject) inputstream.readObject());
            this.session = session_msg.getMessage();
            i2pclient = new I2PClient(this.session);

            //σύνδεση με τον σερβερ (i2p)
            i2pclient.accept();
            //μέσω GUI στέλνονται τα REGISTER/LOGIN

            this.i2p_ois = i2pclient.getI2PInputStream();
            this.i2p_oos = i2pclient.getI2POutputStream();
            
            AliceSipGUI gui = new AliceSipGUI(i2p_ois, i2p_oos, this.symmetricKey, this.iv, this.token, this.mac);
            gui.updateScreen("Connected to server!");

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
    //διαβάζουμε τα IV από το αρχείο

    private void reconstructIV() {
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
            Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
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
            Logger.getLogger(Alice.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
