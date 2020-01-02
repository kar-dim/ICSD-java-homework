//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

//κλάση που υλοποιεί τις κοινές μεθόδους για τις κλάσεις client/server
public abstract class BobEncryptedConnection {

    protected SecureRandom random;
    protected PrivateKey privkey;
    protected SecretKey symmetricKey;
    protected String token;
    protected IvParameterSpec iv;
    protected Mac mac;
    protected Socket connection;
    protected ObjectInputStream inputstream;
    protected ObjectOutputStream outputstream;
    protected KeyStore keystore;
    protected KeyStore truststore;

    //μέθοδος για encrypt ενός μηνύματος
    protected SealedObject encrypt(String msg) {
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
    
    //μέθοδος για encrypt ενός SIP Message
    protected SealedObject encryptSip(SIPMessage msg) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, this.symmetricKey, this.iv);
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

    //μέθοδος για decrypt
    protected Object decrypt(SealedObject sobj) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, this.symmetricKey, this.iv);
            return sobj.getObject(cipher);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | ClassNotFoundException | IllegalBlockSizeException | BadPaddingException ex) {
            System.err.println("Decryption error");
            this.closeConnection();
            System.exit(-1);
        } catch (IOException ioe) {
            System.err.println("Could not decrypt the message");
            this.closeConnection();
            System.exit(-1);
        }
        return null;
    }

    //sign με HMAC
    protected String HMAC_Sign(String data) {
        return javax.xml.bind.DatatypeConverter.printBase64Binary(mac.doFinal(data.getBytes()));
    }
    
    //κλείνει τη σύνδεση
    protected void closeConnection() {
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
            Logger.getLogger(BobEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException | CertificateException ex) {
            System.err.println("Could not verify the certificate! Possibly dangerous condition\nExiting session...");
            closeConnection();
            System.exit(-1);
            Logger.getLogger(BobEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
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

    //παράγει τα RSA keys, αυτά τα παίρνουμε από αρχεία (keystoreCL1 για "server" και keystoreCL2 για client)
    protected PrivateKey getPrivateKey(String username, String password) throws NoSuchAlgorithmException {
        try {
            //extract το private key μας
            privkey = (PrivateKey) keystore.getKey(username, password.toCharArray());
            //επιστροφή του private key
            return privkey;
        } catch (KeyStoreException | UnrecoverableKeyException ex) {
            Logger.getLogger(Bob.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
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
            Logger.getLogger(BobEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    //παραγωγή της HMAC
    protected void initializeHMACs() {
        try {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(this.symmetricKey.getEncoded(), "HMACSHA256"));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(BobEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(BobEncryptedConnection.class.getName()).log(Level.SEVERE, null, ex);
        }
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

    //μέθοδος που ελέγχει το HMAC αλλά και το token
    protected void checkMessage(Message msg_received) throws ConnectionNotSafeException {
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
    }
    
    //το ίδιο αλλά για ένα SIP μήνυμα
     protected void checkSipMessage(SIPMessage msg_received) throws ConnectionNotSafeException {
        String hmac_check = msg_received.getHMAC();
        //έλεγχος του hmac του μηνύματος
        if (!hmac_check.equals(this.HMAC_Sign(msg_received.getFrom()+ msg_received.getToken()))) {
            throw new ConnectionNotSafeException("Your connection is not secure!");
        }
        String hash = SHA256_Hash(msg_received.getFrom()+ msg_received.getToken());
        if (!hash.equals(SHA256_Hash(msg_received.getFrom() + token))) {
            //άλλαξε το token = replay attack!
            throw new ConnectionNotSafeException("Your connection is not secure!");
        }
    }
    
    //encrypt ενός User αντικειμένου
    protected SealedObject encryptUser(String username, String password) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, symmetricKey, this.iv);
            User user = new User(username, password, this.token, this.HMAC_Sign(username + this.token));
            return new SealedObject(user, cipher);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException ex) {
            System.err.println("Encryption error");
            System.exit(-1);
        } catch (IOException ioe) {
            System.err.println("Could not send the message");
            System.exit(-1);
        }
        return null;
    }
}
