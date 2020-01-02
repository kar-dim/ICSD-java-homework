//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AliceProxy extends AliceProxyEncryptedConnection implements Runnable {

    public AliceProxy(Socket connection, ObjectOutputStream outputstream, ObjectInputStream inputstream, String mode) {
        this.mode = mode;
        this.connection = connection;
        this.outputstream = outputstream;
        this.inputstream = inputstream;
        
        Security.addProvider(new BouncyCastleProvider());
        System.setProperty("javax.net.ssl.trustStore", "keystores/truststorePRX1");
        try {
            super.loadKeyStore("keystores/keystorePRX1", "proxypassword1".toCharArray(), "keystore"); //φορτώνουμε το keystore
            super.loadKeyStore("keystores/truststorePRX1", "password1".toCharArray(), "truststore"); //φορτώνουμε το truststore
            this.privkey = this.getPrivateKey("proxy1", "proxypassword1");
        } catch (KeyStoreException | CertificateException ex) {
            System.err.print("Keystore error!");
            System.exit(-1); //σοβαρό security πρόβλημα!
        } catch (IOException ex) {
            Logger.getLogger(AliceProxy.class.getName()).log(Level.SEVERE, null, ex);
        }catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AliceProxy.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void run() {
        try {
            //διαβασμα των IV parameters
            reconstructIV();
            if (this.mode.equals("RSA")) {
                this.whileConnected("RSA", "client", "keys\\skey_client.key", this.outputstream, this.inputstream, false, true);
            } else {
               // this.generateParameters(true, true); //τα p,g τα στέλνει ο client! εδώ παράγουμε τα p2,g2 που χρησιμοποιεί ο proxy όταν καλεί τον άλλον proxy
                //δηλαδή όταν είναι σε λειτουργία "client" o proxy πρέπει να παράγει τα δικά του keypair
                this.whileConnected("STS", "client", "keys\\skey_client.key", this.outputstream, this.inputstream, false, true);
            }
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException ex) {
            System.err.println("An error occured\nExiting session.....");
        }
    }
}
