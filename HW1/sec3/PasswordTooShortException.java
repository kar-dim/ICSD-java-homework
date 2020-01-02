package sec3;

//μια απλή exception που εγείρεται όταν στο register ο χρήστης δώσει κωδικό <6 χαρακτήρες
public class PasswordTooShortException extends Exception {
    public PasswordTooShortException(String msg) {
        super(msg);
    }
    public PasswordTooShortException(){}
}