//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.Serializable;

public class Message implements Serializable {

    private final String message;
    private final String token;
    private String hmac;

    public Message(String msg, String tok, String hmac) {
        this.message = msg;
        this.token = tok;
        this.hmac = hmac;
    }

    public String getMessage() {
        return message;
    }

    public String getToken() {
        return token;
    }

    public String getHMAC() {
        return hmac;
    }

    public void setHMAC(String hmac) {
        this.hmac = hmac;
    }

    //χρησιμοποιείται για έλεγχο
    @Override
    public String toString() {
        return message + token;
    }
}
