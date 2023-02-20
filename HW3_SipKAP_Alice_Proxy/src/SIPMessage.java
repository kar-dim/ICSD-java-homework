//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.Serializable;

public class SIPMessage implements Serializable {

    //Στα SIP fields, έχουμε βάλει κάποια standard fields πχ Max-Forwards: 70
    private String type;
    private String header;
    private final String content_type = "application/sdp";
    private String content_length;
    private final String from; //της μορφης -> sip:alice@client.app.com
    private final String to;
    private String via;
    private String contact;
    private String token;
    private final String nax_forwards = "Max-Forwards: 70";
    private String hmac;
    private String dest_string;

    public SIPMessage(String msg_type, String sender, String receiver, String tok, String hmac) {
        this.from = sender;
        this.type = msg_type;
        this.contact = sender + ";transport=tcp>";
        this.to = receiver;
        //για κάθε τύπο μηνυμάτον βάζουμε τις κατάλληλές τιμές στα fields
        //αν δε βάλουμε τίποτα τότε οι τιμές έχουν τιμή null αφού δε θα έχουν αρχικοποιηθεί
        if (msg_type.equals(Sip.INVITE)) {
            header = "INVITE " + receiver + " SIP/2.0";
        } else if (msg_type.equals(Sip.REGISTER)) {
            header = "REGISTER" + receiver + " SIP/2.0";
        } else if (msg_type.equals(Sip.ACK)) {
            header = "ACK " + receiver + " SIP/2.0";
        } else if (msg_type.equals(Sip.TRYING)) {
            header = "SIP/2.0 100 TRYING";
        } else if (msg_type.equals(Sip.OK)) {
            header = "SIP/2.0 200 OK";
        } else if (msg_type.equals(Sip.BAD_REQUEST)) {
            header = "SIP/2.0 400 Bad Request";
        } else if (msg_type.equals(Sip.UNAUTHORIZED)) {
            header = "SIP/2.0 401 Unauthorized";
        } else if (msg_type.equals(Sip.RINGING)) {
            header = "SIP/2.0 180 RINGING";
        } else if (msg_type.equals(Sip.BYE)) {
            header = "BYE" + receiver + " SIP/2.0";
        } else if (msg_type.equals("")) {
            
        }
        this.token = tok;
        this.hmac = hmac;
    }

    //i2p dest = το i2p destination string
    public SIPMessage(String msg_type, String sender, String receiver, String tok, String hmac, String i2p_dest) {
        this(msg_type, sender, receiver, tok, hmac);
        dest_string = i2p_dest;
    }
    //setter
    public void setHMAC(String hmac) {
        this.hmac = hmac;
    }
    public void setToken(String tok){
        this.token = tok;
    }

    //getters
    public String getType() {
        return type;
    }

    public String getToken() {
        return token;
    }

    public String getHMAC() {
        return hmac;
    }

    public String getHeader() {
        return this.header;
    }

    public String getContentType() {
        return this.content_type;
    }

    public String getContentLength() {
        return this.content_length;
    }

    public String getTo() {
        return this.to;
    }

    public String getFrom() {
        return this.from;
    }

    public String getVia() {
        return this.via;
    }
    public String getDestinationString(){
        return this.dest_string;
    }
    //χρησιμοποιείται για έλεγχο
    @Override
    public String toString() {
        return type  + header  + content_type +  content_length  + from  + via  + to  + token;
    }
}
