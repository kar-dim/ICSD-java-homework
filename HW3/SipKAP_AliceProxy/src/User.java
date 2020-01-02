//Nikolaos Katsiopis icsd13076
//Dimitrios Karatzas icsd13072

import java.io.Serializable;

public class User implements Serializable {
    private String username;
    private final String contact; //της μορφης <sips:"username"@client.app.com>
    private String password; //password -> plaintext
    private String token;
    private String hmac;
    private String salt;
    private String hashed_password; //salted + hashed
    
    public User(String usern, String passw, String token, String hmac){
        this.username = usern;
        this.contact = "<sips:"+username+"@proxyA.com>";
        this.password = passw;
        this.token=token;
        this.hmac = hmac;
        this.hashed_password ="";
    }
    public User(String usern, String passw, String token, String hmac, String salt){
        this(usern,passw,token,hmac);
        this.salt=salt;
    }
    public String getUsername(){
        return username;
    }
    public String getPassword(){
        return password;
    }
    public void setSalt(String sal){
        this.salt = sal;
    }
    public void setHashedPassword(String pass){
        this.hashed_password = pass;
    }
    public void clearPassword(){
        this.password= "";
    }
    public String getHashedPassword(){
        return this.hashed_password;
    }
    public String getSalt(){
        return this.salt;
    }
    public String getContact(){
        return this.contact;
    }
    public String getHMAC() {
        return hmac;
    }
    public String getToken(){
        return token;
    }
    @Override
    public String toString(){
        return this.username + token;
    }
}
