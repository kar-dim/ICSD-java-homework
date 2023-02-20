/* icsd13072 Karatzas Dimitris
   icsd13096 Lazaros Apostolos*/

//η κλάση για τον χρήστη

import java.io.Serializable;

public class User implements Serializable {
    private String password;
    private String username;
    private String name;
    private String lname;
    //κανονικός constructor
    public User(String user, String pass, String nam, String lnam){
        username=user;  password=pass;  name=nam;   lname=lnam;
    }
    //constructor για αρχικοποίηση με βάση άλλον χρήστη
    public User(User usr){
        password=usr.getPassword();
        username=usr.getUsername();
        name=usr.getName();
        lname= usr.getLname();
    }
    //constructor που χρησιμοποιείται μόνο για έλεγχο username και password (login)
    public User(String user, String pass){
        username=user;  password=pass;
    }
    public void setPassword(String pass){password=pass;}
    public void setUsername(String user){username=user;}
    public void setName(String nam){name=nam;}
    public void setLName(String lnam){lname=lnam;}
    public String getUsername(){return username; }
    public String getPassword(){return password; }
    public String getName(){return name; }
    public String getLname(){return lname; }
}