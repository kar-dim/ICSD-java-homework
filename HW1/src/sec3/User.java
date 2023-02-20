/* Dimitris Karatzas icsd13072
   Nikolaos Katsiopis icsd13076
   Christos Papakostas icsd13143
 */

package sec3;

import java.io.Serializable;

//η κλάση για έναν χρήστη, ο κωδικός αποθηκεύεται ως byte[] διότι είναι κρυπτογραφημένος (και hashed)
public class User implements Serializable {

    private String name, lname, username, salt, pathname;
    private final byte[] encrypted_password;

    public User(String user, byte[] pass, String nam, String lnam, String sal, String path) {
        this.username = user;
        encrypted_password = new byte[pass.length];
        for (int i = 0; i < pass.length; i++) {
            encrypted_password[i] = pass[i];
        }
        this.name = nam;
        this.lname = lnam;
        this.salt = sal;
        this.pathname = path;
    }
    //getters
    public String getUsername() {
        return username;
    }

    public byte[] getPassword() {
        return encrypted_password;
    }

    public String getName() {
        return name;
    }

    public String getLname() {
        return lname;
    }

    public String getSalt() {
        return salt;
    }

    //setters
    public void setUsername(String user) {
        username = user;
    }

    public void setPassword(byte[] pass) {
        for (int i = 0; i < pass.length; i++) {
            encrypted_password[i] = pass[i];
        }
    }

    public void setName(String nam) {
        name = nam;
    }

    public void setLname(String lnam) {
        lname = lnam;
    }

    public void setSalt(String sal) {
        this.salt = sal;
    }
    public void setPathName(String path){
        this.pathname=path;
    }
}
