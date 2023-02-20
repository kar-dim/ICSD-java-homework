/* icsd13072 Karatzas Dimitris
   icsd13096 Lazaros Apostolos*/
import java.io.Serializable;
import java.util.Date;

//κλάση για μια ανακοίνωση
public class Announcement implements Serializable{
    private String announcement; //η ανακοίνωση είναι αυτό το string
    private String author; //ποιός έκανε την ανακοίνωση, username
    private Date last_edit;
    public Announcement(String announce, String auth, Date dat){
        announcement=announce;
        author=auth;
        last_edit = dat;
    }
    public Announcement(Announcement announce){
        announcement=announce.getAnnouncement();
        author=announce.getAuthor();
        last_edit = announce.getLastEditDate();
    }
    //setters και getters
    public void setAnnouncement(String announce){  announcement=announce;  }
    public void setAuthor(String auth){ author=auth; }
    public String getAuthor(){ return author; }
    public String getAnnouncement() { return announcement; }
    public Date getLastEditDate() {return last_edit; }
    public void setLastEditDate(Date date){ last_edit = date;}
    @Override
    public String toString(){
        return "Author: "+author + "\nAnnouncement: "+announcement+"\nLast Edit: "+last_edit.toString()+"\n\n";
    }
}
