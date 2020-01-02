/* Dimitris Karatzas icsd13072
   Apostolos Lazaros icsd13096
*/

import java.io.Serializable;

//κλάση που αναπαριστά μια κράτηση
public class Reservation implements Serializable{
    private final String passenger_name;
    private final String passenger_last_name;
    private int[] seats; //seats -> οι θέσεις που δεσμεύει ο συγκεκριμένος πελάτης (μπορεί ο ίδιος να δεσμεύσει παραπάνω από 1 θέση)
    //εδώ έχουμε κάνει μια παραδοχή: Ο πελάτης δεσμεύει τις υπόλοιπες θέσεις (πέρα από τη δικιά του) στο δικό του όνομα και όχι στο όνομα των πελατών
    //που θα καθίσουν σε αυτές
    public Reservation(String c_name, String c_l_name, int [] seats){
        this.passenger_name=c_name;
        this.passenger_last_name=c_l_name;    
        this.seats = new int[seats.length];
        for (int i=0; i<seats.length; i++)
            this.seats[i]=seats[i];
    }
 
    //getters
    public String getPassengerName(){
        return this.passenger_name;
    }
    public String getPassengerLastName(){
        return this.passenger_last_name;
    }
    public int[] getReservatedSeats(){
        return this.seats;
    }
    
    //εμφανίζει τα δεδομένα της συγκεκριμένης κράτησης, στην ουσία τις θέσεις που έχει δεσμεύσει ο χρήστης
    @Override
    public String toString(){
        String return_str="";
        for (int i=0; i<this.seats.length; i++){
            return_str+=String.valueOf(this.seats[i])+", ";
        }
        return "Your reserved seats: "+return_str;
    }
}
