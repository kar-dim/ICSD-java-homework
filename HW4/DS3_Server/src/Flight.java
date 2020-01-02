/* Dimitris Karatzas icsd13072
   Apostolos Lazaros icsd13096
 */
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

//απλή κλάση που αναπαριστά μια πτήση
public class Flight implements Serializable {

    private final int MAX_SEATS_CAPACITY = 250; //η τιμή αυτή δείχνει το μέγιστο όριο χωρητικότητας για κάθε πτήση. Κανονικά είναι μεταβλητή αλλά έτσι θα χρειαζόμασταν μια άλλη
    //κλάση για αεροπλάνο που να θέταμε εκεί τη συγκεκριμένη χωρητικότητα αλλά θεωρήσαμε πως δεν είναι απαραίτητο
    private int id;
    private ArrayList<Reservation> reservations; //η δομή που κρατάει τις κρατήσεις για τη συγκεκριμένη πτήση
    private String start;
    private String dest;
    private final int seats[]; //οι θέσεις
    private double cost;
    private Date date;
    boolean is_reserved[]; //για κάθε θέση κρατάμε πληροφορία για το αν είναι δεσμευμένη

    public Flight(int id, String start, String dest, double cost, Date date, ArrayList<Reservation> reservs) {
        this.is_reserved = new boolean[MAX_SEATS_CAPACITY];
        this.reservations = new ArrayList<>(reservs);
        //έλεγχος των θέσεων, για κάθε κράτηση θέτουμε true στην αντίστοιχη θέση του is_reservated,
        //ανάλογα με τις θέσεις που έχει επιλέξει ο πελάτης
        for (int i=0; i<this.reservations.size(); i++){
            for (int j=0; j<this.reservations.get(i).getReservatedSeats().length; j++){
                is_reserved[this.reservations.get(i).getReservatedSeats()[j]] = true;
            }
        }
        this.id = id;
        this.start = start;
        this.dest = dest;
        this.seats = new int[MAX_SEATS_CAPACITY];
        for (int i=0; i<seats.length; i++)
            seats[i]=i;
        this.cost = cost;
        this.date = date;

    }

    //getters
    public int getId() {
        return this.id;
    }

    public String getStart() {
        return this.start;
    }

    public String getDestination() {
        return this.dest;
    }

    public double getCost() {
        return this.cost;
    }

    public Date getDate() {
        return this.date;
    }

    public ArrayList<Reservation> getReservations() {
        return this.reservations;
    }

    //setters
    public void setId(int id) {
        this.id = id;
    }

    public void setStart(String start) {
        this.start = start;
    }

    public void setDestination(String dest) {
        this.dest = dest;
    }

    public void setCost(int cost) {
        this.cost = cost;
    }

    public void setDate(Date date) {
        this.date = date;
    }

    //προσθήκη κράτησης, θέτουμε σε κάθε θέση της κράτησης TRUE για τη συγκεκριμένη πτήση
    // π.χ θεσεις πτησης: [οχι,οχι,οχι,οχι...] και θεσεις κρατησης:[0,2,3] αρα οι θεσεις πτησεις διαμορφωνονται ως εξης -> [ναι,οχι,ναι,ναι,οχι...]
    public void addReservation(String name, String lname, int[] seats) {
        reservations.add(new Reservation(name, lname, seats));
        //θέτουμε true τις θέσεις που έχουν κάποια κράτηση
        for (int i = 0; i < seats.length; i++) {
            for (int j=0; j< MAX_SEATS_CAPACITY; j++){
                if (seats[i] == this.seats[j]){
                    is_reserved[j]=true;
                }
            }
        }
    }

    //επιστρέφει true αν η θέση είναι πιασμένη, αλλιώς false
    public boolean isSeatReservated(int len) throws ExceededSeatCapacityException {
        if (len > MAX_SEATS_CAPACITY || len <= 0) {
            throw new ExceededSeatCapacityException();
        }
        return this.is_reserved[len];
    }
    //επιστρέφει τον πίνακα με τις θέσεις που δεν είναι δεσμευμένες
    public int[] getNonReservedSeats(){
        ArrayList<Integer> list= new ArrayList<>();
        for (int i=0; i<is_reserved.length; i++){
            if (is_reserved[i]==false){
                list.add(seats[i]);
            }
        }
        int [] new_list = new int[list.size()];
        for (int i=0; i<list.size();i++){
            new_list[i]=list.get(i);
        }
        Arrays.sort(new_list);
        return new_list;
        
    }
    //toString() -> εμφανίζει τα πάντα σχετικά με τη κλάση, ενώ η displayFlightData() εμφανίζει μόνο όσα ζητούνται (για το 1η επιλογή "έλεγχος διαθεσιμότητας" )
    @Override
    public String toString() { 
        return "ID: " + id + "\nStart city: " + start + "\nDestination city: " + dest + "\nSeats Capacity: " + seats.length + "\nTicket Cost: " + cost + "\nDate: " + date + "\n";
    }
  //εδώ υπολογίζονται και οι διαθέσιμες θέσεις, απλώς μετράμε τις θέσεις του is_reserved πίνακα που έχουν τιμή false
    public String displayFlightData() {
        int count=0;
        for (int i=0; i<is_reserved.length; i++){
            if (is_reserved[i]==false)
               count++;
        }
        int hours = date.getHours();
        int minutes = date.getMinutes();
        //επειδή τα getHours() και getMinutes() αν η τιμή είναι 0 επιστρέφουν 0, εμείς θέλουμε η ώρα να φαίνεται με 2 ψηφία (π.χ 18:00 και όχι 18:0 ή 00:30 και όχι 0:30)
        if (hours==0 && minutes!=0){
            return "ID: " + id + "\nAvailable Seats: " + count+ "\nTicket Cost: " + cost + "\nTime: " + "0"+ hours +":"+ minutes + "\n";
        }
        else if (hours==0 && minutes==0){
            return "ID: " + id + "\nAvailable Seats: " + count+ "\nTicket Cost: " + cost + "\nTime: " + "0"+ hours +":"+ "0"+minutes + "\n";
        }
        else if (hours!=0 && minutes==0){
            return "ID: " + id + "\nAvailable Seats: " + count+ "\nTicket Cost: " + cost + "\nTime: " + hours +":"+ "0"+minutes + "\n";
        }
        else {
            return "ID: " + id + "\nAvailable Seats: " + count+ "\nTicket Cost: " + cost + "\nTime: " + hours +":"+ minutes + "\n";
        }    
    }
}
