
//εγείρεται όταν ο χρήστης βάλει λάθος τιμή για δέσμευση θέσης (ένα αεροπλάνο το έχουμε θέσει ότι έχει 250 θέσεις, αν ο χρήστης βάλει μικρότερη του 0, ίση με το 0, ή >max τιμής
//τότε εγείρεται το exception
class ExceededSeatCapacityException extends Exception {

    public ExceededSeatCapacityException() {
    }
    
}
