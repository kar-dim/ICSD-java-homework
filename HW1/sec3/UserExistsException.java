/* Dimitris Karatzas icsd13072
   Nikolaos Katsiopis icsd13076
   Christos Papakostas icsd13143
 */
package sec3;
//μια απλή exception που εγείρεται όταν στο register υπάρχει ήδη χρήστης με κάποιον ήδη registered χρήστη
public class UserExistsException extends Exception {
    public UserExistsException(String msg) {
        super(msg);
    }
    public UserExistsException(){}
}
