/* Dimitris Karatzas icsd13072
   Nikolaos Katsiopis icsd13076
   Christos Papakostas icsd13143
 */
package sec3;
//απλή κλάση που κληρονομείται από τις 2 κλάσεις για έσοδα/έξοδα, είναι abstract διότι δε δημιουργούμε αντικείμενα της
//ορίζουμε μια φορά τη κλάση αυτή και μετά οι άλλες 2 απλώς κάνουν extend

import java.io.Serializable;
import java.util.Calendar;
import java.util.Date;

public abstract class IncomeExpense implements Serializable{
    double value;
    String description;
    Date date;
    public IncomeExpense(double value, String description, Date date){
        this.value=value;
        this.description=description;
        this.date=date;
    }
    //setters/getters
    Date getTransactionDate(){
        return this.date;
    }
    String getDescription(){
        return this.description;
    }
    double getValue(){
        return this.value;
    }
    //ιανουαριος=0, φεβρουαριος=1,.....δεκεμβρης=11
    int getMonth(){
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(this.date);
        return calendar.get(Calendar.MONTH);
    }
    void setTransactionDate(Date date){
        this.date=date;
    }
    void setDescription(String desc){
        this.description=desc;
    }
    void setValue(double value){
        this.value=value;
    }
    @Override
    public abstract String toString();
}
