/* Dimitris Karatzas icsd13072
   Nikolaos Katsiopis icsd13076
   Christos Papakostas icsd13143
 */

package sec3;

import java.io.Serializable;
import java.util.Date;
//κλάση για έξοδα, απλώς κάνει override τη toString
public class Expense extends IncomeExpense implements Serializable{

    public Expense(double value, String description, Date date) {
        super(value, description, date);
    }

    @Override
    public String toString() {
       return "Type: Expense\nTransaction Date: "+this.date.toString()+"\nValue: "+this.value+"\nDescription:"+this.description;
    }
    
}
