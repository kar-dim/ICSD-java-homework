/* Dimitris Karatzas icsd13072
   Nikolaos Katsiopis icsd13076
   Christos Papakostas icsd13143
 */

package sec3;

import java.io.Serializable;
import java.util.Date;
//κλάση για έσοδα, απλώς κάνει override τη toString
public class Income extends IncomeExpense implements Serializable{

    public Income(double value, String description, Date date) {
        super(value, description, date);
    }

    @Override
    public String toString() {
       return "Type: Income\nTransaction Date: "+this.date.toString()+"\nValue: "+this.value+"\nDescription:"+this.description;
    }
    
}
