/* icsd13072 Karatzas Dimitris
   icsd13096 Lazaros Apostolos*/
import java.util.Date;
import javax.swing.table.DefaultTableModel;

//μοντέλο πίνακα, απαραίτητο ώστε να θέσουμε τα checkboxes και τα text fields των ανακοινώσεων να είναι editable μόνο
class TableModel extends DefaultTableModel {

    TableModel(int rows, int cols) { // constructor
        super(rows, cols);
        this.setColumnIdentifiers( new String[]{"Check to delete", "Announcement", "Last Edit Date"});
    }

    @Override
    //μόνο τα checkboxes μπορούμε να αλλάζουμε καθώς επίσης και το όνομα της ανακοίνωσης (για το Update)
    public boolean isCellEditable(int row, int column) { 
        return (column==0 || column==1);
    }
    
    @Override
    public Class<?> getColumnClass(int columnIndex) {
      Class cl = String.class;
      if (columnIndex==0)
          cl = Boolean.class;
      else if (columnIndex==2){
          cl = String.class;
      }
      else if (columnIndex==3){
          cl = Date.class;
      }
      return cl;
    }
}