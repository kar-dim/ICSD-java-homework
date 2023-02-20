/* Dimitris Karatzas icsd13072
   Nikolaos Katsiopis icsd13076
   Christos Papakostas icsd13143
 */
package sec3;

import java.awt.BorderLayout;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JFrame;

public class Main {

    private static byte[] original_bytes;

    public static void main(String[] args) {

        JFrame frame = new JFrame("ISEC 3");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
        MainMenu menu = new MainMenu();
        frame.add(menu, BorderLayout.CENTER);
        frame.pack();
        //Θερωούμε πως όταν ο χρήστης πατήσει το "Χ" τότε θα θέλει να κλείσει την εφαρμογή, άρα εδώ θα υπολογίσουμε τα hash των κρυπτογραφημένων αρχείων "expenses.dat" και "income.dat"
        //για τον logged_in χρήστη, στη συνέχεια θα υπογράψουμε ψηφιακά αυτά τα 2 αρχεία και θα αποθηκεύσουμε τη ψηφιακή υπογραφή στο αρχείο "signature.dat"
        frame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                try {
                    String path_with_slash = MainMenu.getLoggedInUsernamePath(); //π.χ "./dim_kar/"
                    //αν δεν έχει γίνει login δεν υπογράφουμε κάτι
                    if (path_with_slash != null) {
                        Signature sign = Signature.getInstance("SHA256withRSA"); //αντικείμενο υπογραφής
                        //πρέπει να υπογράψουμε τώρα, δεν χρησιμοποιούμε τον SHA-256 και μετά κρυπτογράφηση με RSA, αυτό γίνεται αυτόματα στην υπογραφή, το δηλώσαμε στο getInstance("SHA256withRSA");
                        sign.initSign(MainMenu.getPrivateKey());
                        //παίρνουμε τα bytes  των 2 αρχείων (expense,income), αν δεν υπάρχουν δε κάνουμε κάτι
                        boolean expense_file_exists = new File(path_with_slash + "expenses.dat").exists();
                        boolean income_file_exists = new File(path_with_slash + "income.dat").exists();
                        byte[] signature; //τα bytes της ψηφιακής υπογραφής
                        byte[] expense_bytes = null;
                        byte[] income_bytes = null;
                        //θα πάρουμε τα bytes όλου του αρχείου και θα τα υπογράψουμε
                        //προπσθέτουμε τα bytes προς υπογραφή, δεν υπογράφουμε ακόμα, θα υπογράψουμε μαζί με το αρχείο
                        //για τα έσοδα όλο μαζί, η άσκηση ζητάει να δημιουργήσουμε ζεύγη <filename,digest>, αλλά δεν υπάρχει κάποιος λόγος να το κάνουμε αυτό
                        //διότι τα αρχεία είναι 2 μόνο για τις συναλλαγές, απλώς βάζουμε τα bytes του 1ου και του 2ου και δημιουργουμε τη ψηφιακη υπογραφή
                        //για το σύνολο των 2 αρχείων, με αυτό τον τρόπο δε μπορούμε βέβαια να καταλάβουμε ποιο αρχείο τροποποιήθηκε αλλά λίγη σημασία έχει στη συγκεκριμένη άσκηση
                        if (expense_file_exists && income_file_exists) {

                            expense_bytes = Files.readAllBytes(new File(path_with_slash + "expenses.dat").toPath());
                            sign.update(expense_bytes);
                            income_bytes = Files.readAllBytes(new File(path_with_slash + "income.dat").toPath());
                            sign.update(income_bytes);
                            original_bytes = new byte[expense_bytes.length + income_bytes.length];
                            System.arraycopy(expense_bytes, 0, original_bytes, 0, expense_bytes.length);
                            System.arraycopy(income_bytes, 0, original_bytes, expense_bytes.length, income_bytes.length);
                        } else if (expense_file_exists && !income_file_exists) {
                            expense_bytes = Files.readAllBytes(new File(path_with_slash + "expenses.dat").toPath());
                            sign.update(expense_bytes);
                            original_bytes = new byte[expense_bytes.length];
                            System.arraycopy(expense_bytes, 0, original_bytes, 0, expense_bytes.length);
                        } else if (!expense_file_exists && income_file_exists) {
                            income_bytes = Files.readAllBytes(new File(path_with_slash + "income.dat").toPath());
                            sign.update(income_bytes);
                            original_bytes = new byte[income_bytes.length];
                            System.arraycopy(income_bytes, 0, original_bytes, 0, income_bytes.length);
                        }

                        else if (!income_file_exists && !expense_file_exists) {
                            System.exit(0);
                        }
                        signature = sign.sign();
                        //αποθήκευση στο αρχείο
                        FileOutputStream fos = new FileOutputStream(path_with_slash + "signature.dat");
                        fos.write(signature);
                        fos.flush();
                        fos.close();
                        //από αυτό το αρχείο η εφαρμογή μετά το Login θα πάρει τη ψηφιακή υπογραφή (χρησιμοποιόντας το privatekey της)
                    }
                } catch (NoSuchAlgorithmException | InvalidKeyException | IOException | SignatureException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
        });
    }

}
