//Dimitrios Karatzas icsd13072
//Nikolaos Katsiopis icsd13076

import java.security.SecureRandom;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;

public class TokenGenerator {
    //κλάση που παράγει το τυχαίο token
    public String generateToken() {
        for (int i = 0; i < buf.length; ++i) {
            buf[i] = symbols[random.nextInt(symbols.length)];
        }
        return new String(buf);
    }

    public static final String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static final String lower = upper.toLowerCase(Locale.ROOT);

    public static final String digits = "0123456789";

    public static final String alphanum = upper + lower + digits;

    private final Random random;

    private final char[] symbols;

    private final char[] buf;

    //Overloaded constructors οι οποίοι καλούν ο ένας τον άλλον
    public TokenGenerator(int length, Random random, String symbols) {
        if (length < 1) {
            throw new IllegalArgumentException();
        }
        if (symbols.length() < 2) {
            throw new IllegalArgumentException();
        }
        this.random = Objects.requireNonNull(random);
        this.symbols = symbols.toCharArray();
        this.buf = new char[length];
    }

    // καλεί τον constructor που παράγει εν τέλει το random session identifier
    public TokenGenerator(int length, Random random) {
        this(length, random, alphanum);
    }

    //δημιουργεί το session identifier με μήκος 21
    public TokenGenerator(int length) {
        this(length, new SecureRandom());
    }

    // Δημιουργεί Session identifiers
    public TokenGenerator() {
        this(21);
    }
}
