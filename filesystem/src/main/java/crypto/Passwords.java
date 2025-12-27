package crypto;

import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.mindrot.jbcrypt.BCrypt;

// Argon2: dodaj zavisnost argon2-jvm (de.mkammerer:argon2-jvm:2.11)
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

public final class Passwords {

    private Passwords() {}

    private static final SecureRandom RNG = new SecureRandom();

    /** vrati string oblika "ALG|payload" za nasumicno izabrani algoritam od ovih PBKDF2, BCRYPT, ARGON2 */
    public static String hashForAnyRandom(String password) {
        int r = RNG.nextInt(3); 
        switch (r) {
            case 0:  return "BCRYPT|" + bcryptHash(password);
            case 1:  return "PBKDF2|" + pbkdf2Hash(password);    
            default: return "ARGON2|" + argon2Hash(password);   
        }
    }

    /** verifikuj lozinku na osnovu "ALG|payload" */
    public static boolean verify(String rawPassword, String algAndPayload) {
        int i = algAndPayload.indexOf('|');
        if (i <= 0) return false;
        String alg = algAndPayload.substring(0, i);
        String payload = algAndPayload.substring(i + 1);

        switch (alg) {
            case "BCRYPT":
                return BCrypt.checkpw(rawPassword, payload);
            case "PBKDF2":
                return verifyPbkdf2(rawPassword, payload);
            case "ARGON2":
                return verifyArgon2(rawPassword, payload);
            default:
                return false;
        }
    }

    // ---------- BCrypt ----------
    private static String bcryptHash(String password) {
        return BCrypt.hashpw(password, BCrypt.gensalt());
    }

    // ---------- PBKDF2 (HMAC-SHA256) ----------
    private static final int PBKDF2_ITER      = 120_000; 
    private static final int PBKDF2_SALT_LEN  = 16;
    private static final int PBKDF2_DK_LEN    = 32;      

    private static String pbkdf2Hash(String password) {
        byte[] salt = new byte[PBKDF2_SALT_LEN];
        RNG.nextBytes(salt);
        byte[] dk = pbkdf2(password.toCharArray(), salt, PBKDF2_ITER, PBKDF2_DK_LEN);
        return PBKDF2_ITER + "$" + b64(salt) + "$" + b64(dk);
    }

    private static boolean verifyPbkdf2(String raw, String payload) {
        String[] parts = payload.split("\\$");
        if (parts.length != 3) return false;
        int iter = Integer.parseInt(parts[0]);
        byte[] salt = b64d(parts[1]);
        byte[] dkStored = b64d(parts[2]);
        byte[] dkCalc = pbkdf2(raw.toCharArray(), salt, iter, dkStored.length);
        return constantTimeEquals(dkStored, dkCalc);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int dkLen) {
        try {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, dkLen * 8);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return skf.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("PBKDF2 error", e);
        }
    }

    // ---------- Argon2id (preko API sa char[]) ----------
    private static final int ARGON2_ITER = 3;        // broj prolaza
    private static final int ARGON2_MEM  = 1 << 15;  // 32 mb
    private static final int ARGON2_PAR  = 1;        // paralelizam

    private static String argon2Hash(String password) {
        Argon2 a = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        char[] pw = password.toCharArray();
        try {
            return a.hash(ARGON2_ITER, ARGON2_MEM, ARGON2_PAR, pw);
        } finally {
            a.wipeArray(pw);
        }
    }

    private static boolean verifyArgon2(String raw, String encoded) {
        Argon2 a = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id);
        char[] pw = raw.toCharArray();
        try {
            return a.verify(encoded, pw);
        } finally {
            a.wipeArray(pw);
        }
    }

    // ---------- pomocne metode ----------
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int r = 0;
        for (int i = 0; i < a.length; i++) r |= (a[i] ^ b[i]);
        return r == 0;
    }

    private static String b64(byte[] x) { return Base64.getEncoder().encodeToString(x); }
    private static byte[] b64d(String s) { return Base64.getDecoder().decode(s); }
    
}
