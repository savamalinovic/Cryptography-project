package crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javafx.stage.DirectoryChooser;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import com.main.FileTreeView;

public class FileCrypting {

    private static final int GCM_TAG_BITS = 128; 
    private static final int GCM_IV_BYTES = 12;  
    private static final String ENC_EXT = ".enc";
    private static final String WRAPPED_KEY_EXT = ".key.enc";

    private static final String EC_CURVE = "secp256r1";

    private static final String HKDF_HMAC = "HmacSHA256";
    private static final int KEK_LEN = 32; 
    
    private static final String SIGNATURE_EXT = ".sig";
    
	private static boolean isUnder(File base, File candidate) {
	    try {
	        String basePath = base.getCanonicalPath();
	        String candPath = candidate.getCanonicalPath();
	        return candPath.equals(basePath) || candPath.startsWith(basePath + File.separator);
	    } catch (IOException e) {
	        return false;
	    }
	}

    /* ---------- DEKRIPCIJA (i provjera integriteta) ---------- */

	public static void decryptFileUI(Stage stage, File encryptedFile) {
	    try {
	        File userKeysDir = new File(new File("keys"), FileTreeView.username);
	        String baseHashed = hashedBaseForEncFile(encryptedFile);

	        String base = encryptedFile.getName().substring(
	                0, encryptedFile.getName().length() - ENC_EXT.length());

	        File keyFile = new File(userKeysDir, baseHashed + WRAPPED_KEY_EXT);
	        File sigFile = new File(userKeysDir, baseHashed + SIGNATURE_EXT);

	        if (!sigFile.exists()) {
	            FileTreeView.error("Nedostaje digitalni potpis: " + sigFile.getPath());
	            return;
	        }
	        if (!keyFile.exists()) {
	            FileTreeView.error("Nedostaje ključ: " + keyFile.getPath());
	            return;
	        }

	        if (!verifySignatureForEncFile(encryptedFile, sigFile, FileTreeView.username)) {
	            FileTreeView.error("Potpis NE VAŽI – fajl je izmijenjen ili potpis nije od korisnika.");
	            return;
	        }

	        byte[] wrapped = Files.readAllBytes(keyFile.toPath());
	        SecretKey aesKey;
	        String header = sniffHeaderAscii(wrapped);

	        if ("RSA1".equals(header)) {

	            String payloadB64 = extractPayloadAfterHeader(wrapped);
	            byte[] rsaCt = Base64.getDecoder().decode(payloadB64);

	            PrivateKey rsaPriv = loadPrivateKeyFromPem(
	                    new File("certificates", FileTreeView.username + ".key"), "RSA");
	            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	            rsa.init(Cipher.DECRYPT_MODE, rsaPriv);

	            byte[] aesBytes = rsa.doFinal(rsaCt);
	            aesKey = new SecretKeySpec(aesBytes, "AES");

	        } else if ("ECC1".equals(header)) {

	            String[] parts = extractPayloadAfterHeader(wrapped).split("\\|");
	            if (parts.length != 3) {
	                FileTreeView.error("Neispravan ECC format ključa.");
	                return;
	            }
	            byte[] ephemPub = Base64.getDecoder().decode(parts[0]);
	            byte[] ivWrap   = Base64.getDecoder().decode(parts[1]);
	            byte[] ct       = Base64.getDecoder().decode(parts[2]);

	            PrivateKey ecPriv = loadPrivateKeyFromPem(
	                    new File("certificates", FileTreeView.username + ".ec.key"), "EC");

	            KeyFactory kf = KeyFactory.getInstance("EC");
	            PublicKey ephemPublicKey = kf.generatePublic(new X509EncodedKeySpec(ephemPub));
	            byte[] shared = ecdhSharedSecret(ecPriv, ephemPublicKey);

	            byte[] kek = hkdfSha256(shared, null, "kek-wrap".getBytes(StandardCharsets.UTF_8), KEK_LEN);

	            Cipher gcmWrap = Cipher.getInstance("AES/GCM/NoPadding");
	            gcmWrap.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"),
	                    new GCMParameterSpec(GCM_TAG_BITS, ivWrap));
	            byte[] aesBytes = gcmWrap.doFinal(ct);
	            aesKey = new SecretKeySpec(aesBytes, "AES");

	        } else {
	            PrivateKey rsaPriv = loadPrivateKeyFromPem(
	                    new File("certificates", FileTreeView.username + ".key"), "RSA");
	            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	            rsa.init(Cipher.DECRYPT_MODE, rsaPriv);
	            byte[] aesBytes = rsa.doFinal(wrapped);
	            aesKey = new SecretKeySpec(aesBytes, "AES");
	        }

	        try (InputStream in = new BufferedInputStream(new FileInputStream(encryptedFile))) {
	            byte[] ivFile = in.readNBytes(GCM_IV_BYTES);
	            if (ivFile.length != GCM_IV_BYTES) {
	                FileTreeView.error("Oštećen fajl: IV nedostaje.");
	                return;
	            }

	            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
	            gcm.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, ivFile));

	            FileChooser saver = new FileChooser();
	            saver.setInitialFileName(base);  
	            File outFile = saver.showSaveDialog(stage);
	            if (outFile == null) return;

	            try (CipherInputStream cis = new CipherInputStream(in, gcm);
	                 OutputStream out = new BufferedOutputStream(new FileOutputStream(outFile))) {
	                cis.transferTo(out);
	            }
	            FileTreeView.info("Fajl dekriptovan: " + outFile.getAbsolutePath());
	        }

	    } catch (java.io.FileNotFoundException e) {
	        e.printStackTrace();
	        FileTreeView.error("Nedostaje fajl: " + e.getMessage());
	    } catch (IOException e) {
	        if (e.getCause() instanceof javax.crypto.AEADBadTagException) {
	            FileTreeView.error("Integritet narušen (GCM tag ne važi).");
	        } else {
	            e.printStackTrace();
	        }
	    } catch (javax.crypto.AEADBadTagException e) {
	        e.printStackTrace();
	        FileTreeView.error("Integritet narušen (GCM tag ne važi).");
	    } catch (java.security.spec.InvalidKeySpecException | java.security.InvalidKeyException e) {
	        e.printStackTrace();
	        FileTreeView.error("Privatni ključ nije ispravan (format ili ključ ne odgovara).");
	    } catch (javax.crypto.BadPaddingException | javax.crypto.IllegalBlockSizeException e) {
	        e.printStackTrace();
	        FileTreeView.error("Neuspjela dekripcija ključa – pogrešan privatni ključ ili format.");
	    } catch (Exception ex) {
	        ex.printStackTrace();
	        FileTreeView.error("Greška pri dekripciji (pogledaj konzolu za detalje).");
	    }
	}


    /* ---------- ENKRIPCIJA  ---------- */

    public static void addFile(Stage stage) {
        try {
            FileChooser fc = new FileChooser();
            fc.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("Podržani fajlovi",
                    "*.txt", "*.pdf", "*.png", "*.jpg", "*.jpeg", "*.*"));
            File src = fc.showOpenDialog(stage);
            if (src == null)
                return;

            DirectoryChooser dc = new DirectoryChooser();
            Files.createDirectories(FileTreeView.userDir.toPath());
            dc.setInitialDirectory(FileTreeView.userDir);

            File targetDir;
            while (true) {
                targetDir = dc.showDialog(stage);
                if (targetDir == null) return; // korisnik odustao
                if (isUnder(FileTreeView.userDir, targetDir)) break;

                FileTreeView.error(
                    "Možeš birati samo unutar svog zaštićenog foldera:\n" + 
                    FileTreeView.userDir.getAbsolutePath()
                );
                // loop ponovo dok ne izabere ispravno ili otkaze
            }

            SecretKey aesKey;
            try {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(256);
                aesKey = kg.generateKey();
            } catch (Exception ignore) {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(128);
                aesKey = kg.generateKey();
            }

            byte[] fileIv = new byte[GCM_IV_BYTES];
            SecureRandom sr = SecureRandom.getInstanceStrong();
            sr.nextBytes(fileIv);

            Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
            gcm.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, fileIv));

            File encFile = new File(targetDir, src.getName() + ENC_EXT);
            try (InputStream in = new FileInputStream(src);
                 OutputStream out = new BufferedOutputStream(new FileOutputStream(encFile))) {

                out.write(fileIv);
                out.flush();

                try (CipherOutputStream cos = new CipherOutputStream(out, gcm)) {
                    in.transferTo(cos);
                }
            }

            PublicKey rsaPubFromCert = readUserPublicKeyFromCert(FileTreeView.username); // iz X.509
            PublicKey ecPubOptional = readUserEcPublicKeyIfExists(FileTreeView.username); // certificates/<user>.ecpub (ako postoji)

            boolean useECC = (ecPubOptional != null) && (SecureRandom.getInstanceStrong().nextBoolean());

            byte[] wrappedRecordBytes;
            if (useECC) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(EC_CURVE), SecureRandom.getInstanceStrong());
                KeyPair ephem = kpg.generateKeyPair();

                byte[] shared = ecdhSharedSecret(ephem.getPrivate(), ecPubOptional);

                byte[] kek = hkdfSha256(shared, null, "kek-wrap".getBytes(StandardCharsets.UTF_8), KEK_LEN);

                byte[] iv = new byte[GCM_IV_BYTES];
                SecureRandom.getInstanceStrong().nextBytes(iv);

                Cipher gcmWrap = Cipher.getInstance("AES/GCM/NoPadding");
                gcmWrap.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"),
                        new GCMParameterSpec(GCM_TAG_BITS, iv));
                byte[] ct = gcmWrap.doFinal(aesKey.getEncoded());

                String record = "ECC1|" +
                        Base64.getEncoder().encodeToString(ephem.getPublic().getEncoded()) + "|" +
                        Base64.getEncoder().encodeToString(iv) + "|" +
                        Base64.getEncoder().encodeToString(ct);
                wrappedRecordBytes = record.getBytes(StandardCharsets.US_ASCII);

            } else {
                Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                rsa.init(Cipher.ENCRYPT_MODE, rsaPubFromCert);
                byte[] rsaCt = rsa.doFinal(aesKey.getEncoded());

                String record = "RSA1|" + Base64.getEncoder().encodeToString(rsaCt);
                wrappedRecordBytes = record.getBytes(StandardCharsets.US_ASCII);
            }

            Files.createDirectories(Paths.get("keys", FileTreeView.username));
            String baseHashed = hashedBaseForEncFile(encFile);

            File wrappedKeyFile = new File(new File("keys", FileTreeView.username), baseHashed + WRAPPED_KEY_EXT);
            Files.write(wrappedKeyFile.toPath(), wrappedRecordBytes);

            File sigOut = new File(new File("keys", FileTreeView.username), baseHashed + SIGNATURE_EXT);
            signEncFile(encFile, FileTreeView.username, sigOut);

            FileTreeView.info("Fajl enkriptovan (AES-GCM), ključ umotan i potpisan:\n" + encFile.getAbsolutePath());
            FileTreeView.refreshTree();

        } catch (Exception ex) {
            ex.printStackTrace();
            FileTreeView.error("Greška pri dodavanju fajla.");
        }
    }

    /* ---------- Kljucevi / sertifikati ---------- */

    private static PublicKey readUserPublicKeyFromCert(String user) throws Exception {
        File certFile = new File("certificates", user + ".crt");
        try (FileInputStream fis = new FileInputStream(certFile)) {
            X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
            return cert.getPublicKey(); // očekujemo RSA key u tvom postojećem sistemu
        }
    }

    // Ako postoji EC javni kljuc u PEM ucitaj inace vrati null
    private static PublicKey readUserEcPublicKeyIfExists(String user) {
        try {
            File ecPubFile = new File("certificates", user + ".ecpub");
            if (!ecPubFile.exists()) return null;
            byte[] spki = readPem(ecPubFile, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
            KeyFactory kf = KeyFactory.getInstance("EC");
            return kf.generatePublic(new X509EncodedKeySpec(spki));
        } catch (Exception e) {
            return null;
        }
    }

    private static PrivateKey loadPrivateKeyFromPem(File pemFile, String algorithm) throws Exception {
        if (!pemFile.exists())
            throw new FileNotFoundException(pemFile.getAbsolutePath());
        byte[] der = readPem(pemFile, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        return KeyFactory.getInstance(algorithm).generatePrivate(spec);
    }

    private static byte[] readPem(File file, String begin, String end) throws IOException {
        String pem = Files.readString(file.toPath(), StandardCharsets.US_ASCII)
                .replace("\r", "");
        int i1 = pem.indexOf(begin);
        int i2 = pem.indexOf(end);
        if (i1 < 0 || i2 < 0) throw new IOException("Neispravan PEM: " + file);
        String b64 = pem.substring(i1 + begin.length(), i2).replace("\n", "").trim();
        return Base64.getDecoder().decode(b64);
    }

    /* ---------- ECDH i HKDF helperi ---------- */

    private static byte[] ecdhSharedSecret(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret();
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
        byte[] prk = hkdfExtract(salt, ikm);
        return hkdfExpand(prk, info, len);
    }

    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws Exception {
        Mac mac = Mac.getInstance(HKDF_HMAC);
        if (salt == null) {
            salt = new byte[mac.getMacLength()]; 
        }
        mac.init(new SecretKeySpec(salt, HKDF_HMAC));
        return mac.doFinal(ikm);
    }

    private static byte[] hkdfExpand(byte[] prk, byte[] info, int len) throws Exception {
        Mac mac = Mac.getInstance(HKDF_HMAC);
        mac.init(new SecretKeySpec(prk, HKDF_HMAC));
        byte[] out = new byte[len];
        byte[] t = new byte[0];
        int pos = 0;
        byte ctr = 1;
        while (pos < len) {
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update(ctr);
            t = mac.doFinal();
            int copy = Math.min(t.length, len - pos);
            System.arraycopy(t, 0, out, pos, copy);
            pos += copy;
            ctr++;
        }
        return out;
    }
    
    
    private static void signEncFile(File encFile, String username, File sigOut) throws Exception {
        File ecPrivFile = new File("certificates", username + ".ec.key");
        Signature signature;

        if (ecPrivFile.exists()) {
            PrivateKey ecPriv = loadPrivateKeyFromPem(ecPrivFile, "EC");
            signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(ecPriv);
            byte[] sig = signStream(signature, encFile);
            String payload = "SIG1|ECDSA|" + Base64.getEncoder().encodeToString(sig);
            Files.writeString(sigOut.toPath(), payload, StandardCharsets.US_ASCII);
        } else {
            PrivateKey rsaPriv = loadPrivateKeyFromPem(new File("certificates", username + ".key"), "RSA");
            signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(rsaPriv);
            byte[] sig = signStream(signature, encFile);
            String payload = "SIG1|RSA|" + Base64.getEncoder().encodeToString(sig);
            Files.writeString(sigOut.toPath(), payload, StandardCharsets.US_ASCII);
        }
    }

    private static byte[] signStream(Signature signature, File file) throws Exception {
        try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
            byte[] buf = new byte[8192];
            int r;
            while ((r = in.read(buf)) != -1) {
                signature.update(buf, 0, r);
            }
            return signature.sign();
        }
    }


    
 // Vrati true ako potpis vazi i koristi cert (RSA) ili ecpub (ECDSA) zavisno od headera
    private static boolean verifySignatureForEncFile(File encFile, File sigFile, String username) {
        try {
            String s = Files.readString(sigFile.toPath(), StandardCharsets.US_ASCII).trim();
            if (!s.startsWith("SIG1|")) return false;
            String[] parts = s.split("\\|");
            if (parts.length != 3) return false;
            String alg = parts[1];
            byte[] sigBytes = Base64.getDecoder().decode(parts[2]);

            Signature verifier;

            if ("RSA".equals(alg)) {
                // javni kljuc iz korisnickog certifikata
                PublicKey rsaPub = readUserPublicKeyFromCert(username);
                verifier = Signature.getInstance("SHA256withRSA");
                verifier.initVerify(rsaPub);
            } else if ("ECDSA".equals(alg)) {
                // EC javni kljuc iz certificates/user.ecpub
                PublicKey ecPub = readUserEcPublicKeyIfExists(username);
                if (ecPub == null) return false;
                verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(ecPub);
            } else {
                return false;
            }

            try (InputStream in = new BufferedInputStream(new FileInputStream(encFile))) {
                byte[] buf = new byte[8192];
                int r;
                while ((r = in.read(buf)) != -1) {
                    verifier.update(buf, 0, r);
                }
            }
            return verifier.verify(sigBytes);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }



    /* ---------- Wrap header helperi ---------- */

    private static String sniffHeaderAscii(byte[] data) {
        String s = new String(data, 0, Math.min(data.length, 8), StandardCharsets.US_ASCII);
        if (s.startsWith("RSA1|")) return "RSA1";
        if (s.startsWith("ECC1|")) return "ECC1";
        return null;
    }

    private static String extractPayloadAfterHeader(byte[] data) {
        String s = new String(data, StandardCharsets.US_ASCII);
        int pipe = s.indexOf('|');
        if (pipe < 0) return "";
        return s.substring(pipe + 1);
    }
    
    
    private static String safeRelativeUnix(File baseDir, File child) {
        try {
            File baseCan = baseDir.getCanonicalFile();
            File childCan = child.getCanonicalFile();
            String basePath = baseCan.getPath();
            String childPath = childCan.getPath();

            if (!childPath.equals(basePath) && !childPath.startsWith(basePath + File.separator)) {
                return child.getName();
            }

            Path baseP = baseCan.toPath();
            Path childP = childCan.toPath();
            Path rel = baseP.relativize(childP);
            return rel.toString().replace(File.separatorChar, '/');
        } catch (IOException e) {
            return child.getName();
        }
    }

    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String hashedBaseForEncFile(File encFile) {
        String baseName = encFile.getName();
        if (baseName.endsWith(ENC_EXT)) {
            baseName = baseName.substring(0, baseName.length() - ENC_EXT.length());
        }
        String relUnix = safeRelativeUnix(com.main.FileTreeView.userDir, encFile);
        String hash = sha256Hex(relUnix);
        return hash + "-" + baseName;
    }

    
}
