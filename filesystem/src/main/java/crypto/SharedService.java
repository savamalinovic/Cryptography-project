package crypto;

import com.main.FileTreeView;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonType;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

public final class SharedService {

	private SharedService() {}

	private static final String ENC_EXT = ".enc";
	private static final String WRAPPED_KEY_EXT = ".key.enc";
	private static final String SIGNATURE_EXT = ".sig";
	private static final String SHARED_DIR = "shared";
	private static final String SHARED_META_DIR = "shared_metadata";
	private static final String KEYS_ROOT = "keys";

	private static final int GCM_TAG_BITS = 128;
	private static final int GCM_IV_BYTES = 12;
	private static final int KEK_LEN = 32; 
	private static final String HKDF_HMAC = "HmacSHA256";
	private static final String EC_CURVE = "secp256r1"; 


	public static void shareFile(Stage stage, File senderEncFile, String sender, String recipient) {
		try {
			if (senderEncFile == null || !senderEncFile.isFile() || !senderEncFile.getName().endsWith(ENC_EXT)) {
				FileTreeView.error("Odaberi enkriptovani fajl (.enc) iz svog foldera.");
				return;
			}

			File senderRoot = new File("efs", sender);
			if (!isUnder(senderRoot, senderEncFile)) {
				FileTreeView.error("Možeš dijeliti samo fajlove iz svog korisničkog foldera.");
				return;
			}

			// ne dijeli samom sebi
			if (sender.equals(recipient)) {
				FileTreeView.error("Ne možeš dijeliti fajl samom sebi.");
				return;
			}

			Files.createDirectories(Paths.get(SHARED_DIR));
			Files.createDirectories(Paths.get(SHARED_META_DIR));
			Files.createDirectories(Paths.get(KEYS_ROOT, recipient));

			String relUnix = safeRelativeUnix(senderRoot, senderEncFile);
			String sharedId = sha256Hex(sender + ":" + relUnix);

			String senderKeyBaseHashed = hashedBaseForEncFile(senderEncFile, senderRoot);
			File senderKeyFile = new File(new File(KEYS_ROOT, sender), senderKeyBaseHashed + WRAPPED_KEY_EXT);
			if (!senderKeyFile.exists()) {
				FileTreeView.error("Nedostaje ključ izvornog fajla: " + senderKeyFile.getPath());
				return;
			}
			SecretKey aesKey = unwrapAesKeyForOwner(senderKeyFile, sender);

			File sharedEnc = new File(SHARED_DIR, sharedId + ENC_EXT);
			Files.copy(senderEncFile.toPath(), sharedEnc.toPath(), StandardCopyOption.REPLACE_EXISTING);

			File recipientSigOut = new File(new File(KEYS_ROOT, recipient), sharedId + SIGNATURE_EXT);
			signEncFile(sharedEnc, sender, recipientSigOut);

			PublicKey recipRsaFromCert = null;
			try {
				recipRsaFromCert = readUserRsaPublicFromCert(recipient);
			} catch (Exception ignore) {
			}
			PublicKey recipEcPubOpt = readUserEcPublicIfExists(recipient);
			if (recipRsaFromCert == null && recipEcPubOpt == null) {
				FileTreeView.error("Primatelj nema javni ključ (nema certifikat ili EC public).");
				Files.deleteIfExists(sharedEnc.toPath());
				Files.deleteIfExists(recipientSigOut.toPath());
				return;
			}

			boolean useECC = (recipEcPubOpt != null) && SecureRandom.getInstanceStrong().nextBoolean();
			byte[] wrappedRecord = useECC ? eccWrapKeyForRecipient(aesKey.getEncoded(), recipEcPubOpt)
					: rsaWrapKeyForRecipient(aesKey.getEncoded(), recipRsaFromCert);

			File recipientKeyOut = new File(new File(KEYS_ROOT, recipient), sharedId + WRAPPED_KEY_EXT);
			Files.write(recipientKeyOut.toPath(), wrappedRecord);

			String originalBase = originalBaseNameWithoutEnc(senderEncFile.getName());
			File meta = new File(SHARED_META_DIR, sharedId + ".meta");
			String metaContent = "SH1|sender=" + sender + "|recipient=" + recipient + "|name=" + originalBase;
			Files.writeString(meta.toPath(), metaContent, StandardCharsets.US_ASCII);

			FileTreeView.info("Fajl podijeljen: " + sharedEnc.getAbsolutePath() + "\nZa: " + recipient);
			FileTreeView.refreshTree();

		} catch (Exception ex) {
			ex.printStackTrace();
			FileTreeView.error("Greška pri dijeljenju fajla.");
		}
	}

	/**
	 * Primalac preuzima shared/<sharedId>.enc onda verifikuje potpis posiljaoca,
	 * otvara Save dijalog i dekriptuje
	 */
	public static void downloadShared(Stage stage, File sharedEncFile, String currentUser) {
		try {
			if (sharedEncFile == null || !sharedEncFile.isFile() || !sharedEncFile.getName().endsWith(ENC_EXT)) {
				FileTreeView.error("Odaberi .enc fajl iz shared/.");
				return;
			}
			String sharedId = sharedEncFile.getName().substring(0, sharedEncFile.getName().length() - ENC_EXT.length());

			File meta = new File(SHARED_META_DIR, sharedId + ".meta");
			if (!meta.exists()) {
				FileTreeView.error("Nedostaje metadata: " + meta.getPath());
				return;
			}
			SharedMeta sm = readMeta(meta);
			if (!sm.recipient.equals(currentUser)) {
				FileTreeView.error("Ovaj fajl nije namijenjen korisniku: " + currentUser);
				return;
			}

			File sigFile = new File(new File(KEYS_ROOT, currentUser), sharedId + SIGNATURE_EXT);
			if (!sigFile.exists()) {
				FileTreeView.error("Nedostaje potpis: " + sigFile.getPath());
				return;
			}
			if (!verifySignatureAgainstSender(sharedEncFile, sigFile, sm.sender)) {
				FileTreeView.error("Potpis NE VAŽI – fajl nije vjerodostojan (pošiljalac: " + sm.sender + ").");
				return;
			}

			File wrappedKeyFile = new File(new File(KEYS_ROOT, currentUser), sharedId + WRAPPED_KEY_EXT);
			if (!wrappedKeyFile.exists()) {
				FileTreeView.error("Nedostaje ključ: " + wrappedKeyFile.getPath());
				return;
			}
			SecretKey aesKey = unwrapAesKeyForRecipient(wrappedKeyFile, currentUser);

			try (InputStream in = new BufferedInputStream(new FileInputStream(sharedEncFile))) {
				byte[] ivFile = in.readNBytes(GCM_IV_BYTES);
				if (ivFile.length != GCM_IV_BYTES) {
					FileTreeView.error("Oštećen fajl: IV nedostaje.");
					return;
				}

				Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
				gcm.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, ivFile));

				FileChooser saver = new FileChooser();
				saver.setInitialFileName(sm.originalName);
				File outFile = saver.showSaveDialog(stage);
				if (outFile == null)
					return;

				try (javax.crypto.CipherInputStream cis = new javax.crypto.CipherInputStream(in, gcm);
						OutputStream out = new BufferedOutputStream(new FileOutputStream(outFile))) {
					cis.transferTo(out);
				}
				FileTreeView.info("Fajl preuzet i dekriptovan.");
			}

		} catch (Exception ex) {
			ex.printStackTrace();
			FileTreeView.error("Greška pri preuzimanju shared fajla.");
		}

		try {
			String sharedId = sharedEncFile.getName().substring(0, sharedEncFile.getName().length() - ENC_EXT.length());
			File meta = new File(SHARED_META_DIR, sharedId + ".meta");
			if (meta.exists()) {
				String s = Files.readString(meta.toPath(), StandardCharsets.US_ASCII).trim();
				String recipient = pickField(s, "recipient=");
				
				if (currentUser.equals(recipient)) {
					Files.deleteIfExists(sharedEncFile.toPath());
					Files.deleteIfExists(meta.toPath());
					File recipKeysDir = new File(KEYS_ROOT, recipient);
					Files.deleteIfExists(new File(recipKeysDir, sharedId + WRAPPED_KEY_EXT).toPath());
					Files.deleteIfExists(new File(recipKeysDir, sharedId + SIGNATURE_EXT).toPath());
					FileTreeView.refreshTree();
				}
			}
		} catch (IOException ignore) {
			System.err.println(ignore.getMessage());
		}

	}


	private static String originalBaseNameWithoutEnc(String name) {
		return name.endsWith(ENC_EXT) ? name.substring(0, name.length() - ENC_EXT.length()) : name;
	}

	private static class SharedMeta {
		final String sender, recipient, originalName;

		SharedMeta(String s, String r, String n) {
			sender = s;
			recipient = r;
			originalName = n;
		}
	}

	private static SharedMeta readMeta(File meta) throws IOException {
		String s = Files.readString(meta.toPath(), StandardCharsets.US_ASCII).trim();
		// format: SH1|sender=a|recipient=b|name=file.ext
		if (!s.startsWith("SH1|"))
			throw new IOException("Neispravan meta format.");
		String[] parts = s.substring(4).split("\\|");
		String sender = null, recip = null, name = null;
		for (String p : parts) {
			if (p.startsWith("sender="))
				sender = p.substring(7);
			else if (p.startsWith("recipient="))
				recip = p.substring(10);
			else if (p.startsWith("name="))
				name = p.substring(5);
		}
		if (sender == null || recip == null || name == null)
			throw new IOException("Nepotpuna metadata.");
		return new SharedMeta(sender, recip, name);
	}

	/*
	 * unwrap AES za vlasnika (pošiljaoca) iz
	 * keys/<sender>/<hash-base>.key.enc 
	 */
	private static SecretKey unwrapAesKeyForOwner(File senderKeyFile, String sender) throws Exception {
		
		byte[] wrapped = Files.readAllBytes(senderKeyFile.toPath());
		String header = sniffHeaderAscii(wrapped);
		
		if ("RSA1".equals(header)) {
			String b64 = extractPayloadAfterHeader(wrapped);
			byte[] rsaCt = Base64.getDecoder().decode(b64);
			PrivateKey rsaPriv = loadPrivateKeyFromPem(new File("certificates", sender + ".key"), "RSA");
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, rsaPriv);
			return new SecretKeySpec(rsa.doFinal(rsaCt), "AES");
		} else if ("ECC1".equals(header)) {
			String[] parts = extractPayloadAfterHeader(wrapped).split("\\|");
			if (parts.length != 3)
				throw new IOException("Neispravan ECC format.");
			byte[] ephemPub = Base64.getDecoder().decode(parts[0]);
			byte[] iv = Base64.getDecoder().decode(parts[1]);
			byte[] ct = Base64.getDecoder().decode(parts[2]);

			PrivateKey ecPriv = loadPrivateKeyFromPem(new File("certificates", sender + ".ec.key"), "EC");
			KeyFactory kf = KeyFactory.getInstance("EC");
			PublicKey ephemPublicKey = kf.generatePublic(new X509EncodedKeySpec(ephemPub));
			byte[] shared = ecdhSharedSecret(ecPriv, ephemPublicKey);
			byte[] kek = hkdfSha256(shared, null, "kek-wrap".getBytes(StandardCharsets.UTF_8), KEK_LEN);

			Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
			gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
			return new SecretKeySpec(gcm.doFinal(ct), "AES");
		} else {
			PrivateKey rsaPriv = loadPrivateKeyFromPem(new File("certificates", sender + ".key"), "RSA");
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, rsaPriv);
			return new SecretKeySpec(rsa.doFinal(wrapped), "AES");
		}
	}

	/* unwrap AES za primaoca iz keys/<recipient>/<sharedId>.key.enc */
	private static SecretKey unwrapAesKeyForRecipient(File wrappedKeyFile, String recipient) throws Exception {
		byte[] wrapped = Files.readAllBytes(wrappedKeyFile.toPath());
		String header = sniffHeaderAscii(wrapped);
		if ("RSA1".equals(header)) {
			String b64 = extractPayloadAfterHeader(wrapped);
			byte[] rsaCt = Base64.getDecoder().decode(b64);
			PrivateKey rsaPriv = loadPrivateKeyFromPem(new File("certificates", recipient + ".key"), "RSA");
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, rsaPriv);
			return new SecretKeySpec(rsa.doFinal(rsaCt), "AES");
		} else if ("ECC1".equals(header)) {
			String[] parts = extractPayloadAfterHeader(wrapped).split("\\|");
			if (parts.length != 3)
				throw new IOException("Neispravan ECC format.");
			byte[] ephemPub = Base64.getDecoder().decode(parts[0]);
			byte[] iv = Base64.getDecoder().decode(parts[1]);
			byte[] ct = Base64.getDecoder().decode(parts[2]);

			PrivateKey ecPriv = loadPrivateKeyFromPem(new File("certificates", recipient + ".ec.key"), "EC");
			KeyFactory kf = KeyFactory.getInstance("EC");
			PublicKey ephemPublicKey = kf.generatePublic(new X509EncodedKeySpec(ephemPub));
			byte[] shared = ecdhSharedSecret(ecPriv, ephemPublicKey);
			byte[] kek = hkdfSha256(shared, null, "kek-wrap".getBytes(StandardCharsets.UTF_8), KEK_LEN);

			Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
			gcm.init(Cipher.DECRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
			return new SecretKeySpec(gcm.doFinal(ct), "AES");
		} else {
			PrivateKey rsaPriv = loadPrivateKeyFromPem(new File("certificates", recipient + ".key"), "RSA");
			Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			rsa.init(Cipher.DECRYPT_MODE, rsaPriv);
			return new SecretKeySpec(rsa.doFinal(wrapped), "AES");
		}
	}

	
	private static byte[] rsaWrapKeyForRecipient(byte[] aesRaw, PublicKey recipRsa) throws Exception {
		Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsa.init(Cipher.ENCRYPT_MODE, recipRsa);
		String record = "RSA1|" + Base64.getEncoder().encodeToString(rsa.doFinal(aesRaw));
		return record.getBytes(StandardCharsets.US_ASCII);
	}

	
	private static byte[] eccWrapKeyForRecipient(byte[] aesRaw, PublicKey recipEcPub) throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec(EC_CURVE), SecureRandom.getInstanceStrong());
		KeyPair ephem = kpg.generateKeyPair();

		byte[] shared = ecdhSharedSecret(ephem.getPrivate(), recipEcPub);
		byte[] kek = hkdfSha256(shared, null, "kek-wrap".getBytes(StandardCharsets.UTF_8), KEK_LEN);

		byte[] iv = new byte[GCM_IV_BYTES];
		SecureRandom.getInstanceStrong().nextBytes(iv);

		Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
		gcm.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
		byte[] ct = gcm.doFinal(aesRaw);

		String record = "ECC1|" + Base64.getEncoder().encodeToString(ephem.getPublic().getEncoded()) + "|"
				+ Base64.getEncoder().encodeToString(iv) + "|" + Base64.getEncoder().encodeToString(ct);
		return record.getBytes(StandardCharsets.US_ASCII);
	}


	private static void signEncFile(File encFile, String sender, File sigOut) throws Exception {
		File ecPrivFile = new File("certificates", sender + ".ec.key");
		Signature signature;
		if (ecPrivFile.exists()) {
			PrivateKey ecPriv = loadPrivateKeyFromPem(ecPrivFile, "EC");
			signature = Signature.getInstance("SHA256withECDSA");
			signature.initSign(ecPriv);
			byte[] sig = signStream(signature, encFile);
			String payload = "SIG1|ECDSA|" + Base64.getEncoder().encodeToString(sig);
			Files.writeString(sigOut.toPath(), payload, StandardCharsets.US_ASCII);
		} else {
			PrivateKey rsaPriv = loadPrivateKeyFromPem(new File("certificates", sender + ".key"), "RSA");
			signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(rsaPriv);
			byte[] sig = signStream(signature, encFile);
			String payload = "SIG1|RSA|" + Base64.getEncoder().encodeToString(sig);
			Files.writeString(sigOut.toPath(), payload, StandardCharsets.US_ASCII);
		}
	}

	private static boolean verifySignatureAgainstSender(File encFile, File sigFile, String sender) throws Exception {
		String s = Files.readString(sigFile.toPath(), StandardCharsets.US_ASCII).trim();
		if (!s.startsWith("SIG1|"))
			return false;
		String[] parts = s.split("\\|");
		if (parts.length != 3)
			return false;
		String alg = parts[1];
		byte[] sigBytes = Base64.getDecoder().decode(parts[2]);

		if ("RSA".equals(alg)) {
			PublicKey pub = readUserRsaPublicFromCert(sender);
			Signature ver = Signature.getInstance("SHA256withRSA");
			ver.initVerify(pub);
			return verifyStream(ver, encFile, sigBytes);
		} else if ("ECDSA".equals(alg)) {
			PublicKey pub = readUserEcPublicIfExists(sender);
			if (pub == null)
				return false;
			Signature ver = Signature.getInstance("SHA256withECDSA");
			ver.initVerify(pub);
			return verifyStream(ver, encFile, sigBytes);
		}
		return false;
	}

	private static PublicKey readUserRsaPublicFromCert(String user) throws Exception {
		File certFile = new File("certificates", user + ".crt");
		try (FileInputStream fis = new FileInputStream(certFile)) {
			X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
			return cert.getPublicKey();
		}
	}

	private static PublicKey readUserEcPublicIfExists(String user) {
		try {
			File f = new File("certificates", user + ".ecpub");
			if (!f.exists())
				return null;
			byte[] spki = readPem(f, "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");
			return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(spki));
		} catch (Exception e) {
			return null;
		}
	}

	private static PrivateKey loadPrivateKeyFromPem(File pemFile, String algorithm) throws Exception {
		if (!pemFile.exists())
			throw new FileNotFoundException(pemFile.getAbsolutePath());
		byte[] der = readPem(pemFile, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
		return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
	}

	private static byte[] readPem(File file, String begin, String end) throws IOException {
		String pem = Files.readString(file.toPath(), StandardCharsets.US_ASCII).replace("\r", "");
		int i1 = pem.indexOf(begin), i2 = pem.indexOf(end);
		if (i1 < 0 || i2 < 0)
			throw new IOException("Neispravan PEM: " + file);
		String b64 = pem.substring(i1 + begin.length(), i2).replace("\n", "").trim();
		return Base64.getDecoder().decode(b64);
	}

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
		if (salt == null)
			salt = new byte[mac.getMacLength()];
		mac.init(new javax.crypto.spec.SecretKeySpec(salt, HKDF_HMAC));
		return mac.doFinal(ikm);
	}

	private static byte[] hkdfExpand(byte[] prk, byte[] info, int len) throws Exception {
		Mac mac = Mac.getInstance(HKDF_HMAC);
		mac.init(new javax.crypto.spec.SecretKeySpec(prk, HKDF_HMAC));
		byte[] out = new byte[len], t = new byte[0];
		int pos = 0;
		byte ctr = 1;
		while (pos < len) {
			mac.update(t);
			if (info != null)
				mac.update(info);
			mac.update(ctr);
			t = mac.doFinal();
			int copy = Math.min(t.length, len - pos);
			System.arraycopy(t, 0, out, pos, copy);
			pos += copy;
			ctr++;
		}
		return out;
	}

	private static byte[] signStream(Signature sig, File file) throws Exception {
		try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
			byte[] buf = new byte[8192];
			int n;
			while ((n = in.read(buf)) > 0)
				sig.update(buf, 0, n);
			return sig.sign();
		}
	}

	private static boolean verifyStream(Signature sig, File file, byte[] signature) throws Exception {
		try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
			byte[] buf = new byte[8192];
			int n;
			while ((n = in.read(buf)) > 0)
				sig.update(buf, 0, n);
			return sig.verify(signature);
		}
	}

	private static String sniffHeaderAscii(byte[] data) {
		String s = new String(data, 0, Math.min(data.length, 8), StandardCharsets.US_ASCII);
		if (s.startsWith("RSA1|"))
			return "RSA1";
		if (s.startsWith("ECC1|"))
			return "ECC1";
		return null;
	}

	private static String extractPayloadAfterHeader(byte[] data) {
		String s = new String(data, StandardCharsets.US_ASCII);
		int pipe = s.indexOf('|');
		return pipe < 0 ? "" : s.substring(pipe + 1);
	}

	private static String sha256Hex(String s) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
			StringBuilder sb = new StringBuilder(d.length * 2);
			for (byte b : d)
				sb.append(String.format("%02x", b));
			return sb.toString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
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

	private static String hashedBaseForEncFile(File encFile, File userRoot) {
		String name = encFile.getName();
		if (name.endsWith(ENC_EXT))
			name = name.substring(0, name.length() - ENC_EXT.length());
		String relUnix = safeRelativeUnix(userRoot, encFile);
		return sha256Hex(relUnix) + "-" + name;
	}

	private static boolean isUnder(File baseDir, File candidate) {
		try {
			Path base = baseDir.getCanonicalFile().toPath();
			Path cand = candidate.getCanonicalFile().toPath();
			return cand.startsWith(base);
		} catch (IOException e) {
			return false;
		}
	}

	public static void deleteSharedBySender(File sharedEncFile, String currentUser) {
	    try {
	        if (sharedEncFile == null || !sharedEncFile.isFile() || !sharedEncFile.getName().endsWith(ENC_EXT)) {
	            FileTreeView.error("Odaberi .enc fajl iz shared foldera.");
	            return;
	        }
	        // mora biti pod shared/
	        File sharedRoot = new File(SHARED_DIR);
	        if (!isUnder(sharedRoot, sharedEncFile)) {
	            FileTreeView.error("Ovaj fajl nije u 'shared' direktorijumu.");
	            return;
	        }

	        String name = sharedEncFile.getName();
	        String sharedId = name.substring(0, name.length() - ENC_EXT.length());

	        File meta = new File(SHARED_META_DIR, sharedId + ".meta");
	        if (!meta.exists()) {
	            FileTreeView.error("Nedostaje metadata za shared fajl: " + meta.getPath());
	            return;
	        }
	        String s = Files.readString(meta.toPath(), StandardCharsets.US_ASCII).trim();
	        String sender    = pickField(s, "sender=");
	        String recipient = pickField(s, "recipient=");
	        if (sender == null || recipient == null) {
	            FileTreeView.error("Oštećena metadata (nema sender/recipient).");
	            return;
	        }

	        if (!currentUser.equals(sender)) {
	            FileTreeView.error("Samo pošiljalac (" + sender + ") može obrisati ovaj fajl.");
	            return;
	        }

	        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
	        confirm.setHeaderText("Brisanje podijeljenog fajla");
	        confirm.setContentText("Obrisati fajl i prateće zapise?\n" + sharedEncFile.getAbsolutePath());
	        Optional<ButtonType> choice = confirm.showAndWait();
	        if (choice.isEmpty() || choice.get() != ButtonType.OK) return;

	        Files.deleteIfExists(sharedEncFile.toPath());
	        Files.deleteIfExists(meta.toPath());
	        File recipKeysDir = new File(KEYS_ROOT, recipient);
	        Files.deleteIfExists(new File(recipKeysDir, sharedId + WRAPPED_KEY_EXT).toPath());
	        Files.deleteIfExists(new File(recipKeysDir, sharedId + SIGNATURE_EXT).toPath());

	        FileTreeView.info("Shared fajl obrisan.");
	        FileTreeView.refreshTree();

	    } catch (IOException ex) {
	        ex.printStackTrace();
	        FileTreeView.error("Greška pri brisanju shared fajla: " + ex.getMessage());
	    }
	}


	public static String pickField(String line, String fieldPrefix) {
		if (line == null)
			return null;
		String[] parts = line.split("\\|");
		for (String p : parts) {
			if (p.startsWith(fieldPrefix)) {
				return p.substring(fieldPrefix.length());
			}
		}
		return null;
	}

}
