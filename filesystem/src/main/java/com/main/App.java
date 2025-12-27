package com.main;

import javafx.application.Application;
import javafx.stage.*;
import javafx.scene.*;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.geometry.*;
import java.io.*;
import java.nio.file.*;
import java.security.cert.*;
import java.util.*;

import crypto.Passwords;

public class App extends Application {

    private static final String USERS_FILE = "users.txt";
    private static final String CERTS_DIR = "certificates";  // privatni kljucevi korisnika ostaju ovdje
    private static final String KEYS_DIR  = "keys";          // fajl kljucevi idu u keys/<username>/
    private static final String EFS_DIR = "efs";
    private static final String CA_CERT_FILE = CERTS_DIR + "/myCA.crt";
    private static final String CRL_FILE = CERTS_DIR + "/myCA.crl";

    @Override
    public void start(Stage primaryStage) {
        try {
            initDirs();
            checkAdminExists(primaryStage);

            Label userLabel = new Label("Korisničko ime:");
            TextField userField = new TextField();

            Label passLabel = new Label("Lozinka:");
            PasswordField passField = new PasswordField();

            Button loginBtn = new Button("Prijava");
            loginBtn.setOnAction(e -> {
                String username = userField.getText();
                String password = passField.getText();

                if (verifyLogin(username, password)) {
                    FileTreeView ftv = new FileTreeView(username);
                    ftv.show(primaryStage);
                } else {
                    showError("Neispravni podaci ili sertifikat!");
                }
            });

            Button newUserBtn = new Button("Kreiraj novi nalog");
            newUserBtn.setOnAction(e -> createNewUserDialog(primaryStage));

            GridPane grid = new GridPane();
            grid.setPadding(new Insets(10));
            grid.setVgap(10);
            grid.setHgap(10);
            grid.add(userLabel, 0, 0);
            grid.add(userField, 1, 0);
            grid.add(passLabel, 0, 1);
            grid.add(passField, 1, 1);
            grid.add(loginBtn, 1, 2);
            grid.add(newUserBtn, 2, 2);

            Scene scene = new Scene(grid, 450, 180);
            primaryStage.setScene(scene);
            primaryStage.setTitle("EFS Login");
            primaryStage.show();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void initDirs() throws IOException {
        Files.createDirectories(Paths.get(CERTS_DIR));
        Files.createDirectories(Paths.get(KEYS_DIR));
        Files.createDirectories(Paths.get(EFS_DIR));
    }

    private void checkAdminExists(Stage stage) throws IOException {
        File f = new File(USERS_FILE);
        if (!f.exists()) {
            TextInputDialog d = new TextInputDialog();
            d.setHeaderText("Postavljanje admin lozinke");
            d.setContentText("Unesi novu admin lozinku:");
            Optional<String> result = d.showAndWait();
            if (result.isPresent()) {
                // admin: nasumicno PBKDF2/BCrypt/Argon2 (format: ALG|payload)
                String algPayload = Passwords.hashForAnyRandom(result.get());
                Files.write(Paths.get(USERS_FILE), ("admin|" + algPayload + "\n").getBytes());
            } else {
                throw new RuntimeException("Admin lozinka nije postavljena!");
            }
        }
    }

    private boolean verifyLogin(String username, String password) {
        try {
            // 1) Procitaj zapis iz users.txt (ocekuje format: user|ALG|payload)
            List<String> lines = Files.readAllLines(Paths.get(USERS_FILE));
            String storedAlgPayload = null;
            for (String line : lines) {
                String[] parts = line.split("\\|", 3);
                if (parts.length == 3 && parts[0].equals(username)) {
                    storedAlgPayload = parts[1] + "|" + parts[2]; // "ALG|payload"
                    break;
                }
            }
            if (storedAlgPayload == null) {
                return false;
            }

            // 2) Verifikacija lozinke prateci algoritam
            if (!Passwords.verify(password, storedAlgPayload)) {
                return false;
            }

            if (username.equals("admin")) {
                return true;
            }

            // 3) Ucitaj korisnicki sertifikat
            File userCertFile = new File(CERTS_DIR, username + ".crt");
            if (!userCertFile.exists()) {
                System.out.println("❌ Sertifikat korisnika ne postoji!");
                return false;
            }

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate userCert;
            try (FileInputStream fis = new FileInputStream(userCertFile)) {
                userCert = (X509Certificate) cf.generateCertificate(fis);
            }

            // 4) Provjera CN == username
            String dn = userCert.getSubjectX500Principal().getName();
            if (!dn.contains("CN=" + username)) {
                System.out.println("❌ CN u sertifikatu se ne poklapa sa username!");
                return false;
            }

            // 5) Provjera validnosti (da nije istekao)
            userCert.checkValidity();

            // 6) Provjera potpisa od strane CA
            X509Certificate caCert;
            try (FileInputStream fis = new FileInputStream(CA_CERT_FILE)) {
                caCert = (X509Certificate) cf.generateCertificate(fis);
            }
            userCert.verify(caCert.getPublicKey());

            // 7) Provjera CRL
            File crlFile = new File(CRL_FILE);
            if (crlFile.exists()) {
                try (FileInputStream crlFis = new FileInputStream(crlFile)) {
                    X509CRL crl = (X509CRL) cf.generateCRL(crlFis);
                    if (crl.isRevoked(userCert)) {
                        System.out.println("❌ Sertifikat opozvan (na CRL)!");
                        return false;
                    }
                }
            }

            return true;

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private boolean verifyAdminPassword(String password) {
        try {
            List<String> lines = Files.readAllLines(Paths.get(USERS_FILE));
            for (String line : lines) {
                String[] parts = line.split("\\|", 3); // admin|ALG|payload
                if (parts.length == 3 && parts[0].equals("admin")) {
                    String algPayload = parts[1] + "|" + parts[2];
                    return Passwords.verify(password, algPayload);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    private void createNewUserDialog(Stage stage) {
        Dialog<Void> dialog = new Dialog<>();
        dialog.setTitle("Kreiranje novog naloga");

        Label adminPassLabel = new Label("Admin lozinka:");
        PasswordField adminPassField = new PasswordField();
        Label newUserLabel = new Label("Novi username:");
        TextField newUserField = new TextField();
        Label newPassLabel = new Label("Nova lozinka:");
        PasswordField newPassField = new PasswordField();

        VBox vbox = new VBox(10, adminPassLabel, adminPassField, newUserLabel, newUserField, newPassLabel, newPassField);
        vbox.setPadding(new Insets(10));
        dialog.getDialogPane().setContent(vbox);

        ButtonType createBtn = new ButtonType("Kreiraj", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(createBtn, ButtonType.CANCEL);

        dialog.setResultConverter(btn -> {
            if (btn == createBtn) {
                if (!verifyAdminPassword(adminPassField.getText())) {
                    showError("Pogrešna admin lozinka!");
                    return null;
                }
                createUser(newUserField.getText(), newPassField.getText());
            }
            return null;
        });

        dialog.showAndWait();
    }

    private void createUser(String username, String password) {
        try {
            // 1) Dodaj u users.txt — nasumicno : PBKDF2 / BCRYPT / ARGON2
            String algPayload = Passwords.hashForAnyRandom(password); // "ALG|payload"
            Files.write(Paths.get(USERS_FILE),
                    (username + "|" + algPayload + "\n").getBytes(),
                    StandardOpenOption.APPEND);

            // 2) putanje (privatni kljuc korisnika ostaje u certificates/)
            String userKeyPath  = CERTS_DIR + "/" + username + ".key";
            String userCsrPath  = CERTS_DIR + "/" + username + ".csr";
            String userCertPath = CERTS_DIR + "/" + username + ".crt";

            String openssl = "C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe";
            String config = "C:\\Program Files\\OpenSSL-Win64\\bin\\cnf\\openssl.cnf";

            // 3) Generisi privatni kljuc
            ProcessBuilder genKey = new ProcessBuilder(
                    openssl, "genrsa", "-out", userKeyPath, "2048"
            );
            genKey.inheritIO().start().waitFor();

            // 4) Generisi CSR 
            ProcessBuilder genCsr = new ProcessBuilder(
                    openssl, "req", "-new", "-key", userKeyPath, "-out", userCsrPath,
                    "-subj", "/CN=" + username,
                    "-config", config
            );
            genCsr.inheritIO().start().waitFor();

            // 5) Potpisi sertifikat sa CA
            ProcessBuilder signCert = new ProcessBuilder(
                    openssl, "x509", "-req", "-in", userCsrPath,
                    "-CA", CA_CERT_FILE, "-CAkey", CERTS_DIR + "/myCA.key",
                    "-CAcreateserial", "-out", userCertPath,
                    "-days", "365", "-sha256"
            );
            signCert.inheritIO().start().waitFor();

            // 6) Obrisi CSR (ne treba vise)
            Files.deleteIfExists(Paths.get(userCsrPath));

            // 7) Kreiraj folder u efs i folder za file kljuceve
            Files.createDirectories(Paths.get(EFS_DIR, username));
            Files.createDirectories(Paths.get(KEYS_DIR, username)); // npr. keys/marko/

            showInfo("Korisnik " + username + " je uspješno kreiran!\n" +
                     "Algoritam za lozinku: " + algPayload.split("\\|",2)[0] + "\n" +
                     "Privatni ključ: " + userKeyPath + "\n" +
                     "Sertifikat: " + userCertPath + "\n" +
                     "Folder za ključeve fajlova: " + Paths.get(KEYS_DIR, username));

        } catch (Exception e) {
            e.printStackTrace();
            showError("Greška pri kreiranju korisnika!");
        }
    }

    private void showError(String msg) {
        Alert a = new Alert(Alert.AlertType.ERROR, msg);
        a.showAndWait();
    }

    private void showInfo(String msg) {
        Alert a = new Alert(Alert.AlertType.INFORMATION, msg);
        a.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
