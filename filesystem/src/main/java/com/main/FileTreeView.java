package com.main;


import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.input.MouseButton;
import javafx.scene.layout.*;
import javafx.stage.*;

import crypto.FileCrypting;
import crypto.SharedService;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.stream.Stream;

public class FileTreeView {

    private static final String ENC_EXT = ".enc";
    private static final String KEYS_ROOT = "keys";
    private static final String WRAPPED_KEY_EXT = ".key.enc";

    public static String username;
    public static File userDir;
    private static TreeView<File> treeView;
    private static TreeItem<File> rootItem;

    private static TreeItem<File> userNode;
    private static TreeItem<File> sharedNode;

    private static final String SHARED_DIR = "shared";
    private static final String SHARED_META_DIR = "shared_metadata";
    private static final String SIGNATURE_EXT = ".sig";

    public FileTreeView(String username) {
        FileTreeView.username = username;
        userDir = new File("efs", username);
    }

    public void show(Stage stage) {
        Label welcome = new Label("Dobrodošao, " + username + "!");
        Button logout = new Button("Odjava");
        logout.setOnAction(e -> stage.close());

        Button addFileBtn = new Button("Dodaj fajl");
        addFileBtn.setOnAction(e -> FileCrypting.addFile(stage));

        Button addDirBtn = new Button("Novi folder");
        addDirBtn.setOnAction(e -> createDirectory());

        Button deleteBtn = new Button("Obriši");
        deleteBtn.setOnAction(e -> deleteSelected());

        HBox toolbar = new HBox(10, welcome, new Separator(), addFileBtn, addDirBtn, deleteBtn, new Separator(), logout);

        try {
            Files.createDirectories(userDir.toPath());
            Files.createDirectories(Paths.get(SHARED_DIR));
            Files.createDirectories(Paths.get(SHARED_META_DIR));
        } catch (IOException ignore) {}

        //Foriraju se korisnicki i shared folder
        userNode = createNode(userDir);
        File sharedDir = new File(SHARED_DIR);
        sharedNode = createNode(sharedDir);

        rootItem = new TreeItem<>(new File("ROOT"));
        rootItem.getChildren().setAll(userNode, sharedNode);
        rootItem.setExpanded(true);

        treeView = new TreeView<>(rootItem);
        treeView.setShowRoot(false);

        treeView.setCellFactory(tv -> {
            MenuItem miNew   = new MenuItem("Novi folder ovdje");
            miNew.setOnAction(e -> createDirectory());

            MenuItem miDel   = new MenuItem("Obriši");
            miDel.setOnAction(e -> {
                TreeItem<File> sel = treeView.getSelectionModel().getSelectedItem();
                if (sel == null) return;
                File target = sel.getValue();
                if (target == null) return;

                File sharedRoot = new File(SHARED_DIR);
                if (isUnder(sharedRoot, target) && target.isFile() && target.getName().endsWith(ENC_EXT)) {
                    // brisanje shared fajla – dozvoljeno samo posiljaocu
                    SharedService.deleteSharedBySender(target, username);
                    refreshTree();
                } else {
                    deleteSelected();
                }
            });

            MenuItem miShare = new MenuItem("Podijeli…");
            miShare.setOnAction(e -> shareSelected(stage));

            ContextMenu ctx = new ContextMenu(miNew, miDel, miShare);

            return new TreeCell<File>() {
                @Override
                protected void updateItem(File f, boolean empty) {
                    super.updateItem(f, empty);
                    if (empty || f == null) {
                        setText(null);
                        setContextMenu(null);
                        return;
                    }

                    // Labela za shared fajl sa meta prikazom
                    if (f.isFile() && isUnder(new File(SHARED_DIR), f) && f.getName().endsWith(ENC_EXT)) {
                        String sharedId = f.getName().substring(0, f.getName().length() - ENC_EXT.length());
                        File meta = new File(SHARED_META_DIR, sharedId + ".meta");
                        String label = f.getName();
                        try {
                            if (meta.exists()) {
                                String s = Files.readString(meta.toPath(), StandardCharsets.US_ASCII).trim();
                                String sender = pickField(s, "sender=");
                                String recip  = pickField(s, "recipient=");
                                String name   = pickField(s, "name=");
                                if (sender != null && recip != null && name != null) {
                                    label = name + "  (od: " + sender + " → za: " + recip + ")";
                                }
                            }
                        } catch (IOException ignore) {}
                        setText(label);
                    } else {
                        setText(f.getName());
                    }

                    // Dijeljenje
                    boolean canShare = f.isFile() && f.getName().endsWith(ENC_EXT) && isUnder(userDir, f);
                    miShare.setDisable(!canShare);

                    // Brisanje
                    boolean canDelete;
                    File sharedRoot = new File(SHARED_DIR);

                    if (isUnder(sharedRoot, f) && f.isFile() && f.getName().endsWith(ENC_EXT)) {
                        canDelete = isSenderOfShared(f, username);
                    } else if (f.isDirectory() && (samePath(f, userDir) || samePath(f, sharedRoot))) {
                        canDelete = false;
                    } else {
                        canDelete = isUnder(userDir, f);
                    }
                    miDel.setDisable(!canDelete);

                    setContextMenu(ctx);
                }
            };
        });

        // Disable dugme “Obrisi” kad user nema pravo
        deleteBtn.disableProperty().bind(
            javafx.beans.binding.Bindings.createBooleanBinding(() -> {
                TreeItem<File> sel = treeView.getSelectionModel().getSelectedItem();
                if (sel == null) return true;
                File f = sel.getValue();
                if (f == null) return true;

                File sharedRoot = new File(SHARED_DIR);
                // rootovi ne mogu da se brišu
                if (f.isDirectory() && (samePath(f, userDir) || samePath(f, sharedRoot))) return true;

                if (isUnder(sharedRoot, f)) {
                    return !(f.isFile() && f.getName().endsWith(ENC_EXT) && isSenderOfShared(f, username));
                }
                return !isUnder(userDir, f);
            }, treeView.getSelectionModel().selectedItemProperty())
        );

        // Dvoklik za preuzimanje
        treeView.setOnMouseClicked(evt -> {
            if (evt.getButton() == MouseButton.PRIMARY && evt.getClickCount() == 2) {
                TreeItem<File> it = treeView.getSelectionModel().getSelectedItem();
                if (it == null) return;
                File f = it.getValue();
                if (f.isFile() && f.getName().endsWith(ENC_EXT)) {
                    if (isUnder(new File(SHARED_DIR), f)) {
                        SharedService.downloadShared(stage, f, username);
                        refreshTree(); 
                    } else if (isUnder(userDir, f)) {
                        FileCrypting.decryptFileUI(stage, f);
                    } else {
                        error("Nepoznata lokacija fajla.");
                    }
                }
            }
        });

        VBox vbox = new VBox(12, toolbar, treeView);
        vbox.setStyle("-fx-padding: 20;");
        Scene scene = new Scene(vbox, 800, 520);
        stage.setScene(scene);
        stage.setTitle("EFS - " + username);
        stage.show();
    }

    /* ---------- TREE HELPER METODE ---------- */

    public static void refreshTree() {
        if (userNode != null) {
            userNode.getChildren().setAll(childrenOf(userDir));
            userNode.setExpanded(true);
        }
        if (sharedNode != null) {
            File sharedDir = new File(SHARED_DIR);
            sharedNode.setValue(sharedDir);
            sharedNode.getChildren().setAll(childrenOf(sharedDir));
            sharedNode.setExpanded(true);
        }
        if (treeView != null) {
            treeView.refresh();
        }
    }

    private static TreeItem<File> createNode(File f) {
        TreeItem<File> node = new TreeItem<>(f);
        node.getChildren().setAll(childrenOf(f));
        node.setExpanded(true);
        return node;
    }

    private static List<TreeItem<File>> childrenOf(File dir) {
        List<TreeItem<File>> list = new ArrayList<>();
        File[] children = dir.listFiles();
        if (children != null) {
            List<File> dirs = new ArrayList<>();
            List<File> files = new ArrayList<>();
            for (File c : children) {
                if (c.isDirectory()) dirs.add(c);
                else files.add(c);
            }
            dirs.sort(Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));
            files.sort(Comparator.comparing(File::getName, String.CASE_INSENSITIVE_ORDER));

            for (File d : dirs) list.add(createNode(d));
            for (File f : files) list.add(new TreeItem<>(f));
        }
        return list;
    }

    /* ---------- OGRANICENJE NA USER ROOT ---------- */

    private static boolean isUnder(File base, File candidate) {
        try {
            String basePath = base.getCanonicalPath();
            String candPath = candidate.getCanonicalPath();
            return candPath.equals(basePath) || candPath.startsWith(basePath + File.separator);
        } catch (IOException e) {
            return false;
        }
    }

    private static boolean samePath(File a, File b) {
        try {
            return a.getCanonicalFile().equals(b.getCanonicalFile());
        } catch (IOException e) {
            return a.equals(b);
        }
    }

    private File resolveSelectedDirOrUserRoot() {
        TreeItem<File> sel = treeView.getSelectionModel().getSelectedItem();
        if (sel == null) return userDir;
        File f = sel.getValue();
        if (f == null) return userDir;
        if (f.isDirectory()) return f;
        File parent = f.getParentFile();
        return (parent != null && isUnder(userDir, parent)) ? parent : userDir;
    }

    /* ---------- KREIRANJE FOLDERA ---------- */

    private void createDirectory() {
        try {
            Files.createDirectories(userDir.toPath());
            File base = resolveSelectedDirOrUserRoot();

            if (!isUnder(userDir, base)) {
                error("Folder može biti kreiran samo unutar: " + userDir.getAbsolutePath());
                return;
            }

            TextInputDialog d = new TextInputDialog();
            d.setHeaderText("Kreiraj novi folder");
            d.setContentText("Naziv foldera:");
            Optional<String> res = d.showAndWait();
            if (res.isEmpty()) return;

            String name = res.get().trim();
            if (name.isEmpty() || name.contains("/") || name.contains("\\") || name.contains("..")) {
                error("Neispravan naziv foldera.");
                return;
            }

            File newDir = new File(base, name);
            if (newDir.exists()) {
                error("Taj folder već postoji.");
                return;
            }

            if (!newDir.mkdirs()) {
                error("Kreiranje foldera nije uspjelo.");
                return;
            }

            info("Folder kreiran.");
            refreshTree();

        } catch (Exception ex) {
            ex.printStackTrace();
            error("Greška pri kreiranju foldera.");
        }
    }

    /* ---------- BRISANJE ---------- */

    private void deleteSelected() {
        TreeItem<File> sel = treeView.getSelectionModel().getSelectedItem();
        if (sel == null) { error("Nije selektovan fajl ili folder."); return; }
        File target = sel.getValue();
        if (target == null) { error("Nije selektovan fajl ili folder."); return; }

        File sharedRoot = new File(SHARED_DIR);

        // Zabrani brisanje root-ova
        if (target.isDirectory() && (samePath(target, userDir) || samePath(target, sharedRoot))) {
            error("Ne možeš obrisati root folder.");
            return;
        }

        // Ako je u shared: dozvoljeno samo posiljaocu i samo .enc
        if (isUnder(sharedRoot, target)) {
            if (!(target.isFile() && target.getName().endsWith(ENC_EXT) && isSenderOfShared(target, username))) {
                error("U shared/ može brisati samo pošiljalac taj .enc fajl.");
                return;
            }
            
            Alert confirm = new Alert(Alert.AlertType.CONFIRMATION,
                    "Obrisati podijeljeni fajl?\n" + target.getAbsolutePath());
            Optional<ButtonType> choice = confirm.showAndWait();
            if (choice.isEmpty() || choice.get() != ButtonType.OK) return;

            SharedService.deleteSharedBySender(target, username);
            info("Shared fajl obrisan.");
            refreshTree();
            return;
        }

        // Inace: user prostor
        if (!isUnder(userDir, target)) {
            error("Brisanje je dozvoljeno samo unutar: " + userDir.getAbsolutePath());
            return;
        }

        Alert confirm = new Alert(Alert.AlertType.CONFIRMATION);
        confirm.setHeaderText("Potvrda brisanja");
        confirm.setContentText(target.isDirectory()
                ? "Obrisati direktorijum i SAV njegov sadržaj?\n" + target.getAbsolutePath()
                : "Obrisati fajl?\n" + target.getAbsolutePath());
        Optional<ButtonType> choice = confirm.showAndWait();
        if (choice.isEmpty() || choice.get() != ButtonType.OK) return;

        try {
            if (target.isDirectory()) {
                deleteDirectoryAndKeys(target.toPath());
            } else {
                deleteFileAndKey(target.toPath());
            }
            info("Obrisano.");
            refreshTree();
        } catch (UncheckedIOException uioe) {
            uioe.printStackTrace();
            error("Greška pri brisanju: " + uioe.getMessage());
        } catch (Exception ex) {
            ex.printStackTrace();
            error("Greška pri brisanju.");
        }
    }

    // Obrisi fajl a ako je .enc, obrisi i pratece keys/<username>/<hash-base>.key.enc i .sig 
    private void deleteFileAndKey(Path file) throws IOException {
        File f = file.toFile();
        if (f.isFile() && f.getName().endsWith(ENC_EXT)) {
            File userKeysDir = new File(KEYS_ROOT, username);
            String baseHashed = hashedBaseForEncFile(f);

            File keyFile = new File(userKeysDir, baseHashed + WRAPPED_KEY_EXT);
            try { Files.deleteIfExists(keyFile.toPath()); } catch (IOException e) {
                System.err.println("Upozorenje: nije moguće obrisati ključ " + keyFile + ": " + e.getMessage());
            }

            File sigFile = new File(userKeysDir, baseHashed + SIGNATURE_EXT);
            try { Files.deleteIfExists(sigFile.toPath()); } catch (IOException e) {
                System.err.println("Upozorenje: nije moguće obrisati potpis " + sigFile + ": " + e.getMessage());
            }
        }
        Files.deleteIfExists(file);
    }

    // Rekurzivno obrisi dir i sve pratece .key.enc/.sig za sve .enc fajlove u njemu
    private void deleteDirectoryAndKeys(Path dir) throws IOException {
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.filter(p -> Files.isRegularFile(p) && p.getFileName().toString().endsWith(ENC_EXT))
                .forEach(p -> {
                    File f = p.toFile();
                    String baseHashed = hashedBaseForEncFile(f);
                    File userKeysDir = new File(KEYS_ROOT, username);
                    File keyFile = new File(userKeysDir, baseHashed + WRAPPED_KEY_EXT);
                    File sigFile = new File(userKeysDir, baseHashed + SIGNATURE_EXT);
                    try { Files.deleteIfExists(keyFile.toPath()); } catch (IOException e) {
                        System.err.println("Upozorenje: nije moguće obrisati ključ " + keyFile + ": " + e.getMessage());
                    }
                    try { Files.deleteIfExists(sigFile.toPath()); } catch (IOException e) {
                        System.err.println("Upozorenje: nije moguće obrisati potpis " + sigFile + ": " + e.getMessage());
                    }
                });
        }
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted(Comparator.reverseOrder())
                .forEach(p -> {
                    try { Files.deleteIfExists(p); }
                    catch (IOException e) { throw new UncheckedIOException(e); }
                });
        }
    }

    /* ---------- dodatni helperi ---------- */

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
        String relUnix = safeRelativeUnix(userDir, encFile);
        String hash = sha256Hex(relUnix);
        return hash + "-" + baseName;
    }

    /* ---------- UI metode za shared dio ---------- */

    private void shareSelected(Stage stage) {
        TreeItem<File> sel = treeView.getSelectionModel().getSelectedItem();
        if (sel == null) { error("Nije odabran fajl."); return; }
        File f = sel.getValue();
        if (!(f.isFile() && f.getName().endsWith(ENC_EXT) && isUnder(userDir, f))) {
            error("Možeš dijeliti samo .enc iz svog foldera.");
            return;
        }
        TextInputDialog d = new TextInputDialog();
        d.setHeaderText("Podijeli fajl");
        d.setContentText("Kome (username):");
        Optional<String> r = d.showAndWait();
        if (r.isEmpty()) return;
        String recipient = r.get().trim();
        if (recipient.isEmpty() || recipient.contains("/") || recipient.contains("\\") || recipient.contains("..")) {
            error("Neispravno korisničko ime.");
            return;
        }
        SharedService.shareFile(stage, f, username, recipient);
        refreshTree();
    }

    /* ---------- ostali shared helperi ---------- */

    private static boolean isSenderOfShared(File sharedEncFile, String currentUser) {
        if (sharedEncFile == null || !sharedEncFile.isFile()) return false;
        String name = sharedEncFile.getName();
        if (!name.endsWith(ENC_EXT)) return false;
        String sharedId = name.substring(0, name.length() - ENC_EXT.length());
        File meta = new File(SHARED_META_DIR, sharedId + ".meta");
        if (!meta.exists()) return false;
        try {
            String s = Files.readString(meta.toPath(), StandardCharsets.US_ASCII).trim();
            String sender = pickField(s, "sender=");
            return currentUser.equals(sender);
        } catch (IOException e) {
            return false;
        }
    }

    private static String pickField(String meta, String key) {
        if (meta == null) return null;
        String[] parts = meta.split("\\|");
        for (String p : parts) {
            if (p.startsWith(key)) return p.substring(key.length());
        }
        return null;
    }

    /* ---------- UI helperi ---------- */

    public static void info(String msg) {
        new Alert(Alert.AlertType.INFORMATION, msg).showAndWait();
    }

    public static void error(String msg) {
        new Alert(Alert.AlertType.ERROR, msg).showAndWait();
    }
}
