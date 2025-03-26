package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Optional;

public class JavaFxApp extends Application {
    private int selectedKey;
    //private String textToEncrypt;
    private byte[] textToEncrypt;
    private Stage primaryStage;
    private byte[] textToDecrypt;
    private byte [][] roundKeys;
    private int paddedBytes;
    private int keySize;
    private String encryptedText;
    private int keySizeDecryption;
    private int paddedBytesDecryption;
    private byte  [][] roundKeysDecryption;;


    @Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;
        reloadMainScene();
    }
    public void reloadMainScene() throws IOException {
        // Load the initial FXML for the starting scene
        URL initialFxmlLocation = getClass().getResource("/org/example/encryption_or_decryption_main.fxml");
        if (initialFxmlLocation == null) {
            throw new RuntimeException("Invalid Initial FXML location");
        }
        FXMLLoader loader = new FXMLLoader(initialFxmlLocation);
        Parent initialRoot = loader.load();
        initialRoot.setStyle("-fx-background-color: pink;"); // Ustawienie koloru tła

        Button btnEncryption = (Button) initialRoot.lookup("#btnEncryption");
        Button btnDecryption = (Button) initialRoot.lookup("#btnDecryption");

        if (btnEncryption != null) {
            btnEncryption.setOnAction(event -> openEncryptionScene());
        }

        if (btnDecryption != null) {
            btnDecryption.setOnAction(event -> System.out.println("Decryption not yet implemented."));
        }

        // Set the initial scene
        primaryStage.setTitle("Choose Operation");
        primaryStage.setScene(new Scene(initialRoot, 640, 400));
        primaryStage.show();
    }

    private void openEncryptionScene(){
        try {
            // Load the encryption FXML
            URL fxmlLocation = getClass().getResource("/org/example/encrypt_file_or_text.fxml");
            if (fxmlLocation == null) {
                throw new RuntimeException("Invalid Encryption FXML location");
            }
            FXMLLoader loader = new FXMLLoader(fxmlLocation);
            Parent root = loader.load();

            root.setStyle("-fx-background-color: pink;"); // Ustawienie koloru tła


            Button btnEncryptFile = (Button) root.lookup("#btnEncryptFile");
            Button btnEncryptText = (Button) root.lookup("#btnEncryptText");
            //btnEncryptFile.setStyle("-fx-background-color: #91275e; -fx-text-fill: white;");
            //btnEncryptText.setStyle("-fx-background-color: #91275e; -fx-text-fill: white;");

            if (btnEncryptFile != null) {
                btnEncryptFile.setOnAction(event -> {
                    FileChooser fileChooser = new FileChooser();
                    fileChooser.setTitle("Wybierz plik do zaszyfrowania");
                    File file = fileChooser.showOpenDialog(primaryStage);
                    if (file != null) {
                        try {
                            textToEncrypt = Files.readAllBytes(Path.of(file.getAbsolutePath()));
                            System.out.println("Wybrano plik: " + file.getAbsolutePath());
                            openKeySelectionScene();
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
            } else {
                System.err.println("Błąd: btnEncryptFile nie znaleziono w FXML!");
            }

            if (btnEncryptText != null) {
                btnEncryptText.setOnAction(event -> {
                    TextInputDialog dialog = new TextInputDialog();
                    dialog.setTitle("Wpisz tekst do zaszyfrowania");
                    dialog.setHeaderText("Podaj tekst, który chcesz zaszyfrować:");
                    dialog.setContentText("Tekst:");

                    Optional<String> result = dialog.showAndWait();
                    result.ifPresent(text -> {
                        textToEncrypt = text.getBytes();
                        openKeySelectionScene();
                    });
                });
            } else {
                System.err.println("Błąd: btnEncryptText nie znaleziono w FXML!");
            }

            primaryStage.setScene(new Scene(root, 600, 400));
            primaryStage.setTitle("Cryptography Application");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private  void openDecryptionScene(){
        try {
            // Load the encryption FXML
            URL fxmlLocation = getClass().getResource("/org/example/decryption_choose_type.fxml");
            if (fxmlLocation == null) {
                throw new RuntimeException("Invalid Encryption FXML location");
            }
            FXMLLoader loader = new FXMLLoader(fxmlLocation);
            Parent root = loader.load();
            root.setStyle("-fx-background-color: pink;"); // Ustawienie koloru tła

            RadioButton fileInput = (RadioButton) root.lookup("#fileInput");
            RadioButton textInput = (RadioButton) root.lookup("#textInput");
            RadioButton keysFromMemmory = (RadioButton) root.lookup("#keysFromMemmory");
            RadioButton keysFromFile = (RadioButton) root.lookup("#keysFromFile");
            RadioButton keysFromText = (RadioButton) root.lookup("#keysFromText");
            RadioButton key128 = (RadioButton) root.lookup("#key128");
            RadioButton key192 = (RadioButton) root.lookup("#key192");
            RadioButton key256 = (RadioButton) root.lookup("#key256");
            Button confirm = (Button) root.lookup("#confirm");
            TextArea mainKeyInput = (TextArea) root.lookup("#mainKeyInputmainKeyInput");
            TextArea paddingTextInput = (TextArea) root.lookup("#paddingTextInput");
            if(keysFromText != null) {
                if(key128!=null){
                    keySizeDecryption=128;
                }
                if(key192!=null){
                    keySizeDecryption=192;
                }
                if(key256!=null){
                    keySizeDecryption=256;
                }
                if(mainKeyInput!=null){
                    Encryptor encryptor=new Encryptor(null,keySizeDecryption);
                    roundKeysDecryption= encryptor.getRoundKeys();
                }
                if(paddingTextInput!=null){
                    paddedBytesDecryption= Integer.parseInt(paddingTextInput.getText());
                }
            }
           if(keysFromMemmory!=null){
                //if(keySize!=null){
                    keySizeDecryption=keySize;
                    paddedBytesDecryption=paddedBytes;
                    roundKeysDecryption=roundKeys;
                //}
                //else{
                 //   System.err.println("nie dokonano wcześniej enkrypcji, key size jest null");
               // }

            }
            if(keysFromFile!=null){
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Wybierz plik w którym zawarto klucze, padding i rozmiar klucza: ");
                File file = fileChooser.showOpenDialog(primaryStage);
                if (file != null) {
                    try {
                        textToDecrypt = Files.readAllBytes(Path.of(file.getAbsolutePath()));
                        System.out.println("Wybrano plik: " + file.getAbsolutePath());
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
                //file.rea
                        //TU UZYJ SCANNERA?
            }

            if (fileInput != null) {
                fileInput.setOnAction(event -> {
                    FileChooser fileChooser = new FileChooser();
                    fileChooser.setTitle("Wybierz plik do odszyfrowania");
                    File file = fileChooser.showOpenDialog(primaryStage);
                    if (file != null) {
                        try {
                            textToDecrypt = Files.readAllBytes(Path.of(file.getAbsolutePath()));
                            System.out.println("Wybrano plik: " + file.getAbsolutePath());
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    }
                });
            } else {
                System.err.println("Błąd: fileInput nie znaleziono w FXML!");
            }

            if (textInput != null) {
                confirm.setOnAction(event -> {
                    TextInputDialog dialog = new TextInputDialog();
                    dialog.setTitle("Wpisz tekst do odszyfrowania");
                    dialog.setHeaderText("Podaj tekst, który chcesz zaszyfrować:");
                    dialog.setContentText("Tekst:");

                    Optional<String> result = dialog.showAndWait();
                    result.ifPresent(text -> {
                        textToDecrypt = text.getBytes();
                        openKeySelectionScene();
                    });
                });
            }
            else {
                confirm.setOnAction(event -> {

                });

            }


            primaryStage.setScene(new Scene(root, 600, 400));
            primaryStage.setTitle("Cryptography Application");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void openKeySelectionScene() {
        try {
            URL keySelectionFxml = getClass().getResource("/org/example/key_lenght_choice.fxml");
            if (keySelectionFxml == null) {
                throw new RuntimeException("Invalid key selection FXML location");
            }

            FXMLLoader loader = new FXMLLoader(keySelectionFxml);
            Parent keyRoot = loader.load();
            keyRoot.setStyle("-fx-background-color: pink;"); // Ustawienie koloru tła

            RadioButton rb128 = (RadioButton) keyRoot.lookup("#rb128");
            RadioButton rb192 = (RadioButton) keyRoot.lookup("#rb192");
            RadioButton rb256 = (RadioButton) keyRoot.lookup("#rb256");
            Button btnConfirm = (Button) keyRoot.lookup("#btnConfirm");

            ToggleGroup keyLengthGroup = new ToggleGroup();
            rb128.setToggleGroup(keyLengthGroup);
            rb192.setToggleGroup(keyLengthGroup);
            rb256.setToggleGroup(keyLengthGroup);
            rb128.setSelected(true);

            btnConfirm.setOnAction(event -> {
                if (rb128.isSelected()) {
                    selectedKey = 128;
                } else if (rb192.isSelected()) {
                    selectedKey = 192;
                } else if (rb256.isSelected()) {
                    selectedKey = 256;
                }

                System.out.println("Wybrano długość klucza: " + selectedKey);
                encryptText();
            });

            primaryStage.setScene(new Scene(keyRoot, 400, 300));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void encryptText() {
        Encryptor encryptor = new Encryptor(textToEncrypt, selectedKey);
        encryptor.encrypt();
        System.out.println("Zaszyfrowano: " + encryptor.getBlocksList());
        try {
            URL encryptionSucceededFxml = getClass().getResource("/org/example/encryption_succeded.fxml");
            if (encryptionSucceededFxml == null) {
                throw new RuntimeException("Invalid encryption succeeded FXML location");
            }

            FXMLLoader loader = new FXMLLoader(encryptionSucceededFxml);
            Parent keyRoot = loader.load();
            keyRoot.setStyle("-fx-background-color: pink;");

            CheckBox textToFile = (CheckBox) keyRoot.lookup("#textIntoFile");
            CheckBox textIntoProgram = (CheckBox) keyRoot.lookup("#textIntoProgram");
            CheckBox keysToFile = (CheckBox) keyRoot.lookup("#keysIntoFile");
            CheckBox keysToProgram = (CheckBox) keyRoot.lookup("#keysIntoProgram");
            CheckBox goBack = (CheckBox) keyRoot.lookup("#goBack");
            Button confirm = (Button) keyRoot.lookup("#confirm");

            confirm.setOnAction(event -> {
                if (textToFile.isSelected()) {
                    saveToFile("encrypted_text.txt", encryptor.joinEncryptedText());
                }
                if (textIntoProgram.isSelected()) {
                    this.encryptedText = encryptor.joinEncryptedText();
                }
                if (keysToFile.isSelected()) {
                    saveToFile("keys.txt", Arrays.deepToString(encryptor.getRoundKeys()) + "\nPadding: " + encryptor.getPaddingCount() + "\nKey Size: " + encryptor.getKeySize());
                }
                if (keysToProgram.isSelected()) {
                    this.roundKeys = encryptor.getRoundKeys();
                    this.paddedBytes = encryptor.getPaddingCount();
                    this.keySize = encryptor.getKeySize();
                }
                if (goBack.isSelected()) {
                    try {
                        reloadMainScene();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            });

            //Stage stage = (Stage) ((Button) event.getSource()).getScene().getWindow();
            //stage.setScene(new Scene(keyRoot));
            //stage.show();
            primaryStage.setScene(new Scene(keyRoot, 600, 400));
            primaryStage.setTitle("Encryption Successful");
            primaryStage.show();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void saveToFile(String filename, String content) {
        try (FileWriter writer = new FileWriter(filename)) {
            writer.write(content);
            System.out.println("Zapisano do pliku: " + filename);
        } catch (IOException e) {
            System.err.println("Błąd zapisu do pliku: " + e.getMessage());
        }
    }

    private void switchScene(javafx.event.ActionEvent event, String fxmlPath) {
        try {
            URL sceneUrl = getClass().getResource(fxmlPath);
            if (sceneUrl == null) {
                throw new RuntimeException("Invalid FXML path: " + fxmlPath);
            }
            FXMLLoader loader = new FXMLLoader(sceneUrl);
            Parent root = loader.load();
            Stage stage = (Stage) ((Button) event.getSource()).getScene().getWindow();
            stage.setScene(new Scene(root));
            stage.show();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void decryptText() {
        Decryptor decryptor = new Decryptor(textToDecrypt,keySize, roundKeys,paddedBytes);
        decryptor.decrypt();
        System.out.println("Rozszyfrowano: " + decryptor.getDecryptedText());
    }

    public static void main(String[] args) {
        launch();
    }
}
