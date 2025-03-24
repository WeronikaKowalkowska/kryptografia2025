package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ToggleGroup;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.control.Button;
import javafx.scene.control.TextInputDialog;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

public class JavaFxApp extends Application {
    private int selectedKey;
    private String textToEncrypt;
    private Stage primaryStage;

    @Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;

        URL fxmlLocation = getClass().getResource("/org/example/test.fxml");
        if (fxmlLocation == null) {
            throw new RuntimeException("Invalid FXML location");
        }
        FXMLLoader loader = new FXMLLoader(fxmlLocation);
        Parent root = loader.load();

        Button btnEncryptFile = (Button) root.lookup("#btnEncryptFile");
        Button btnEncryptText = (Button) root.lookup("#btnEncryptText");

        if (btnEncryptFile != null) {
            btnEncryptFile.setOnAction(event -> {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Wybierz plik do zaszyfrowania");
                File file = fileChooser.showOpenDialog(primaryStage);
                if (file != null) {
                    try {
                        textToEncrypt = Files.readString(Path.of(file.getAbsolutePath()));
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
                    textToEncrypt = text;
                    openKeySelectionScene();
                });
            });
        } else {
            System.err.println("Błąd: btnEncryptText nie znaleziono w FXML!");
        }

        primaryStage.setTitle("Cryptography Application");
        primaryStage.setScene(new Scene(root, 600, 400));
        primaryStage.show();
    }

    private void openKeySelectionScene() {
        try {
            URL keySelectionFxml = getClass().getResource("/org/example/key_lenght_choice.fxml");
            if (keySelectionFxml == null) {
                throw new RuntimeException("Invalid key selection FXML location");
            }

            FXMLLoader loader = new FXMLLoader(keySelectionFxml);
            Parent keyRoot = loader.load();

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

    private void encryptText() {
        if (textToEncrypt != null && !textToEncrypt.isEmpty()) {
            NewEncryptor encryptor = new NewEncryptor(textToEncrypt, selectedKey);
            encryptor.encrypt();
            System.out.println("Zaszyfrowano: " + encryptor.getBlocksList());
        } else {
            System.err.println("Błąd: Brak tekstu do zaszyfrowania!");
        }
    }

    public static void main(String[] args) {
        launch();
    }
}
