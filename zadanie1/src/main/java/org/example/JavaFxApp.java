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
    public int selectedKey;
    @Override
    public void start(Stage primaryStage) throws Exception {
        // Załaduj plik FXML
        URL fxmlLocation = getClass().getResource("/org/example/test.fxml");
        if (fxmlLocation == null) {
            throw new RuntimeException("Invalid FXML location");
        }
        FXMLLoader loader = new FXMLLoader(fxmlLocation);
        Parent root = loader.load();

        // Pobranie przycisków z FXML
        Button btnEncryptFile = (Button) root.lookup("#btnEncryptFile");
        Button btnEncryptText = (Button) root.lookup("#btnEncryptText");

        // Obsługa kliknięcia na "Encrypt file"
        if (btnEncryptFile != null) {
            btnEncryptFile.setOnAction(event ->  {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Wybierz plik do zaszyfrowania");
                File file = fileChooser.showOpenDialog(primaryStage);
                String text;
                if (file != null) {
                    System.out.println("Wybrano plik: " + file.getAbsolutePath());
                }
                try {
                     text= Files.readString(Path.of(file.getAbsolutePath())) ;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                openKeySelectionScene(primaryStage, 'a');
                NewEncryptor encryptor = new NewEncryptor(text, this.selectedKey);
                encryptor.encrypt();
                System.out.println("Zaszyfrowano: "+encryptor.getBlocksList());

            });
        } else {
            System.err.println("Błąd: btnEncryptFile nie znaleziono w FXML!");
        }

        // Obsługa kliknięcia na "Encrypt plain text"
        if (btnEncryptText != null) {
            btnEncryptText.setOnAction(event -> {
                TextInputDialog dialog = new TextInputDialog();
                dialog.setTitle("Wpisz tekst do zaszyfrowania");
                dialog.setHeaderText("Podaj tekst, który chcesz zaszyfrować:");
                dialog.setContentText("Tekst:");

                Optional<String> result = dialog.showAndWait();
                String newText = result.orElse("");
                result.ifPresent(text -> System.out.println("Wpisany tekst: " + text));
                openKeySelectionScene(primaryStage,'b');
                NewEncryptor encryptor = new NewEncryptor(newText, this.selectedKey);
                System.out.println('a');
                encryptor.encrypt();
                System.out.println('b');
                System.out.println("Zaszyfrowano: "+encryptor.getBlocksList());
            });
        } else {
            System.err.println("Błąd: btnEncryptText nie znaleziono w FXML!");
        }

        // Ustawienie sceny
        primaryStage.setTitle("Cryptography Application");
        primaryStage.setScene(new Scene(root, 600, 400));
        primaryStage.show();
    }
    private void openKeySelectionScene(Stage primaryStage, char input ) {
        try {
            URL keySelectionFxml = getClass().getResource("/org/example/key_lenght_choice.fxml");
            if (keySelectionFxml == null) {
                throw new RuntimeException("Invalid key selection FXML location");
            }

            FXMLLoader loader = new FXMLLoader(keySelectionFxml);
            Parent keyRoot = loader.load();

            // Pobranie przycisków z FXML
            RadioButton rb128 = (RadioButton) keyRoot.lookup("#rb128");
            RadioButton rb192 = (RadioButton) keyRoot.lookup("#rb192");
            RadioButton rb256 = (RadioButton) keyRoot.lookup("#rb256");
            Button btnConfirm = (Button) keyRoot.lookup("#btnConfirm");

            // Ustawienie ToggleGroup
            ToggleGroup keyLengthGroup = new ToggleGroup();
            rb128.setToggleGroup(keyLengthGroup);
            rb192.setToggleGroup(keyLengthGroup);
            rb256.setToggleGroup(keyLengthGroup);
            rb128.setSelected(true); // Domyślna wartość

            btnConfirm.setOnAction(event -> {
                 this.selectedKey = 128; // Domyślna wartość
                if (rb192.isSelected()) {
                    this.selectedKey = 192;
                } else if (rb256.isSelected()) {
                    this.selectedKey = 256;
                }

                System.out.println("Wybrano długość klucza: " + this.selectedKey);

                // Wyświetlenie nowej sceny lub zamknięcie wyboru
                //primaryStage.setScene(new Scene(keyRoot, 400, 300));

            });

            primaryStage.setScene(new Scene(keyRoot, 400, 300));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }



    public static void main(String[] args) {
        launch();
    }
}
