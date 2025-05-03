/*
    AES Encryption and Decryption application
    Copyright (C) 2025  Weronika Kowalkowska 251561, Nadzeya Silchankava 253184

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package org.example;

import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

public class DESApp extends Application {

    private ComboBox<Integer> keySizeComboBox;  //wybór długości klucza
    private TextArea inputTextArea;     //pole do wpisania tekstu do zaszyfrowania/deszyfrowania
    private TextArea outputTextArea;    //pole wyświetlające wynik operacji.
    private Button encryptTextButton;
    private Button decryptTextButton;
    private Button encryptFileButton;
    private Button decryptFileButton;
    private Label statusLabel;      //etykieta informująca użytkownika o statusie operacji
    private TextField keyTextField;    //pole do wprowadzenia klucza AES w formacie heksadecymalnym

    private String signature;   // podpis elektroniczny
    private BigInteger p;
    private BigInteger q;
    private BigInteger h;
    private BigInteger b;       // klucz publiczny

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("AES Encryption/Decryption");

        //tworzenie komponentów
        keySizeComboBox = new ComboBox<>();
        keySizeComboBox.getItems().addAll(640, 768, 1024);
        keySizeComboBox.setValue(640);

        inputTextArea = new TextArea();
        inputTextArea.setPromptText("Enter text to sign/check here...");
        inputTextArea.setWrapText(true);

        outputTextArea = new TextArea();
        outputTextArea.setPromptText("Result will appear here...");
        outputTextArea.setWrapText(true);
        outputTextArea.setEditable(false);

        encryptTextButton = new Button("Sign Text");
        decryptTextButton = new Button("Check Text");
        encryptFileButton = new Button("Sign File");
        decryptFileButton = new Button("Check File");

        statusLabel = new Label();
        statusLabel.setStyle("-fx-text-fill: #ee00ff;");

        keyTextField = new TextField();
        keyTextField.setPromptText("Enter public key for verification");
        keyTextField.setVisible(false);

        //ustawienie akcji dla przycisków
        encryptTextButton.setOnAction(e -> encryptText());
        decryptTextButton.setOnAction(e -> decryptText());
        encryptFileButton.setOnAction(e -> encryptFile(primaryStage));
        decryptFileButton.setOnAction(e -> decryptFile(primaryStage));

        //dodawanie układów
        HBox keySizeBox = new HBox(10, new Label("Key Size (bits):"), keySizeComboBox);
        keySizeBox.setAlignment(Pos.CENTER_LEFT);

        HBox textButtons = new HBox(10, encryptTextButton, decryptTextButton);
        textButtons.setAlignment(Pos.CENTER);

        HBox fileButtons = new HBox(10, encryptFileButton, decryptFileButton);
        fileButtons.setAlignment(Pos.CENTER);

        VBox leftVBox = new VBox(10, new Label("Input:"), inputTextArea, textButtons);
        VBox rightVBox = new VBox(10, new Label("Output:"), outputTextArea, fileButtons, keyTextField);

        HBox mainContent = new HBox(20, leftVBox, rightVBox);
        mainContent.setPadding(new Insets(10));

        VBox root = new VBox(15, keySizeBox, mainContent, statusLabel);
        root.setPadding(new Insets(15));
        root.setStyle("-fx-background-color: pink;");

        //ustawienie rozmiaru okienek
        inputTextArea.setPrefSize(300, 200);
        outputTextArea.setPrefSize(300, 200);

        Scene scene = new Scene(root, 700, 450);
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    //metoda w przypadku wyboru szyfrowania tekstu
    private void encryptText() {
        String text = inputTextArea.getText();
        if (text.isEmpty()) {
            showStatus("Please enter text to create electronic signature", "red");
            return;
        }

        try {
            //pobiera wybrany rozmiar klucza
            int keySize = keySizeComboBox.getValue();
            byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);

            Encryptor encryptor = new Encryptor(keySize, textBytes);
            p = encryptor.getP();
            q = encryptor.getQ();
            h = encryptor.getH();
            b = encryptor.getB();
            signature = encryptor.getClenSignature();

            String publicKey = encryptor.getB().toString();

            outputTextArea.setText(signature);
            showStatus("Electronic signature created successfully with " + keySize + "-bit key", "green");

            //pokazanie klucza głównego
            keyTextField.setVisible(true);
            keyTextField.setText(publicKey);
        } catch (Exception e) {
            showStatus("Error during the process: " + e.getMessage(), "red");
            e.printStackTrace();
        }
    }

    //metoda w przypadku wyboru deszyfrowania tekstu
    private void decryptText() {
        String text = inputTextArea.getText().trim();    //.trim() w do usuwania białych znaków
        if (text.isEmpty()) {
            showStatus("Please enter string to check", "red");
            return;
        }

        String hexKey = keyTextField.getText().trim();  //.trim() w do usuwania białych znaków
        if (hexKey.isEmpty()) {
            showStatus("Please enter the public key", "red");
            return;
        }

        //sprawdzenie, czy podany klucz ma odpowiedni rozmiar
        try {
            BigInteger keyBigInt = new BigInteger(hexKey);

            byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);

            Decryptor decryptor = new Decryptor(signature ,textBytes, p, q, h, keyBigInt);

            boolean result = decryptor.isSignatureValid;
            String resultStr = null;
            if (result) {
                resultStr = "Signature verified successfully";
            } else {
                resultStr = "Signature verification failed";
            }

            outputTextArea.setText(resultStr);
            showStatus("Text verified", "green");
        } catch (Exception e) {
            showStatus("Error during the process: " + e.getMessage(), "red");
            e.printStackTrace();
        }
    }

    //metoda w przypadku wyboru szyfrowania pliku
    private void encryptFile(Stage primaryStage) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File to Sign");
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            try {
                //pobiera wybrany rozmiar klucza
                int keySize = keySizeComboBox.getValue();
                //odczytanie tekstu z pliku
                Path path = file.toPath();
                byte[] fileBytes = Files.readAllBytes(path);

                Encryptor encryptor = new Encryptor(keySize, fileBytes);
                p = encryptor.getP();
                q = encryptor.getQ();
                h = encryptor.getH();
                b = encryptor.getB();
                signature = encryptor.getClenSignature();

                String publicKey = encryptor.getB().toString();

                //wybór pliku do zapisu podpisu
                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Save Signature to File");
                saveChooser.setInitialFileName(file.getName() + ".txt");
                File saveFile = saveChooser.showSaveDialog(primaryStage);

                if (saveFile != null) {
                    //zapis podpisu do pliku
                    Files.writeString(saveFile.toPath(), signature);
                    showStatus("File signed successfully with " + keySize + "-bit key and saved to " + saveFile.getName(), "green");

                    outputTextArea.setText("File signed successfully!");
                    keyTextField.setVisible(true);
                    //wyświetlenie klucza publicznego
                    keyTextField.setText(publicKey);
                }
            } catch (Exception e) {
                showStatus("Error during the process: " + e.getMessage(), "red");
                e.printStackTrace();
            }
        }
    }

    //metoda w przypadku wyboru deszyfrowania pliku
    private void decryptFile(Stage primaryStage) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File to Check");
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            try {
                String hexKey = keyTextField.getText().trim();       //.trim() w do usuwania białych znaków
                if (hexKey.isEmpty()) {
                    TextInputDialog keyDialog = new TextInputDialog();
                    keyDialog.setTitle("Verification Key Needed");
                    keyDialog.setHeaderText("Enter the public key");
                    keyDialog.setContentText("Key:");
                    keyDialog.getEditor().setPrefWidth(400);

                    hexKey = keyDialog.showAndWait().orElse("");
                    if (hexKey.isEmpty()) {
                        showStatus("Verification cancelled - key required", "red");
                        return;
                    }
                }

                 BigInteger keyBigInt = new BigInteger(hexKey);

                //odczytanie szyfrogramu z pliku
                byte[] encryptedBytes = Files.readAllBytes(file.toPath());

                Decryptor decryptor = new Decryptor(signature ,encryptedBytes, p, q, h, keyBigInt);

                boolean result = decryptor.isSignatureValid;
                String resultStr = null;
                if (result) {
                    resultStr = "Signature verified successfully";
                } else {
                    resultStr = "Signature verification failed";
                }

                byte[] decryptedBytes = resultStr.getBytes(StandardCharsets.UTF_8);

                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Save result to File");
                String originalName = file.getName();
                if (originalName.endsWith(".txt")) {
                    originalName = originalName.substring(0, originalName.length() - 4);    //usuwanie formatu .enc, żeby wynikowy format był taki jak pliku przez szyfrowaniem
                }
                saveChooser.setInitialFileName(originalName);
                File saveFile = saveChooser.showSaveDialog(primaryStage);

                if (saveFile != null) {
                    //zapis odszyfrowanego tesku do pliku
                    Files.write(saveFile.toPath(), decryptedBytes);
                    showStatus("File verified and result saved to " + saveFile.getName(), "green");
                    outputTextArea.setText("File verified!");
                    keyTextField.setText(hexKey);
                    keyTextField.setVisible(true);
                }
            } catch (Exception e) {
                showStatus("Error during the process: " + e.getMessage(), "red");
                e.printStackTrace();
            }
        }
    }

    //metoda do wyświetlenia statusu operacji
    private void showStatus(String message, String color) {
        statusLabel.setText(message);
        statusLabel.setStyle("-fx-text-fill: " + color + ";");
    }

}