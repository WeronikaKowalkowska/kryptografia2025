import javafx.application.Application;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

public class AESApp extends Application {

    private ComboBox<Integer> keySizeComboBox;  //wybór długości klucza
    private TextArea inputTextArea;     //pole do wpisania tekstu do zaszyfrowania/deszyfrowania
    private TextArea outputTextArea;    //pole wyświetlające wynik operacji.
    private Button encryptTextButton;
    private Button decryptTextButton;
    private Button encryptFileButton;
    private Button decryptFileButton;
    private Label statusLabel;      //etykieta informująca użytkownika o statusie operacji
    private TextField keyTextField;    //pole do wprowadzenia klucza AES w formacie heksadecymalnym

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("AES Encryption/Decryption");

        //tworzenie komponentów
        keySizeComboBox = new ComboBox<>();
        keySizeComboBox.getItems().addAll(128, 192, 256);
        keySizeComboBox.setValue(128);

        inputTextArea = new TextArea();
        inputTextArea.setPromptText("Enter text to encrypt/decrypt here...");
        inputTextArea.setWrapText(true);

        outputTextArea = new TextArea();
        outputTextArea.setPromptText("Result will appear here...");
        outputTextArea.setWrapText(true);
        outputTextArea.setEditable(false);

        encryptTextButton = new Button("Encrypt Text");
        decryptTextButton = new Button("Decrypt Text");
        encryptFileButton = new Button("Encrypt File");
        decryptFileButton = new Button("Decrypt File");

        statusLabel = new Label();
        statusLabel.setStyle("-fx-text-fill: #ee00ff;");

        keyTextField = new TextField();
        keyTextField.setPromptText("Enter encryption key (hex) for decryption");
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
            showStatus("Please enter text to encrypt", "red");
            return;
        }

        try {
            //pobiera wybrany rozmiar klucza
            int keySize = keySizeComboBox.getValue();
            byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);

            Encryptor encryptor = new Encryptor(textBytes, keySize);
            encryptor.encrypt();

            byte[] encryptedBytes = encryptor.joinEncryptedText();
            String hexResult = bytesToHex(encryptedBytes);
            String hexKey = bytesToHex(encryptor.getMainKey());

            outputTextArea.setText(hexResult);
            showStatus("Text encrypted successfully with " + keySize + "-bit key", "green");

            //pokazanie klucza głównego
            keyTextField.setVisible(true);
            keyTextField.setText(hexKey);
        } catch (Exception e) {
            showStatus("Error during encryption: " + e.getMessage(), "red");
            e.printStackTrace();
        }
    }

    //metoda w przypadku wyboru deszyfrowania tekstu
    private void decryptText() {
        String text = inputTextArea.getText().trim();    //.trim() w do usuwania białych znaków
        if (text.isEmpty()) {
            showStatus("Please enter hex string to decrypt", "red");
            return;
        }

        String hexKey = keyTextField.getText().trim();  //.trim() w do usuwania białych znaków
        if (hexKey.isEmpty()) {
            showStatus("Please enter the encryption key", "red");
            return;
        }

        //sprawdzenie, czy podany klucz ma odpowiedni rozmiar
        try {
            byte[] keyBytes = hexToBytes(hexKey);
            int keySize = keyBytes.length * 8;

            if (keySize != 128 && keySize != 192 && keySize != 256) {
                showStatus("Invalid key size. Must be 128, 192 or 256 bits", "red");
                return;
            }

            byte[] encryptedBytes = hexToBytes(text);

            Decryptor decryptor = new Decryptor(encryptedBytes, keySize, keyBytes);
            decryptor.decrypt();

            byte[] decryptedBytes = decryptor.removePadding();
            String result = new String(decryptedBytes, StandardCharsets.UTF_8);

            outputTextArea.setText(result);
            showStatus("Text decrypted successfully", "green");
        } catch (Exception e) {
            showStatus("Error during decryption: " + e.getMessage(), "red");
            e.printStackTrace();
        }
    }

    //metoda w przypadku wyboru szyfrowania pliku
    private void encryptFile(Stage primaryStage) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File to Encrypt");
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            try {
                //pobiera wybrany rozmiar klucza
                int keySize = keySizeComboBox.getValue();
                //odczytanie tekstu z pliku
                byte[] fileBytes = Files.readAllBytes(file.toPath());

                Encryptor encryptor = new Encryptor(fileBytes, keySize);
                encryptor.encrypt();

                byte[] encryptedBytes = encryptor.joinEncryptedText();
                String hexKey = bytesToHex(encryptor.getMainKey());

                //wybór pliku do zapisu szyfrogramu
                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Save Encrypted File");
                saveChooser.setInitialFileName(file.getName() + ".txt");
                File saveFile = saveChooser.showSaveDialog(primaryStage);

                if (saveFile != null) {
                    //zapis szyfrogramu do pliku
                    Files.write(saveFile.toPath(), encryptedBytes);
                    showStatus("File encrypted successfully with " + keySize + "-bit key and saved to " + saveFile.getName(), "green");

                    outputTextArea.setText("File encrypted successfully!");
                    keyTextField.setVisible(true);
                    //wyświetlenie klucza głownego
                    keyTextField.setText(hexKey);
                }
            } catch (Exception e) {
                showStatus("Error during file encryption: " + e.getMessage(), "red");
                e.printStackTrace();
            }
        }
    }

    //metoda w przypadku wyboru deszyfrowania pliku
    private void decryptFile(Stage primaryStage) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select File to Decrypt");
        File file = fileChooser.showOpenDialog(primaryStage);

        if (file != null) {
            try {
                String hexKey = keyTextField.getText().trim();       //.trim() w do usuwania białych znaków
                if (hexKey.isEmpty()) {
                    TextInputDialog keyDialog = new TextInputDialog();
                    keyDialog.setTitle("Decryption Key Needed");
                    keyDialog.setHeaderText("Enter the encryption key (in hex format)");
                    keyDialog.setContentText("Key:");
                    keyDialog.getEditor().setPrefWidth(400);

                    hexKey = keyDialog.showAndWait().orElse("");
                    if (hexKey.isEmpty()) {
                        showStatus("Decryption cancelled - key required", "red");
                        return;
                    }
                }

                byte[] keyBytes = hexToBytes(hexKey);
                int keySize = keyBytes.length * 8;

                //sprawdzenie, czy podany klucz ma odpowiedni rozmiar
                if (keySize != 128 && keySize != 192 && keySize != 256) {
                    showStatus("Invalid key size. Must be 128, 192 or 256 bits", "red");
                    return;
                }

                //odczytanie szyfrogramu z pliku
                byte[] encryptedBytes = Files.readAllBytes(file.toPath());

                Decryptor decryptor = new Decryptor(encryptedBytes, keySize, keyBytes);
                decryptor.decrypt();

                byte[] decryptedBytes = decryptor.removePadding();

                FileChooser saveChooser = new FileChooser();
                saveChooser.setTitle("Save Decrypted File");
                String originalName = file.getName();
                if (originalName.endsWith(".txt")) {
                    originalName = originalName.substring(0, originalName.length() - 4);    //usuwanie formatu .enc, żeby wynikowy format był taki jak pliku przez szyfrowaniem
                }
                saveChooser.setInitialFileName(originalName);
                File saveFile = saveChooser.showSaveDialog(primaryStage);

                if (saveFile != null) {
                    //zapis odszyfrowanego tesku do pliku
                    Files.write(saveFile.toPath(), decryptedBytes);
                    showStatus("File decrypted successfully and saved to " + saveFile.getName(), "green");
                    outputTextArea.setText("File decrypted successfully!");
                    keyTextField.setText(hexKey);
                    keyTextField.setVisible(true);
                }
            } catch (Exception e) {
                showStatus("Error during file decryption: " + e.getMessage(), "red");
                e.printStackTrace();
            }
        }
    }

    //metoda do wyświetlenia statusu operacji
    private void showStatus(String message, String color) {
        statusLabel.setText(message);
        statusLabel.setStyle("-fx-text-fill: " + color + ";");
    }

    //metoda do konwersji bitów na napis heksadecymalny
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    //metoda do konwersji napisu heksadecymalnego na bity
    private static byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("[^0-9A-Fa-f]", ""); //usuwa nieistniejące znaki
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}