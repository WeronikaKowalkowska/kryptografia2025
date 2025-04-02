package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.stage.Stage;

import java.io.IOException;
import java.net.URL;

public class JavaFxApp2 extends Application {

    private int selectedKeyLength;
    private byte[] mainKey;
    private byte [][] roundKeys;

    private byte[] textToEncrypt;
    private int paddedBytes;
    private String encryptedText;
    private String decryptedText;

    private Stage primaryStage;


    @Override
    public void start(Stage primaryStage) throws Exception {
        this.primaryStage = primaryStage;
        reloadMainScene();
    }

    public void reloadMainScene() throws IOException {
        URL initialFxmlLocation = getClass().getResource("/org/example/encryption_or_decryption_main.fxml");
        if (initialFxmlLocation == null) {
            throw new RuntimeException("Invalid Initial FXML location");
        }
        FXMLLoader loader = new FXMLLoader(initialFxmlLocation);
        Parent initialRoot = loader.load();
        initialRoot.setStyle("-fx-background-color: pink;"); //ustawienie koloru tła

        Button btnEncryption = (Button) initialRoot.lookup("#btnEncryption");
        Button btnDecryption = (Button) initialRoot.lookup("#btnDecryption");

        if (btnEncryption != null) {
            btnEncryption.setOnAction(event -> openEncryptionScene());
        }

        if (btnDecryption != null) {
            btnDecryption.setOnAction(event -> openDecryptionScene());
        }
        
        primaryStage.setTitle("Choose Operation");
        primaryStage.setScene(new Scene(initialRoot, 640, 400));
        primaryStage.show();
    }

    private void openDecryptionScene() {

    }

    private void openEncryptionScene() {
    }

}
