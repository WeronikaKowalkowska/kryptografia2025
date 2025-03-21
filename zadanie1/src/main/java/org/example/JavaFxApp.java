package org.example;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

import java.net.URL;

public class JavaFxApp extends Application {
    @Override
    public void start(Stage primaryStage) throws Exception {

        URL fxmlLocation = getClass().getResource("/org/example/test.fxml");
        if (fxmlLocation == null) {
            throw new RuntimeException("blabla!");
        }
        Parent root = FXMLLoader.load(fxmlLocation);
        //Parent root = FXMLLoader.load(getClass().getResource("/org/example/app1.fxml"));
        primaryStage.setTitle("JavaFX Scene Builder Example");
        primaryStage.setScene(new Scene(root, 600, 400));
        primaryStage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}
