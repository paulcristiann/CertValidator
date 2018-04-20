package main;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.fxml.JavaFXBuilderFactory;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;

import java.io.InputStream;

public class Main extends Application {


    private static Stage stage;
    private Scene scene = null;

    @Override
    public void start(Stage primaryStage) throws Exception{

        try {
            stage = primaryStage;
            stage.setMinWidth(700);
            stage.setMinHeight(700);
            stage.setTitle("Validator certificate x509");
            //stage.setFullScreen(true);
            openValidator();
            primaryStage.show();
        } catch (Exception ex) {

        }

    }


    public static void main(String[] args) {
        launch(args);
    }

    private void openValidator() {
        try {
            CertValidController validator = (CertValidController) replaceSceneContent("CertValid.fxml");
        } catch (Exception ex) {
            System.out.println(ex);
        }
    }

    private Initializable replaceSceneContent(String fxml) throws Exception {
        FXMLLoader loader = new FXMLLoader();
        InputStream in = Main.class.getResourceAsStream(fxml);
        loader.setBuilderFactory(new JavaFXBuilderFactory());
        loader.setLocation(Main.class.getResource(fxml));
        AnchorPane page;
        try {
            page = loader.load(in);
        } finally {
            in.close();
        }
        scene = new Scene(page);

        stage.setScene(scene);
        stage.sizeToScene();
        return (Initializable) loader.getController();
    }

}
