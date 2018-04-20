package main;

import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.AnchorPane;
import javafx.scene.paint.Paint;
import javafx.stage.FileChooser;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.net.URL;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.Date;
import java.util.ResourceBundle;

public class CertValidController implements Initializable {

    public Button cauta;
    public Label issuer;
    public Label sn;
    public Label subject;
    public Label sa;
    public Label nb;
    public Label na;
    public Label actionStatus;
    public AnchorPane structura;
    public Label versiune;
    public Label ski;
    public Label aia;

    public Boolean valid;
    public Label cp;
    public Label cdp;
    public Label status;

    @FXML
    private void open(){

        FileChooser fileChooser = new FileChooser();
        File selectedFile = fileChooser.showOpenDialog(null);
        if (selectedFile != null) {
            actionStatus.setTextFill(Paint.valueOf("green"));
            actionStatus.setText("Certificat selectat: " + selectedFile.getName());
        }
        else {
            actionStatus.setTextFill(Paint.valueOf("red"));
            actionStatus.setText("Alegerea a fost anulata.");
        }

        CertificateFactory fact = null;
        try {
            fact = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        FileInputStream is = null;
        try {
            is = new FileInputStream(selectedFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        X509Certificate cer = null;
        try {
            cer = (X509Certificate) fact.generateCertificate(is);
            valid = true;
            structura.setVisible(true); //afisam blocul cu informatii

            PublicKey key = cer.getPublicKey(); //Salvam cheia publica a certificatului

            if(cer.getSerialNumber().toString() != null) {//Serial number
                sn.setTextFill(Paint.valueOf("green"));
                sn.setText(cer.getSerialNumber().toString());
            }
            else{
                sn.setTextFill(Paint.valueOf("red"));
                sn.setText("Inexistent");
                valid = false;
            }

            if(cer.getSigAlgName() == "SHA256withRSA") {//Signature Algorithm
                sa.setTextFill(Paint.valueOf("green"));
                sa.setText(cer.getSigAlgName());
            }
            else{
                sa.setTextFill(Paint.valueOf("red"));
                sa.setText(cer.getSigAlgName());
                valid = false;
            }

            if(cer.getIssuerDN().toString() != null) {//Issuer
                issuer.setTextFill(Paint.valueOf("green"));
                issuer.setText(cer.getIssuerDN().toString());
            }
            else{
                issuer.setTextFill(Paint.valueOf("red"));
                issuer.setText("Inexistent");
                valid = false;
            }

            if(cer.getSubjectDN().toString() != null) {//Subject
                subject.setTextFill(Paint.valueOf("green"));
                subject.setText(cer.getSubjectDN().toString());
            }
            else{
                subject.setTextFill(Paint.valueOf("red"));
                subject.setText("Inexistent");
                valid = false;
            }

            if(cer.getNotBefore().before(new Date()) && cer.getNotAfter().after(new Date())){ //Not Before, Not After

                nb.setTextFill(Paint.valueOf("green"));
                na.setTextFill(Paint.valueOf("green"));
                nb.setText(cer.getNotBefore().toString());
                na.setText(cer.getNotAfter().toString());

            }
            else{

                nb.setTextFill(Paint.valueOf("red"));
                na.setTextFill(Paint.valueOf("red"));
                nb.setText(cer.getNotBefore().toString());
                na.setText(cer.getNotAfter().toString());
                valid = false;
            }

            if(cer.getVersion() == 3) { //Versiune certificat x509

                versiune.setTextFill(Paint.valueOf("green"));
                versiune.setText(Integer.toString(cer.getVersion()));
            }
            else{

                versiune.setTextFill(Paint.valueOf("red"));
                versiune.setText(Integer.toString(cer.getVersion()));
                valid = false;
            }

            if(cer.getExtensionValue("2.5.29.14") != null){
                ski.setTextFill(Paint.valueOf("green"));
                ski.setText(bytesToHex(cer.getExtensionValue("2.5.29.14")));
            }
            else{
                ski.setTextFill(Paint.valueOf("red"));
                ski.setText("Nu exista campul");
                valid = false;
            }


            if(cer.getExtensionValue("1.3.6.1.5.5.7.1.1") != null){
                aia.setTextFill(Paint.valueOf("green"));
                aia.setText("Campul exista, momentan nu se valideaza OCSP");
            }
            else{
                aia.setTextFill(Paint.valueOf("red"));
                aia.setText("Nu exista campul");
                valid = false;
            }

            if(cer.getExtensionValue("2.5.29.32") != null){
                cp.setTextFill(Paint.valueOf("green"));
                cp.setText("Campul exista, momentan nu se valideaza online");
            }
            else{
                cp.setTextFill(Paint.valueOf("red"));
                cp.setText("Nu exista campul");
                valid = false;
            }

            if(cer.getExtensionValue("2.5.29.31") != null){
                cdp.setTextFill(Paint.valueOf("green"));
                cdp.setText("Campul exista, momentan nu se valideaza online");
            }
            else{
                cdp.setTextFill(Paint.valueOf("red"));
                cdp.setText("Nu exista campul");
                valid = false;
            }

            if(valid){
                status.setTextFill(Paint.valueOf("green"));
                status.setText("Certificatul este conform");
            }
            else{
                status.setTextFill(Paint.valueOf("red"));
                status.setText("Certificatul nu este conform");
            }


        } catch (CertificateException e) {
            valid = false;
            actionStatus.setTextFill(Paint.valueOf("red"));
            actionStatus.setText("Eroare la incarcarea certificatului!");
            structura.setVisible(false);
            e.printStackTrace();
        }

    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {

        structura.setVisible(false);

    }
}
