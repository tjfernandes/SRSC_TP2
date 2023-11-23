package org.example;

import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.prefs.Preferences;

public class RemoteFileSystemApp extends Application {

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) throws Exception {
        stage.setTitle("Remote FS");

        TextField commandTextField = new TextField();
        TextArea outputTextArea = new TextArea();
        Button requestButton = new Button("Request");

        requestButton.setOnAction(e -> {
            String command = commandTextField.getText();
            String response = "";
            try {
                response = requestCommand(command);
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            outputTextArea.appendText(response + "\n");
            commandTextField.clear();
        });

        VBox layout = new VBox(10);
        layout.getChildren().addAll(commandTextField, requestButton, outputTextArea);

        Scene scene = new Scene(layout, 300, 200);

        stage.setScene(scene);

        stage.show();
    }

    private String requestCommand(String command) throws IOException {

        String baseUrl = "http:/localhost:8080/api";

        String url = "";

        String jwtToken = null;

        String response = "";

        String[] fullCommand = command.split("\\s+");

        String commandName = fullCommand[0];

        switch (commandName) {
            case "login":

                String username = fullCommand[1];
                String password = fullCommand[2];
                String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8);
                String encodedPassword = URLEncoder.encode(password, StandardCharsets.UTF_8);

                url = baseUrl + "/login?username=" + encodedUsername + "&password=" + encodedPassword;

                response = HttpUtils.makeHttpRequest(url, "POST", null);

                String jwtTkn = JwtTokenUtils.extractJwtToken(response);
                if (jwtTkn != null) {
                    JwtTokenUtils.storeToken(jwtTkn);
                } else {
                    return "Bad Response...";
                }

                return "JWT token: " + jwtTkn;

            case "ls":

                jwtToken = JwtTokenUtils.getStoredToken();

                String usernameLs = fullCommand[1];
                String pathLs = fullCommand[2];
                String encodedUsernameLs = URLEncoder.encode(usernameLs, StandardCharsets.UTF_8);
                String encodedPathLs = URLEncoder.encode(pathLs, StandardCharsets.UTF_8);

                url = baseUrl + "/ls?username=" + encodedUsernameLs + "&path=" + encodedPathLs;

                response = HttpUtils.makeHttpRequest(url, "GET", jwtToken);
                return "Response: " + response;

            case "mkdir":

                jwtToken = JwtTokenUtils.getStoredToken();

                String usernameMkDir = fullCommand[1];
                String pathMkDir = fullCommand[2];
                String encodedUsernameMkDir = URLEncoder.encode(usernameMkDir, StandardCharsets.UTF_8);
                String encodedPathMkDir = URLEncoder.encode(pathMkDir, StandardCharsets.UTF_8);

                url = baseUrl + "/mkdir?username=" + encodedUsernameMkDir + "&path=" + encodedPathMkDir;

                response = HttpUtils.makeHttpRequest(url, "POST", jwtToken);
                return "Response: " + response;

            case "put":
                jwtToken = JwtTokenUtils.getStoredToken();

                String usernamePut = fullCommand[1];
                String filePut = fullCommand[2];
                String encodedUsernamePut = URLEncoder.encode(usernamePut, StandardCharsets.UTF_8);
                String encodedFilePut = URLEncoder.encode(filePut, StandardCharsets.UTF_8);

                url = baseUrl + "/mkdir?username=" + encodedUsernamePut + "&file=" + encodedFilePut;

                response = HttpUtils.makeHttpRequest(url, "POST", jwtToken);
                return "Response: " + response;
            case "get":
                jwtToken = JwtTokenUtils.getStoredToken();

                String usernameGet = fullCommand[1];
                String fileGet = fullCommand[2];
                String encodedUsernameGet = URLEncoder.encode(usernameGet, StandardCharsets.UTF_8);
                String encodedFileGet = URLEncoder.encode(fileGet, StandardCharsets.UTF_8);

                url = baseUrl + "/get?username=" + encodedUsernameGet + "&file=" + encodedFileGet;

                response = HttpUtils.makeHttpRequest(url, "GET", jwtToken);
                return "Response: " + response;
            case "cp":
                jwtToken = JwtTokenUtils.getStoredToken();

                String usernameCp = fullCommand[1];
                String srcFile = fullCommand[2];
                String destFile = fullCommand[3];
                String encodedUsernameCp = URLEncoder.encode(usernameCp, StandardCharsets.UTF_8);
                String encodedSrcFile = URLEncoder.encode(srcFile, StandardCharsets.UTF_8);
                String encodedDestFile = URLEncoder.encode(destFile, StandardCharsets.UTF_8);

                url = baseUrl + "/cp?username=" + encodedUsernameCp + "&srcFile=" + encodedSrcFile + "&destFile=" + encodedDestFile;

                response = HttpUtils.makeHttpRequest(url, "PUT", jwtToken);
                return "Response: " + response;
            case "rm":
                jwtToken = JwtTokenUtils.getStoredToken();

                String usernameDelete = fullCommand[1];
                String fileDelete = fullCommand[2];
                String encodedUsernameDelete = URLEncoder.encode(usernameDelete, StandardCharsets.UTF_8);
                String encodedFileDelete = URLEncoder.encode(fileDelete, StandardCharsets.UTF_8);

                url = baseUrl + "/get?username=" + encodedUsernameDelete + "&file=" + encodedFileDelete;

                response = HttpUtils.makeHttpRequest(url, "DELETE", jwtToken);
                return "Response: " + response;
            case "file":
                jwtToken = JwtTokenUtils.getStoredToken();

                String file = fullCommand[1];
                String encodedFile = URLEncoder.encode(file, StandardCharsets.UTF_8);

                url = baseUrl + "/get?file=" + encodedFile;

                response = HttpUtils.makeHttpRequest(url, "GET", jwtToken);
                return "Response: " + response;
            default:
                throw new InvalidCommandException("This command is invalid");
        }

    }

}