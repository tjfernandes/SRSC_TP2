package org.example;

import java.awt.event.*;
import javax.swing.*;
import java.awt.*;
import java.io.IOException;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class RemoteFileSystemApp extends JFrame {

    public static void main(String[] args) {
        JFrame frame = new JFrame("Remote FS");
        frame.setSize(800, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(35, 35, 35, 35));

        JLabel inputInstruction = new JLabel("Enter your command");
        JTextField commandTextField = new JTextField();
        JTextArea outputText = new JTextArea();
        outputText.setLineWrap(true);
        outputText.setWrapStyleWord(true);
        outputText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputText);
        scrollPane.setPreferredSize(new Dimension(750, 300));

        JButton requestButton = getjButton(commandTextField, outputText);

        panel.add(inputInstruction);
        panel.add(commandTextField);
        panel.add(requestButton);
        panel.add(scrollPane);

        frame.add(panel);
        frame.setVisible(true);
    }

    private static JButton getjButton(JTextField commandTextField, JTextArea outputText) {
        JButton requestButton = new JButton("Request");
        requestButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String command = commandTextField.getText();
                String response = "";
                try {
                    response = requestCommand(command);
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
                outputText.append(response + "\n");
                commandTextField.setText("");
            }
        });
        return requestButton;
    }


    private static String requestCommand(String command) throws IOException {

        String baseUrl = "https://localhost:8080/api";

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
                //url = baseUrl + "/login";

                response = HttpUtils.makeHttpRequest(url, "POST", null);

                return "Response: " + response;

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