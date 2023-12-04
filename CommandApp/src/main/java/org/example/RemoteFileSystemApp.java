package org.example;


import org.example.utils.RequestAuthenticationMessage;
import org.example.utils.ResponseAuthenticationMessage;
import org.example.utils.ResponseTGSMessage;
import org.example.utils.Wrapper;

import java.awt.event.*;
import javax.crypto.SecretKey;
import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.KeyStore;
import java.time.Duration;
import java.time.LocalDateTime;

public class RemoteFileSystemApp {

    public static final String[] CONFPROTOCOLS     = {"TLSv1.2"};
    public static final String[] CONFCIPHERSUITES  = {"TLS_RSA_WITH_AES_256_CBC_SHA256"};
    public static final String KEYSTORE_TYPE       = "JKS";
    public static final String KEYSTORE_PASSWORD   = "client_password";
    public static final String KEYSTORE_PATH       = "/keystore.jks";
    public static final String TRUSTSTORE_TYPE     = "JKS";
    public static final char[] TRUSTSTORE_PASSWORD = "client_truststore_password".toCharArray();
    public static final String TRUSTSTORE_PATH     = "/truststore.jks";
    public static final String TLS_VERSION         = "TLSv1.2";
    public static final String DISPATCHER_HOST     = "localhost";
    public static final int DISPATCHER_PORT        = 8080;

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

        try {
            SSLSocket socket = initTLSSocket();

            // Communication logic with the server
            ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());

            String[] fullCommand = command.split("\\s+");

            byte messageType;
            if (fullCommand[0].equals("login")) {
                processLogin(ois, oos);
            }



        } catch (Exception e) {
            e.printStackTrace();
        }
        return "response";
    }

    private static void processLogin(ObjectInputStream ois, ObjectOutputStream oos) {
        try {
            sendRequest(ois, oos, (byte) 1);
            sendRequest(ois, oos, (byte) 3);
            sendRequest(ois, oos, (byte) 5);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void sendRequest(ObjectInputStream ois, ObjectOutputStream oos, byte messageType) {
        try {
            byte[] requestMessageSerialized = getRequestMessageSerialized(messageType);

            // Create wrapper object with serialized request message for auth and its type
            Wrapper authWrapper = new Wrapper(messageType, requestMessageSerialized);

            // Send wrapper to dispatcher
            oos.writeObject(authWrapper);
            oos.flush();

            // handle response
            Wrapper authWrapperResponse = (Wrapper) ois.readObject();
            processResponse(authWrapperResponse);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] getRequestMessageSerialized(byte messageType) throws IOException {
        Object requestMessage = null;
        switch (messageType) {
            case (byte) 1:
                requestMessage = new RequestAuthenticationMessage("client", "localhost", "storage");
                break;
            case (byte) 3:
                //requestMessage =
                break;
            case (byte) 5:
                //
                break;
            default: break;
        }
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);

        objectOutputStream.writeObject(requestMessage);
        byte[] requestMessageSerialized = byteArrayOutputStream.toByteArray();
        return requestMessageSerialized;
    }

    private static void processResponse(Wrapper wrapper) {
        try {
            ObjectInputStream objectInputStream = null;
            switch(wrapper.getMessageType()) {
                case (byte) 2:
                    objectInputStream = new ObjectInputStream(new ByteArrayInputStream(wrapper.getMessage()));
                    ResponseAuthenticationMessage responseAuth = (ResponseAuthenticationMessage) objectInputStream.readObject();

                    byte[] encryptedTGT = responseAuth.getEncryptedTGT();
                    SecretKey generatedKey = responseAuth.getGeneratedKey();
                    LocalDateTime issuedTime = responseAuth.getIssueTime();
                    Duration lifetime = responseAuth.getLifetime();
                    break;
                case (byte) 4:
                    objectInputStream = new ObjectInputStream(new ByteArrayInputStream(wrapper.getMessage()));
                    ResponseTGSMessage responseTGS = (ResponseTGSMessage) objectInputStream.readObject();

                    break;
                case (byte) 6:
                    break;
                default:
                    System.out.println("Invalid message type");
                    break;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static SSLSocket initTLSSocket() {
        SSLSocket socket = null;
        try {

            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(RemoteFileSystemApp.class.getResourceAsStream(TRUSTSTORE_PATH), TRUSTSTORE_PASSWORD);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(trustStore);

            // Set up the SSLContext
            SSLContext sslContext = SSLContext.getInstance(TLS_VERSION);
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            System.out.println("HOST: " + DISPATCHER_HOST);
            System.out.println("PORT: " + DISPATCHER_PORT);

            socket = (SSLSocket) sslSocketFactory.createSocket(DISPATCHER_HOST, DISPATCHER_PORT);
            socket.setUseClientMode(true);
            socket.setEnabledProtocols(CONFPROTOCOLS);
            socket.setEnabledCipherSuites(CONFCIPHERSUITES);

            socket.startHandshake();

        } catch (Exception e) {
            e.printStackTrace();
        }

        return socket;
    }

}