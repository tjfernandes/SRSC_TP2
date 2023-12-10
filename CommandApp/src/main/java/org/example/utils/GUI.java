package org.example.utils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.concurrent.atomic.AtomicReference;

public class GUI {
    private JFrame frame;
    private JPanel panel;
    private JLabel inputInstruction;
    private JTextField commandTextField;
    private JTextArea outputText;
    private JLabel fileNameLabel;
    private JButton submitFileButton;
    private JButton requestButton;
    private AtomicReference<byte[]> payload;
    private AtomicReference<byte[]> metadata;

    public GUI() {
        frame = new JFrame("Remote FS");
        frame.setSize(800, 400);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        inputInstruction = new JLabel("Enter your command");
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(inputInstruction, gbc);

        commandTextField = new JTextField(50);
        gbc.gridy = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(commandTextField, gbc);

        outputText = new JTextArea();
        outputText.setLineWrap(true);
        outputText.setWrapStyleWord(true);
        outputText.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputText);
        scrollPane.setPreferredSize(new Dimension(750, 200));

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(scrollPane, gbc);

        fileNameLabel = new JLabel();
        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.anchor = GridBagConstraints.WEST;
        panel.add(fileNameLabel, gbc);

        submitFileButton = new JButton("Submit File");
        payload = new AtomicReference<>();
        metadata = new AtomicReference<>();
        submitFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                submitFile();
            }
        });

        requestButton = new JButton("Request");

        // Add the components to the panel
        gbc.gridy = 4;
        panel.add(submitFileButton, gbc);

        gbc.gridy = 5;
        panel.add(requestButton, gbc);

        // Add the panel to the frame
        frame.add(panel);

        JPanel buttonsPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        buttonsPanel.add(submitFileButton);
        buttonsPanel.add(requestButton);

        gbc.gridx = 0;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.anchor = GridBagConstraints.CENTER;
        panel.add(buttonsPanel, gbc);

        frame.add(panel);
        frame.setVisible(true);
    }

    private void submitFile() {
        JFileChooser fileChooser = new JFileChooser();
        int result = fileChooser.showOpenDialog(null);

        if (result == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();
            try {
                BasicFileAttributes attrs = Files.readAttributes(selectedFile.toPath(),
                        BasicFileAttributes.class);
                metadata.set(Utils.serialize(new FileMetadata(attrs)));
                payload.set(Files.readAllBytes(selectedFile.toPath()));
            } catch (IOException ex) {
                ex.printStackTrace();
            }
            fileNameLabel.setText("Selected file: " + selectedFile.getName());
        }
    }

    public AtomicReference<byte[]> getPayload() {
        return payload;
    }

    public AtomicReference<byte[]> getMetadata() {
        return metadata;
    }

    public void setOutputText(String text) {
        outputText.setText(text);
    }

    public String getCommand() {
        return commandTextField.getText();
    }

    public void setCommand(String command) {
        commandTextField.setText(command);
    }

    public void setRequestButtonListener(ActionListener listener) {
        requestButton.addActionListener(listener);
    }
}