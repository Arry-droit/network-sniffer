package com.armaan.sniffer.alert;

import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.mail.*;
import javax.mail.internet.*;
import java.io.FileInputStream;
import java.io.IOException;

public class AlertManager {
    private static final BlockingQueue<Alert> alertQueue = new LinkedBlockingQueue<>();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private static Properties emailProperties;
    private static String emailUsername;
    private static String emailPassword;

    static {
        loadEmailConfig();
        startAlertProcessor();
    }

    public static class Alert {
        private final String severity;
        private final String type;
        private final String message;
        private final String sourceIP;
        private final String destIP;
        private final long timestamp;

        public Alert(String severity, String type, String message, String sourceIP, String destIP) {
            this.severity = severity;
            this.type = type;
            this.message = message;
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.timestamp = System.currentTimeMillis();
        }

        public String getSeverity() {
            return severity;
        }

        public String getType() {
            return type;
        }

        public String getMessage() {
            return message;
        }

        public String getSourceIP() {
            return sourceIP;
        }

        public String getDestIP() {
            return destIP;
        }

        public long getTimestamp() {
            return timestamp;
        }

        @Override
        public String toString() {
            return String.format("[%s] %s - %s (Source: %s, Destination: %s)",
                    severity, type, message, sourceIP, destIP);
        }
    }

    private static void loadEmailConfig() {
        try {
            Properties config = new Properties();
            config.load(new FileInputStream("email_config.properties"));

            emailProperties = new Properties();
            emailProperties.put("mail.smtp.host", config.getProperty("smtp.host"));
            emailProperties.put("mail.smtp.port", config.getProperty("smtp.port"));
            emailProperties.put("mail.smtp.auth", "true");
            emailProperties.put("mail.smtp.starttls.enable", "true");

            emailUsername = config.getProperty("email.username");
            emailPassword = config.getProperty("email.password");
        } catch (IOException e) {
            System.err.println("Error loading email configuration: " + e.getMessage());
        }
    }

    private static void startAlertProcessor() {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                while (!alertQueue.isEmpty()) {
                    Alert alert = alertQueue.poll();
                    if (alert != null) {
                        processAlert(alert);
                    }
                }
            } catch (Exception e) {
                System.err.println("Error processing alerts: " + e.getMessage());
            }
        }, 0, 1, TimeUnit.SECONDS);
    }

    public static void sendAlert(String severity, String type, String message,
            String sourceIP, String destIP) {
        Alert alert = new Alert(severity, type, message, sourceIP, destIP);
        alertQueue.offer(alert);
    }

    private static void processAlert(Alert alert) {
        // Log alert
        System.out.println(alert.toString());

        // Send email for high severity alerts
        if ("HIGH".equals(alert.getSeverity())) {
            sendEmailAlert(alert);
        }

        // TODO: Add other notification methods (SMS, Slack, etc.)
    }

    private static void sendEmailAlert(Alert alert) {
        if (emailProperties == null || emailUsername == null || emailPassword == null) {
            System.err.println("Email configuration not loaded");
            return;
        }

        try {
            Session session = Session.getInstance(emailProperties, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(emailUsername, emailPassword);
                }
            });

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(emailUsername));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(emailUsername));
            message.setSubject("Network Security Alert: " + alert.getType());

            String emailContent = String.format(
                    "Severity: %s\n" +
                            "Type: %s\n" +
                            "Message: %s\n" +
                            "Source IP: %s\n" +
                            "Destination IP: %s\n" +
                            "Timestamp: %s\n",
                    alert.getSeverity(),
                    alert.getType(),
                    alert.getMessage(),
                    alert.getSourceIP(),
                    alert.getDestIP(),
                    new java.util.Date(alert.getTimestamp()));

            message.setText(emailContent);
            Transport.send(message);

        } catch (MessagingException e) {
            System.err.println("Error sending email alert: " + e.getMessage());
        }
    }

    public static void shutdown() {
        scheduler.shutdown();
    }
}