package com.armaan.sniffer;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicBoolean;

public class PacketSnifferApp extends Application {
    private static final Logger logger = LoggerFactory.getLogger(PacketSnifferApp.class);
    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT = 10 * 1000;
    private static final int PACKET_COUNT = 50;

    private final ObservableList<PacketInfo> packetList = FXCollections.observableArrayList();
    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    private PcapHandle handle;
    private Thread captureThread;
    private Scanner scanner;

    @Override
    public void start(Stage primaryStage) {
        try {
            primaryStage.setTitle("Network Packet Sniffer");

            // Create table view
            TableView<PacketInfo> tableView = createTableView();

            // Create controls
            ComboBox<String> interfaceComboBox = new ComboBox<>();
            Button startButton = new Button("Start Capture");
            Button stopButton = new Button("Stop Capture");
            stopButton.setDisable(true);
            TextField packetCountField = new TextField("50");
            packetCountField.setPrefWidth(100);

            // Load interfaces
            loadInterfaces(interfaceComboBox);

            // Create control panel
            HBox controlPanel = new HBox(10);
            controlPanel.setPadding(new Insets(10));
            controlPanel.getChildren().addAll(
                    new Label("Interface:"),
                    interfaceComboBox,
                    new Label("Packet Count:"),
                    packetCountField,
                    startButton,
                    stopButton);

            // Create main layout
            BorderPane root = new BorderPane();
            root.setTop(controlPanel);
            root.setCenter(tableView);

            // Set up event handlers
            startButton.setOnAction(e -> {
                if (interfaceComboBox.getValue() == null) {
                    showAlert("Please select a network interface");
                    return;
                }

                try {
                    int packetCount = Integer.parseInt(packetCountField.getText());
                    if (packetCount <= 0) {
                        showAlert("Packet count must be greater than 0");
                        return;
                    }
                    startCapture(interfaceComboBox.getValue(), packetCount);
                    startButton.setDisable(true);
                    stopButton.setDisable(false);
                    interfaceComboBox.setDisable(true);
                    packetCountField.setDisable(true);
                } catch (NumberFormatException ex) {
                    showAlert("Please enter a valid number for packet count");
                }
            });

            stopButton.setOnAction(e -> {
                stopCapture();
                startButton.setDisable(false);
                stopButton.setDisable(true);
                interfaceComboBox.setDisable(false);
                packetCountField.setDisable(false);
            });

            // Create scene
            Scene scene = new Scene(root, 800, 600);
            primaryStage.setScene(scene);
            primaryStage.setOnCloseRequest(e -> stop());
            primaryStage.show();

        } catch (Exception e) {
            logger.error("Error initializing application: {}", e.getMessage());
            showAlert("Error initializing application: " + e.getMessage());
        }
    }

    private TableView<PacketInfo> createTableView() {
        TableView<PacketInfo> tableView = new TableView<>();
        tableView.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);

        TableColumn<PacketInfo, String> timestampCol = new TableColumn<>("Timestamp");
        timestampCol.setCellValueFactory(new PropertyValueFactory<>("timestamp"));

        TableColumn<PacketInfo, String> sourceCol = new TableColumn<>("Source");
        sourceCol.setCellValueFactory(cellData -> new SimpleStringProperty(
                cellData.getValue().getSourceIP() + ":" + cellData.getValue().getSourcePort()));

        TableColumn<PacketInfo, String> destCol = new TableColumn<>("Destination");
        destCol.setCellValueFactory(cellData -> new SimpleStringProperty(
                cellData.getValue().getDestinationIP() + ":" + cellData.getValue().getDestinationPort()));

        TableColumn<PacketInfo, String> protocolCol = new TableColumn<>("Protocol");
        protocolCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));

        TableColumn<PacketInfo, Integer> sizeCol = new TableColumn<>("Size (bytes)");
        sizeCol.setCellValueFactory(new PropertyValueFactory<>("packetSize"));

        TableColumn<PacketInfo, String> flagsCol = new TableColumn<>("Flags");
        flagsCol.setCellValueFactory(new PropertyValueFactory<>("flags"));

        tableView.getColumns().addAll(timestampCol, sourceCol, destCol, protocolCol, sizeCol, flagsCol);
        tableView.setItems(packetList);

        return tableView;
    }

    private void loadInterfaces(ComboBox<String> comboBox) {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces != null && !interfaces.isEmpty()) {
                for (PcapNetworkInterface nif : interfaces) {
                    comboBox.getItems().add(nif.getName() + " - " + nif.getDescription());
                }
            } else {
                showAlert("No network interfaces found. Please check your network configuration.");
            }
        } catch (PcapNativeException e) {
            logger.error("Error loading interfaces: {}", e.getMessage());
            showAlert("Error loading network interfaces: " + e.getMessage());
        }
    }

    private void startCapture(String interfaceName, int packetCount) {
        isCapturing.set(true);
        packetList.clear();

        captureThread = new Thread(() -> {
            try {
                PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName.split(" - ")[0]);
                if (nif == null) {
                    throw new PcapNativeException("Interface not found: " + interfaceName);
                }

                handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT);
                handle.setFilter("tcp", BpfProgram.BpfCompileMode.OPTIMIZE);

                PacketListener listener = packet -> {
                    if (!isCapturing.get())
                        return;

                    try {
                        PacketInfo packetInfo = createPacketInfo(handle, packet);
                        Platform.runLater(() -> packetList.add(packetInfo));
                    } catch (Exception e) {
                        logger.error("Error processing packet: {}", e.getMessage());
                    }
                };

                handle.loop(packetCount, listener);
            } catch (Exception e) {
                logger.error("Error during capture: {}", e.getMessage());
                Platform.runLater(() -> {
                    showAlert("Error during capture: " + e.getMessage());
                    isCapturing.set(false);
                });
            }
        });

        captureThread.setDaemon(true);
        captureThread.start();
    }

    private void stopCapture() {
        isCapturing.set(false);
        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
                handle.close();
            } catch (NotOpenException e) {
                logger.error("Error closing handle: {}", e.getMessage());
            }
        }
        if (captureThread != null) {
            captureThread.interrupt();
        }
    }

    private void showAlert(String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Error");
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }

    private PacketInfo createPacketInfo(PcapHandle handle, Packet packet) {
        String sourceIP = "Unknown";
        String destinationIP = "Unknown";
        String protocol = "Unknown";
        String sourcePort = "Unknown";
        String destinationPort = "Unknown";
        int packetSize = packet.length();
        String flags = "";

        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        if (ipV4 != null) {
            sourceIP = ipV4.getHeader().getSrcAddr().getHostAddress();
            destinationIP = ipV4.getHeader().getDstAddr().getHostAddress();

            if (packet.contains(TcpPacket.class)) {
                protocol = "TCP";
                TcpPacket tcp = packet.get(TcpPacket.class);
                if (tcp != null) {
                    sourcePort = String.valueOf(tcp.getHeader().getSrcPort().value());
                    destinationPort = String.valueOf(tcp.getHeader().getDstPort().value());
                    flags = getTcpFlags(tcp.getHeader());
                }
            } else if (packet.contains(UdpPacket.class)) {
                protocol = "UDP";
                UdpPacket udp = packet.get(UdpPacket.class);
                if (udp != null) {
                    sourcePort = String.valueOf(udp.getHeader().getSrcPort().value());
                    destinationPort = String.valueOf(udp.getHeader().getDstPort().value());
                }
            } else {
                protocol = "Other";
            }
        }

        return new PacketInfo(
                handle,
                sourceIP,
                destinationIP,
                protocol,
                sourcePort,
                destinationPort,
                packetSize,
                flags,
                packet.toString());
    }

    private String getTcpFlags(TcpHeader header) {
        StringBuilder flags = new StringBuilder();
        if (header.getUrg())
            flags.append("URG ");
        if (header.getAck())
            flags.append("ACK ");
        if (header.getPsh())
            flags.append("PSH ");
        if (header.getRst())
            flags.append("RST ");
        if (header.getSyn())
            flags.append("SYN ");
        if (header.getFin())
            flags.append("FIN ");
        return flags.toString().trim();
    }

    @Override
    public void stop() {
        stopCapture();
        if (scanner != null) {
            scanner.close();
        }
    }

    public static void main(String[] args) {
        launch(args);
    }
}