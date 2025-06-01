package com.armaan.sniffer.ui;

import com.armaan.sniffer.*;
import com.armaan.sniffer.model.ConversationInfo;
import com.armaan.sniffer.model.PacketInfo;
import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.chart.LineChart;
import javafx.scene.chart.PieChart;
import javafx.scene.chart.XYChart;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.stage.FileChooser;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.File;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class MainViewController {
    @FXML
    private ComboBox<String> interfaceComboBox;
    @FXML
    private TextField packetCountField;
    @FXML
    private TextField filterField;
    @FXML
    private Button startButton;
    @FXML
    private Button stopButton;
    @FXML
    private TableView<PacketInfo> packetTableView;
    @FXML
    private TableView<ConversationInfo> conversationTableView;
    @FXML
    private Label statusLabel;
    @FXML
    private Label captureStatusLabel;
    @FXML
    private Label totalPacketsLabel;
    @FXML
    private Label totalTrafficLabel;
    @FXML
    private Label durationLabel;
    @FXML
    private LineChart<String, Number> trafficChart;
    @FXML
    private PieChart protocolChart;

    private final ObservableList<PacketInfo> packetList = FXCollections.observableArrayList();
    private final ObservableList<ConversationInfo> conversationList = FXCollections.observableArrayList();
    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    private PcapHandle handle;
    private Thread captureThread;
    private Instant captureStartTime;
    private final AtomicInteger totalPackets = new AtomicInteger(0);
    private final AtomicInteger totalBytes = new AtomicInteger(0);

    @FXML
    public void initialize() {
        setupTableViews();
        loadInterfaces();
        setupCharts();
    }

    private void setupTableViews() {
        // Packet Table Columns
        TableColumn<PacketInfo, String> timestampCol = new TableColumn<>("Timestamp");
        timestampCol.setCellValueFactory(
                cellData -> new SimpleStringProperty(cellData.getValue().getTimestamp().toString()));

        TableColumn<PacketInfo, String> sourceCol = new TableColumn<>("Source");
        sourceCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().getSourceIP() + ":" +
                cellData.getValue().getSourcePort()));

        TableColumn<PacketInfo, String> destCol = new TableColumn<>("Destination");
        destCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().getDestinationIP() + ":" +
                cellData.getValue().getDestinationPort()));

        TableColumn<PacketInfo, String> protocolCol = new TableColumn<>("Protocol");
        protocolCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().getProtocol()));

        TableColumn<PacketInfo, String> sizeCol = new TableColumn<>("Size");
        sizeCol.setCellValueFactory(
                cellData -> new SimpleStringProperty(String.valueOf(cellData.getValue().getPacketSize())));

        TableColumn<PacketInfo, String> flagsCol = new TableColumn<>("Flags");
        flagsCol.setCellValueFactory(cellData -> new SimpleStringProperty(cellData.getValue().getFlags()));

        TableColumn<PacketInfo, String> malwareCol = new TableColumn<>("Malware Status");
        malwareCol.setCellValueFactory(cellData -> {
            PacketInfo info = cellData.getValue();
            if (info.isMalicious()) {
                return new SimpleStringProperty("⚠️ " + info.getSeverity() + " - " +
                        info.getMalwareReason());
            }
            return new SimpleStringProperty("✓ Safe");
        });

        packetTableView.getColumns().addAll(timestampCol, sourceCol, destCol,
                protocolCol, sizeCol, flagsCol, malwareCol);
        packetTableView.setItems(packetList);

        // Conversation Table Columns
        TableColumn<ConversationInfo, String> convSourceCol = new TableColumn<>("Source");
        convSourceCol.setCellValueFactory(new PropertyValueFactory<>("source"));

        TableColumn<ConversationInfo, String> convDestCol = new TableColumn<>("Destination");
        convDestCol.setCellValueFactory(new PropertyValueFactory<>("destination"));

        TableColumn<ConversationInfo, String> convProtocolCol = new TableColumn<>("Protocol");
        convProtocolCol.setCellValueFactory(new PropertyValueFactory<>("protocol"));

        TableColumn<ConversationInfo, Integer> convPacketsCol = new TableColumn<>("Packets");
        convPacketsCol.setCellValueFactory(new PropertyValueFactory<>("packetCount"));

        TableColumn<ConversationInfo, Integer> convBytesCol = new TableColumn<>("Bytes");
        convBytesCol.setCellValueFactory(new PropertyValueFactory<>("byteCount"));

        TableColumn<ConversationInfo, String> convDurationCol = new TableColumn<>("Duration");
        convDurationCol.setCellValueFactory(new PropertyValueFactory<>("duration"));

        conversationTableView.getColumns().addAll(convSourceCol, convDestCol,
                convProtocolCol, convPacketsCol,
                convBytesCol, convDurationCol);
        conversationTableView.setItems(conversationList);
    }

    private void setupCharts() {
        // Initialize charts with empty data
        trafficChart.setTitle("Traffic Over Time");
        protocolChart.setTitle("Protocol Distribution");
    }

    private void loadInterfaces() {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces != null && !interfaces.isEmpty()) {
                for (PcapNetworkInterface nif : interfaces) {
                    interfaceComboBox.getItems().add(nif.getName() + " - " +
                            nif.getDescription());
                }
            } else {
                showAlert("No network interfaces found. Please check your network configuration.");
            }
        } catch (PcapNativeException e) {
            showAlert("Error loading network interfaces: " + e.getMessage());
        }
    }

    @FXML
    private void handleStartCapture() {
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
            filterField.setDisable(true);
            captureStartTime = Instant.now();
            updateStatus("Capturing...");
        } catch (NumberFormatException ex) {
            showAlert("Please enter a valid number for packet count");
        }
    }

    @FXML
    private void handleStopCapture() {
        stopCapture();
        startButton.setDisable(false);
        stopButton.setDisable(true);
        interfaceComboBox.setDisable(false);
        packetCountField.setDisable(false);
        filterField.setDisable(false);
        updateStatus("Capture stopped");
    }

    private void startCapture(String interfaceName, int packetCount) {
        isCapturing.set(true);
        packetList.clear();
        conversationList.clear();
        totalPackets.set(0);
        totalBytes.set(0);

        captureThread = new Thread(() -> {
            try {
                PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName.split(" - ")[0]);
                if (nif == null) {
                    throw new PcapNativeException("Interface not found: " + interfaceName);
                }

                handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
                handle.setFilter(filterField.getText(), BpfProgram.BpfCompileMode.OPTIMIZE);

                PacketListener listener = packet -> {
                    if (!isCapturing.get())
                        return;

                    try {
                        PacketInfo packetInfo = createPacketInfo(handle, packet);
                        Platform.runLater(() -> {
                            packetList.add(packetInfo);
                            updateStatistics(packetInfo);
                            updateConversations(packetInfo);
                        });
                    } catch (Exception e) {
                        System.err.println("Error processing packet: " + e.getMessage());
                    }
                };

                handle.loop(packetCount, listener);
            } catch (Exception e) {
                System.err.println("Error during capture: " + e.getMessage());
                Platform.runLater(() -> {
                    showAlert("Error during capture: " + e.getMessage());
                    isCapturing.set(false);
                });
            } finally {
                if (handle != null && handle.isOpen()) {
                    handle.close();
                }
            }
        });

        captureThread.setDaemon(true);
        captureThread.start();
    }

    private void stopCapture() {
        isCapturing.set(false);
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
        if (captureThread != null) {
            captureThread.interrupt();
        }
    }

    private void updateStatistics(PacketInfo packetInfo) {
        totalPackets.incrementAndGet();
        totalBytes.addAndGet(packetInfo.getPacketSize());

        Platform.runLater(() -> {
            totalPacketsLabel.setText(String.valueOf(totalPackets.get()));
            totalTrafficLabel.setText(formatBytes(totalBytes.get()));

            Duration duration = Duration.between(captureStartTime, Instant.now());
            durationLabel.setText(formatDuration(duration));

            updateCharts(packetInfo);
        });
    }

    private void updateConversations(PacketInfo packetInfo) {
        String conversationKey = packetInfo.getSourceIP() + ":" + packetInfo.getSourcePort() +
                " -> " + packetInfo.getDestinationIP() + ":" +
                packetInfo.getDestinationPort();

        ConversationInfo conversation = conversationList.stream()
                .filter(c -> c.getKey().equals(conversationKey))
                .findFirst()
                .orElseGet(() -> {
                    ConversationInfo newConv = new ConversationInfo(
                            packetInfo.getSourceIP() + ":" + packetInfo.getSourcePort(),
                            packetInfo.getDestinationIP() + ":" + packetInfo.getDestinationPort(),
                            packetInfo.getProtocol());
                    conversationList.add(newConv);
                    return newConv;
                });

        conversation.incrementPackets();
        conversation.addBytes(packetInfo.getPacketSize());
    }

    private void updateCharts(PacketInfo packetInfo) {
        // Update traffic chart
        XYChart.Series<String, Number> series = trafficChart.getData().isEmpty() ? new XYChart.Series<>()
                : trafficChart.getData().get(0);
        if (series == null) {
            series = new XYChart.Series<>();
            series.setName("Traffic");
            trafficChart.getData().add(series);
        }
        series.getData().add(new XYChart.Data<>(
                packetInfo.getTimestamp().toString(),
                packetInfo.getPacketSize()));

        // Update protocol chart
        PieChart.Data protocolData = protocolChart.getData().stream()
                .filter(d -> d.getName().equals(packetInfo.getProtocol()))
                .findFirst()
                .orElseGet(() -> {
                    PieChart.Data newData = new PieChart.Data(packetInfo.getProtocol(), 0);
                    protocolChart.getData().add(newData);
                    return newData;
                });
        protocolData.setPieValue(protocolData.getPieValue() + 1);
    }

    private PacketInfo createPacketInfo(PcapHandle handle, Packet packet) {
        // Extract basic packet information
        String sourceIP = packet.get(IpPacket.class) != null
                ? packet.get(IpPacket.class).getHeader().getSrcAddr().getHostAddress()
                : "N/A";
        String destIP = packet.get(IpPacket.class) != null
                ? packet.get(IpPacket.class).getHeader().getDstAddr().getHostAddress()
                : "N/A";

        // Extract port information
        String sourcePort = "N/A";
        String destPort = "N/A";
        if (packet.get(TcpPacket.class) != null) {
            sourcePort = String.valueOf(packet.get(TcpPacket.class).getHeader().getSrcPort().valueAsInt());
            destPort = String.valueOf(packet.get(TcpPacket.class).getHeader().getDstPort().valueAsInt());
        } else if (packet.get(UdpPacket.class) != null) {
            sourcePort = String.valueOf(packet.get(UdpPacket.class).getHeader().getSrcPort().valueAsInt());
            destPort = String.valueOf(packet.get(UdpPacket.class).getHeader().getDstPort().valueAsInt());
        }

        // Determine protocol
        String protocol = "Unknown";
        if (packet.get(TcpPacket.class) != null) {
            protocol = "TCP";
        } else if (packet.get(UdpPacket.class) != null) {
            protocol = "UDP";
        } else if (packet.get(IpPacket.class) != null) {
            IpNumber ipNumber = packet.get(IpPacket.class).getHeader().getProtocol();
            if (ipNumber == IpNumber.ICMPV4) {
                protocol = "ICMPv4";
            } else if (ipNumber == IpNumber.ICMPV6) {
                protocol = "ICMPv6";
            }
        }

        // Extract flags
        String flags = "";
        if (packet.get(TcpPacket.class) != null) {
            TcpPacket.TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();
            if (tcpHeader.getSyn())
                flags += "S";
            if (tcpHeader.getAck())
                flags += "A";
            if (tcpHeader.getFin())
                flags += "F";
            if (tcpHeader.getRst())
                flags += "R";
            if (tcpHeader.getPsh())
                flags += "P";
            if (tcpHeader.getUrg())
                flags += "U";
        }

        return new PacketInfo(
                Instant.now(),
                sourceIP,
                destIP,
                sourcePort,
                destPort,
                protocol,
                packet.length(),
                flags,
                false,
                "Low",
                "");
    }

    private String formatBytes(long bytes) {
        if (bytes < 1024)
            return bytes + " B";
        if (bytes < 1024 * 1024)
            return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024)
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    private String formatDuration(Duration duration) {
        long hours = duration.toHours();
        long minutes = duration.toMinutesPart();
        long seconds = duration.toSecondsPart();
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }

    private void updateStatus(String status) {
        Platform.runLater(() -> {
            statusLabel.setText(status);
            captureStatusLabel.setText(isCapturing.get() ? "Capturing" : "Not Capturing");
        });
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

    // Menu Handlers
    @FXML
    private void handleSaveCapture() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save Capture");
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("PCAP Files", "*.pcap"));
        File file = fileChooser.showSaveDialog(packetTableView.getScene().getWindow());
        if (file != null) {
            // TODO: Implement save functionality
        }
    }

    @FXML
    private void handleLoadCapture() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Load Capture");
        fileChooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("PCAP Files", "*.pcap"));
        File file = fileChooser.showOpenDialog(packetTableView.getScene().getWindow());
        if (file != null) {
            // TODO: Implement load functionality
        }
    }

    @FXML
    private void handleExit() {
        stopCapture();
        Platform.exit();
    }

    // Filter Handlers
    @FXML
    private void handleFilterHTTP() {
        filterField.setText("tcp port 80 or tcp port 443");
    }

    @FXML
    private void handleFilterDNS() {
        filterField.setText("udp port 53");
    }

    @FXML
    private void handleFilterSuspicious() {
        filterField.setText("tcp[tcpflags] & (tcp-syn|tcp-fin) != 0 and not src and dst net localnet");
    }

    // View Handlers
    @FXML
    private void handleShowStats() {
        // TODO: Implement statistics view
    }

    @FXML
    private void handleShowConversations() {
        // TODO: Implement conversations view
    }

    @FXML
    private void handleShowProtocolDist() {
        // TODO: Implement protocol distribution view
    }

    // Tools Handlers
    @FXML
    private void handleShowFilter() {
        // TODO: Implement advanced filter dialog
    }

    @FXML
    private void handleShowSearch() {
        // TODO: Implement packet search dialog
    }

    @FXML
    private void handleShowSettings() {
        // TODO: Implement settings dialog
    }

    // Help Handlers
    @FXML
    private void handleShowDocs() {
        // TODO: Implement documentation viewer
    }

    @FXML
    private void handleShowAbout() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("About Network Packet Sniffer");
        alert.setHeaderText("Network Packet Sniffer v1.0");
        alert.setContentText("A modern network packet capture and analysis tool.\n\n" +
                "Features:\n" +
                "- Real-time packet capture and analysis\n" +
                "- Protocol decoding and deep packet inspection\n" +
                "- Traffic statistics and visualization\n" +
                "- Conversation tracking\n" +
                "- Malware detection\n" +
                "- Advanced filtering and search capabilities");
        alert.showAndWait();
    }
}