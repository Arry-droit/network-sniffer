package com.armaan.sniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;
import java.util.Scanner;
import java.util.Objects;

public class PacketSniffer {
    private static final Logger logger = LoggerFactory.getLogger(PacketSniffer.class);
    private static final int SNAPLEN = 65536;
    private static final int TIMEOUT = 10 * 1000;
    private static final int PACKET_COUNT = 50;

    public static void main(String[] args) {
        try {
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces == null || interfaces.isEmpty()) {
                logger.error("No network interfaces found. Please check your network configuration.");
                return;
            }

            // Display available interfaces
            System.out.println("Available Interfaces:");
            for (int i = 0; i < interfaces.size(); i++) {
                System.out.println(i + ": " + interfaces.get(i).getName() + " - " + interfaces.get(i).getDescription());
            }

            // Get user input for interface selection
            Scanner scanner = new Scanner(System.in);
            int selectedInterface;
            do {
                System.out.print("\nSelect interface (0-" + (interfaces.size() - 1) + "): ");
                try {
                    selectedInterface = Integer.parseInt(scanner.nextLine());
                } catch (NumberFormatException e) {
                    System.out.println("Please enter a valid number.");
                    selectedInterface = -1;
                }
            } while (selectedInterface < 0 || selectedInterface >= interfaces.size());

            PcapNetworkInterface nif = interfaces.get(selectedInterface);
            logger.info("Using interface: {}", nif.getName());

            // Open capture handle with try-with-resources
            try (PcapHandle handle = nif.openLive(SNAPLEN, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, TIMEOUT)) {
                // Set BPF filter
                String filter = "tcp";
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

                logger.info("Listening for TCP packets... (Capturing {} packets)", PACKET_COUNT);

                // Write to file
                try (BufferedWriter writer = new BufferedWriter(new FileWriter("packets_log.txt"))) {
                    // Packet listener
                    PacketListener listener = packet -> {
                        try {
                            PacketInfo packetInfo = createPacketInfo(handle, packet);
                            String packetDetails = packetInfo.toString();

                            System.out.println(packetDetails);
                            writer.write(packetDetails);
                            writer.flush();
                        } catch (IOException e) {
                            logger.error("Error writing packet information: {}", e.getMessage());
                        }
                    };

                    // Start capture loop
                    handle.loop(PACKET_COUNT, listener);
                } catch (IOException e) {
                    logger.error("Error writing to log file: {}", e.getMessage());
                }
            } catch (PcapNativeException | NotOpenException e) {
                logger.error("Error opening network interface: {}", e.getMessage());
            }

            logger.info("Sniffing complete. Output saved to packets_log.txt");
            scanner.close();

        } catch (Exception e) {
            logger.error("Unexpected error: {}", e.getMessage());
        }
    }

    private static PacketInfo createPacketInfo(PcapHandle handle, Packet packet) {
        String sourceIP = "Unknown";
        String destinationIP = "Unknown";
        String protocol = "Unknown";
        String sourcePort = "Unknown";
        String destinationPort = "Unknown";
        int packetSize = packet.length();
        String flags = "";

        IpV4Packet ipV4 = packet.get(IpV4Packet.class);
        if (ipV4 != null) {
            sourceIP = Objects.requireNonNullElse(ipV4.getHeader().getSrcAddr().getHostAddress(), "Unknown");
            destinationIP = Objects.requireNonNullElse(ipV4.getHeader().getDstAddr().getHostAddress(), "Unknown");

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

        // Analyze packet for malware
        MalwareDetector.DetectionResult result = MalwareDetector.analyzePacket(packet);

        return new PacketInfo(
                handle,
                sourceIP,
                destinationIP,
                protocol,
                sourcePort,
                destinationPort,
                packetSize,
                flags,
                packet.toString(),
                result.isMalicious(),
                result.getReason(),
                result.getSeverity());
    }

    private static String getTcpFlags(TcpPacket.TcpHeader header) {
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
}
