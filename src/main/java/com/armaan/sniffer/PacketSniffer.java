package com.armaan.sniffer;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

public class PacketSniffer {

    public static void main(String[] args) {
        try {
            // List all network interfaces
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("No interfaces found. Exiting...");
                return;
            }

            // Print interfaces
            System.out.println("Available Interfaces:");
            for (int i = 0; i < interfaces.size(); i++) {
                System.out.println(i + ": " + interfaces.get(i).getName() + " - " + interfaces.get(i).getDescription());
            }

            // Select interface by index (change index as needed)
            PcapNetworkInterface nif = interfaces.get(3);
            System.out.println("\nUsing interface: " + nif.getName());

            int snapLen = 65536;
            int timeout = 10 * 1000;

            // Open capture handle
            PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);

            // Set BPF filter
            String filter = "tcp";
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

            System.out.println("Listening for TCP packets... (Capturing 50 packets)");

            // Write to file
            try (BufferedWriter writer = new BufferedWriter(new FileWriter("packets_log.txt"))) {

                // Packet listener
                PacketListener listener = new PacketListener() {
                    @Override
                    public void gotPacket(Packet packet) {
                        try {
                            StringBuilder sb = new StringBuilder();
                            sb.append("-------------------------------------------------\n");
                            sb.append("Timestamp: ").append(handle.getTimestamp()).append("\n");

                            IpV4Packet ipV4 = packet.get(IpV4Packet.class);
                            if (ipV4 != null) {
                                sb.append("Source IP: ").append(ipV4.getHeader().getSrcAddr()).append("\n");
                                sb.append("Destination IP: ").append(ipV4.getHeader().getDstAddr()).append("\n");

                                if (packet.contains(TcpPacket.class)) {
                                    sb.append("Protocol: TCP\n");
                                } else if (packet.contains(UdpPacket.class)) {
                                    sb.append("Protocol: UDP\n");
                                } else {
                                    sb.append("Protocol: Other\n");
                                }
                            } else {
                                sb.append("Not an IPv4 packet.\n");
                            }

                            sb.append("Raw Packet: ").append(packet).append("\n");

                            System.out.println(sb.toString());
                            writer.write(sb.toString());

                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                };

                // Start loop safely
                try {
                    handle.loop(50, listener);
                } catch (InterruptedException e) {
                    System.out.println("Packet capture interrupted.");
                }
            }

            handle.close();
            System.out.println("Sniffing complete. Output saved to packets_log.txt");

        } catch (PcapNativeException | NotOpenException | IOException e) {
            e.printStackTrace();
        }
    }
}
