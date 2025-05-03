package com.armaan.sniffer;

import org.pcap4j.core.PcapHandle;
import java.time.Instant;
import java.io.Serializable;

public class PacketInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    private final Instant timestamp;
    private final String sourceIP;
    private final String destinationIP;
    private final String protocol;
    private final String sourcePort;
    private final String destinationPort;
    private final int packetSize;
    private final String flags;
    private final String rawPacket;

    public PacketInfo(PcapHandle handle, String sourceIP, String destinationIP, String protocol,
            String sourcePort, String destinationPort, int packetSize, String flags, String rawPacket) {
        this.timestamp = Instant.ofEpochMilli(handle.getTimestamp().getTime());
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.protocol = protocol;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.packetSize = packetSize;
        this.flags = flags;
        this.rawPacket = rawPacket;
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public String getDestinationIP() {
        return destinationIP;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getSourcePort() {
        return sourcePort;
    }

    public String getDestinationPort() {
        return destinationPort;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public String getFlags() {
        return flags;
    }

    public String getRawPacket() {
        return rawPacket;
    }

    @Override
    public String toString() {
        return String.format(
                "-------------------------------------------------%n" +
                        "Timestamp: %s%n" +
                        "Source: %s:%s%n" +
                        "Destination: %s:%s%n" +
                        "Protocol: %s%n" +
                        "Size: %d bytes%n" +
                        "Flags: %s%n" +
                        "Raw Packet: %s%n",
                timestamp, sourceIP, sourcePort, destinationIP, destinationPort,
                protocol, packetSize, flags, rawPacket);
    }
}