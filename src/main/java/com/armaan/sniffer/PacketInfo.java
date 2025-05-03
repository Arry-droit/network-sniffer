package com.armaan.sniffer;

import org.pcap4j.core.PcapHandle;
import java.time.Instant;
import java.io.Serializable;
import java.util.Objects;

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
        this.sourceIP = Objects.requireNonNullElse(sourceIP, "Unknown");
        this.destinationIP = Objects.requireNonNullElse(destinationIP, "Unknown");
        this.protocol = Objects.requireNonNullElse(protocol, "Unknown");
        this.sourcePort = Objects.requireNonNullElse(sourcePort, "Unknown");
        this.destinationPort = Objects.requireNonNullElse(destinationPort, "Unknown");
        this.packetSize = packetSize;
        this.flags = Objects.requireNonNullElse(flags, "");
        this.rawPacket = Objects.requireNonNullElse(rawPacket, "");
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
                timestamp,
                sourceIP,
                sourcePort,
                destinationIP,
                destinationPort,
                protocol,
                packetSize,
                flags,
                rawPacket);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        PacketInfo that = (PacketInfo) o;
        return packetSize == that.packetSize &&
                Objects.equals(timestamp, that.timestamp) &&
                Objects.equals(sourceIP, that.sourceIP) &&
                Objects.equals(destinationIP, that.destinationIP) &&
                Objects.equals(protocol, that.protocol) &&
                Objects.equals(sourcePort, that.sourcePort) &&
                Objects.equals(destinationPort, that.destinationPort) &&
                Objects.equals(flags, that.flags) &&
                Objects.equals(rawPacket, that.rawPacket);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, sourceIP, destinationIP, protocol, sourcePort, destinationPort, packetSize,
                flags, rawPacket);
    }
}