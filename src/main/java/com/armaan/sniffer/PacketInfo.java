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
    private final boolean isMalicious;
    private final String malwareReason;
    private final String severity;

    public PacketInfo(PcapHandle handle, String sourceIP, String destinationIP, String protocol,
            String sourcePort, String destinationPort, int packetSize, String flags, String rawPacket,
            boolean isMalicious, String malwareReason, String severity) {
        this.timestamp = Instant.now();
        this.sourceIP = Objects.requireNonNullElse(sourceIP, "Unknown");
        this.destinationIP = Objects.requireNonNullElse(destinationIP, "Unknown");
        this.protocol = Objects.requireNonNullElse(protocol, "Unknown");
        this.sourcePort = Objects.requireNonNullElse(sourcePort, "Unknown");
        this.destinationPort = Objects.requireNonNullElse(destinationPort, "Unknown");
        this.packetSize = packetSize;
        this.flags = Objects.requireNonNullElse(flags, "");
        this.rawPacket = Objects.requireNonNullElse(rawPacket, "");
        this.isMalicious = isMalicious;
        this.malwareReason = Objects.requireNonNullElse(malwareReason, "");
        this.severity = Objects.requireNonNullElse(severity, "INFO");
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

    public boolean isMalicious() {
        return isMalicious;
    }

    public String getMalwareReason() {
        return malwareReason;
    }

    public String getSeverity() {
        return severity;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("-------------------------------------------------\n");
        sb.append("Timestamp: ").append(timestamp).append("\n");
        sb.append("Source: ").append(sourceIP).append(":").append(sourcePort).append("\n");
        sb.append("Destination: ").append(destinationIP).append(":").append(destinationPort).append("\n");
        sb.append("Protocol: ").append(protocol).append("\n");
        sb.append("Size: ").append(packetSize).append(" bytes\n");
        sb.append("Flags: ").append(flags).append("\n");

        if (isMalicious) {
            sb.append("*** MALWARE DETECTED ***\n");
            sb.append("Severity: ").append(severity).append("\n");
            sb.append("Reason: ").append(malwareReason).append("\n");
        }

        sb.append("Raw Packet: ").append(rawPacket).append("\n");
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        PacketInfo that = (PacketInfo) o;
        return packetSize == that.packetSize &&
                isMalicious == that.isMalicious &&
                Objects.equals(timestamp, that.timestamp) &&
                Objects.equals(sourceIP, that.sourceIP) &&
                Objects.equals(destinationIP, that.destinationIP) &&
                Objects.equals(protocol, that.protocol) &&
                Objects.equals(sourcePort, that.sourcePort) &&
                Objects.equals(destinationPort, that.destinationPort) &&
                Objects.equals(flags, that.flags) &&
                Objects.equals(rawPacket, that.rawPacket) &&
                Objects.equals(malwareReason, that.malwareReason) &&
                Objects.equals(severity, that.severity);
    }

    @Override
    public int hashCode() {
        return Objects.hash(timestamp, sourceIP, destinationIP, protocol, sourcePort, destinationPort,
                packetSize, flags, rawPacket, isMalicious, malwareReason, severity);
    }
}