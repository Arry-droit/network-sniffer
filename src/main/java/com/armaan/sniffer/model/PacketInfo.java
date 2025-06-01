package com.armaan.sniffer.model;

import java.time.Instant;

public class PacketInfo {
    private final Instant timestamp;
    private final String sourceIP;
    private final String destinationIP;
    private final String sourcePort;
    private final String destinationPort;
    private final String protocol;
    private final int packetSize;
    private final String flags;
    private final boolean malicious;
    private final String severity;
    private final String malwareReason;

    public PacketInfo(Instant timestamp, String sourceIP, String destinationIP,
            String sourcePort, String destinationPort, String protocol,
            int packetSize, String flags, boolean malicious,
            String severity, String malwareReason) {
        this.timestamp = timestamp;
        this.sourceIP = sourceIP;
        this.destinationIP = destinationIP;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.packetSize = packetSize;
        this.flags = flags;
        this.malicious = malicious;
        this.severity = severity;
        this.malwareReason = malwareReason;
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

    public String getSourcePort() {
        return sourcePort;
    }

    public String getDestinationPort() {
        return destinationPort;
    }

    public String getProtocol() {
        return protocol;
    }

    public int getPacketSize() {
        return packetSize;
    }

    public String getFlags() {
        return flags;
    }

    public boolean isMalicious() {
        return malicious;
    }

    public String getSeverity() {
        return severity;
    }

    public String getMalwareReason() {
        return malwareReason;
    }
}