package com.armaan.sniffer.model;

import java.time.Duration;
import java.time.Instant;

public class ConversationInfo {
    private final String source;
    private final String destination;
    private final String protocol;
    private final String key;
    private int packetCount;
    private int byteCount;
    private final Instant startTime;
    private Instant lastPacketTime;

    public ConversationInfo(String source, String destination, String protocol) {
        this.source = source;
        this.destination = destination;
        this.protocol = protocol;
        this.key = source + " -> " + destination;
        this.packetCount = 0;
        this.byteCount = 0;
        this.startTime = Instant.now();
        this.lastPacketTime = this.startTime;
    }

    public String getSource() {
        return source;
    }

    public String getDestination() {
        return destination;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getKey() {
        return key;
    }

    public int getPacketCount() {
        return packetCount;
    }

    public int getByteCount() {
        return byteCount;
    }

    public String getDuration() {
        Duration duration = Duration.between(startTime, lastPacketTime);
        long hours = duration.toHours();
        long minutes = duration.toMinutesPart();
        long seconds = duration.toSecondsPart();
        return String.format("%02d:%02d:%02d", hours, minutes, seconds);
    }

    public void incrementPackets() {
        this.packetCount++;
        this.lastPacketTime = Instant.now();
    }

    public void addBytes(int bytes) {
        this.byteCount += bytes;
    }
}