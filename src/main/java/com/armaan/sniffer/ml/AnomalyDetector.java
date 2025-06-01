package com.armaan.sniffer.ml;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

public class AnomalyDetector {
    private static final int WINDOW_SIZE = 1000; // Number of packets to analyze
    private static final double ANOMALY_THRESHOLD = 2.0; // Standard deviations for anomaly detection

    private final Queue<PacketStats> packetWindow = new LinkedList<>();
    private final Map<String, AtomicInteger> portFrequency = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> ipFrequency = new ConcurrentHashMap<>();
    private final Map<String, AtomicInteger> protocolFrequency = new ConcurrentHashMap<>();

    public static class PacketStats {
        private final String sourceIP;
        private final String destIP;
        private final String protocol;
        private final int sourcePort;
        private final int destPort;
        private final int size;
        private final long timestamp;

        public PacketStats(String sourceIP, String destIP, String protocol,
                int sourcePort, int destPort, int size) {
            this.sourceIP = sourceIP;
            this.destIP = destIP;
            this.protocol = protocol;
            this.sourcePort = sourcePort;
            this.destPort = destPort;
            this.size = size;
            this.timestamp = System.currentTimeMillis();
        }
    }

    public static class AnomalyResult {
        private final boolean isAnomaly;
        private final String anomalyType;
        private final double score;
        private final String details;

        public AnomalyResult(boolean isAnomaly, String anomalyType, double score, String details) {
            this.isAnomaly = isAnomaly;
            this.anomalyType = anomalyType;
            this.score = score;
            this.details = details;
        }

        public boolean isAnomaly() {
            return isAnomaly;
        }

        public String getAnomalyType() {
            return anomalyType;
        }

        public double getScore() {
            return score;
        }

        public String getDetails() {
            return details;
        }
    }

    public AnomalyResult analyzePacket(PacketStats stats) {
        // Add packet to window
        packetWindow.offer(stats);
        if (packetWindow.size() > WINDOW_SIZE) {
            PacketStats oldStats = packetWindow.poll();
            decrementFrequencies(oldStats);
        }

        // Update frequencies
        incrementFrequencies(stats);

        // Check for anomalies
        List<AnomalyResult> anomalies = new ArrayList<>();

        // Check port frequency
        anomalies.add(checkPortAnomaly(stats));

        // Check IP frequency
        anomalies.add(checkIPAnomaly(stats));

        // Check protocol frequency
        anomalies.add(checkProtocolAnomaly(stats));

        // Check packet size
        anomalies.add(checkSizeAnomaly(stats));

        // Return the most severe anomaly
        return anomalies.stream()
                .filter(AnomalyResult::isAnomaly)
                .max(Comparator.comparingDouble(AnomalyResult::getScore))
                .orElse(new AnomalyResult(false, null, 0.0, "No anomalies detected"));
    }

    private void incrementFrequencies(PacketStats stats) {
        portFrequency.computeIfAbsent(String.valueOf(stats.sourcePort), k -> new AtomicInteger(0)).incrementAndGet();
        portFrequency.computeIfAbsent(String.valueOf(stats.destPort), k -> new AtomicInteger(0)).incrementAndGet();
        ipFrequency.computeIfAbsent(stats.sourceIP, k -> new AtomicInteger(0)).incrementAndGet();
        ipFrequency.computeIfAbsent(stats.destIP, k -> new AtomicInteger(0)).incrementAndGet();
        protocolFrequency.computeIfAbsent(stats.protocol, k -> new AtomicInteger(0)).incrementAndGet();
    }

    private void decrementFrequencies(PacketStats stats) {
        portFrequency.computeIfPresent(String.valueOf(stats.sourcePort), (k, v) -> {
            v.decrementAndGet();
            return v.get() == 0 ? null : v;
        });
        portFrequency.computeIfPresent(String.valueOf(stats.destPort), (k, v) -> {
            v.decrementAndGet();
            return v.get() == 0 ? null : v;
        });
        ipFrequency.computeIfPresent(stats.sourceIP, (k, v) -> {
            v.decrementAndGet();
            return v.get() == 0 ? null : v;
        });
        ipFrequency.computeIfPresent(stats.destIP, (k, v) -> {
            v.decrementAndGet();
            return v.get() == 0 ? null : v;
        });
        protocolFrequency.computeIfPresent(stats.protocol, (k, v) -> {
            v.decrementAndGet();
            return v.get() == 0 ? null : v;
        });
    }

    private AnomalyResult checkPortAnomaly(PacketStats stats) {
        int totalPackets = packetWindow.size();
        if (totalPackets < 10)
            return new AnomalyResult(false, null, 0.0, "Insufficient data");

        double sourcePortFreq = portFrequency.getOrDefault(String.valueOf(stats.sourcePort), new AtomicInteger(0)).get()
                / (double) totalPackets;
        double destPortFreq = portFrequency.getOrDefault(String.valueOf(stats.destPort), new AtomicInteger(0)).get()
                / (double) totalPackets;

        if (sourcePortFreq > 0.5 || destPortFreq > 0.5) {
            return new AnomalyResult(true, "PORT_FREQUENCY",
                    Math.max(sourcePortFreq, destPortFreq),
                    "Unusual port frequency detected");
        }

        return new AnomalyResult(false, null, 0.0, "Normal port frequency");
    }

    private AnomalyResult checkIPAnomaly(PacketStats stats) {
        int totalPackets = packetWindow.size();
        if (totalPackets < 10)
            return new AnomalyResult(false, null, 0.0, "Insufficient data");

        double sourceIPFreq = ipFrequency.getOrDefault(stats.sourceIP, new AtomicInteger(0)).get()
                / (double) totalPackets;
        double destIPFreq = ipFrequency.getOrDefault(stats.destIP, new AtomicInteger(0)).get() / (double) totalPackets;

        if (sourceIPFreq > 0.3 || destIPFreq > 0.3) {
            return new AnomalyResult(true, "IP_FREQUENCY",
                    Math.max(sourceIPFreq, destIPFreq),
                    "Unusual IP frequency detected");
        }

        return new AnomalyResult(false, null, 0.0, "Normal IP frequency");
    }

    private AnomalyResult checkProtocolAnomaly(PacketStats stats) {
        int totalPackets = packetWindow.size();
        if (totalPackets < 10)
            return new AnomalyResult(false, null, 0.0, "Insufficient data");

        double protocolFreq = protocolFrequency.getOrDefault(stats.protocol, new AtomicInteger(0)).get()
                / (double) totalPackets;

        if (protocolFreq > 0.8) {
            return new AnomalyResult(true, "PROTOCOL_FREQUENCY",
                    protocolFreq,
                    "Unusual protocol frequency detected");
        }

        return new AnomalyResult(false, null, 0.0, "Normal protocol frequency");
    }

    private AnomalyResult checkSizeAnomaly(PacketStats stats) {
        if (packetWindow.size() < 10)
            return new AnomalyResult(false, null, 0.0, "Insufficient data");

        // Calculate mean and standard deviation of packet sizes
        double[] sizes = packetWindow.stream()
                .mapToDouble(p -> p.size)
                .toArray();

        double mean = Arrays.stream(sizes).average().orElse(0.0);
        double variance = Arrays.stream(sizes)
                .map(size -> Math.pow(size - mean, 2))
                .average()
                .orElse(0.0);
        double stdDev = Math.sqrt(variance);

        // Check if current packet size is anomalous
        double zScore = Math.abs(stats.size - mean) / stdDev;

        if (zScore > ANOMALY_THRESHOLD) {
            return new AnomalyResult(true, "PACKET_SIZE",
                    zScore,
                    "Unusual packet size detected");
        }

        return new AnomalyResult(false, null, 0.0, "Normal packet size");
    }
}