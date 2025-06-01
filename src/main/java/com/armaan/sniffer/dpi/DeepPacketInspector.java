package com.armaan.sniffer.dpi;

import org.pcap4j.packet.*;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class DeepPacketInspector {
    private static final Map<String, Pattern> PROTOCOL_PATTERNS = new HashMap<>();
    private static final Map<String, Pattern> MALWARE_PATTERNS = new HashMap<>();

    static {
        // HTTP patterns
        PROTOCOL_PATTERNS.put("HTTP", Pattern.compile("^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) .* HTTP/\\d\\.\\d"));
        PROTOCOL_PATTERNS.put("HTTPS", Pattern.compile("^\\x16\\x03\\x01")); // TLS 1.0

        // DNS patterns
        PROTOCOL_PATTERNS.put("DNS", Pattern.compile("^\\x00\\x01\\x00\\x01"));

        // FTP patterns
        PROTOCOL_PATTERNS.put("FTP", Pattern.compile(
                "^(USER|PASS|ACCT|CWD|CDUP|SMNT|QUIT|REIN|PORT|PASV|TYPE|STRU|MODE|RETR|STOR|STOU|APPE|ALLO|REST|RNFR|RNTO|ABOR|DELE|RMD|MKD|PWD|LIST|NLST|SITE|SYST|STAT|HELP|NOOP)"));

        // Malware patterns
        MALWARE_PATTERNS.put("SHELLCODE", Pattern.compile("\\x90\\x90\\x90.*\\xcc\\xcc\\xcc")); // NOP sled + INT3
        MALWARE_PATTERNS.put("SQL_INJECTION",
                Pattern.compile("(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|EXEC|DECLARE).*FROM.*WHERE"));
        MALWARE_PATTERNS.put("XSS", Pattern.compile("(?i)<script.*>.*</script>|<img.*onerror=|<svg.*onload="));
        MALWARE_PATTERNS.put("COMMAND_INJECTION",
                Pattern.compile("(?i)(\\|.*\\||;.*\\||&.*\\||\\|.*;|;.*;|&.*;|\\|.*&|;.*&|&.*&)"));
    }

    public static class InspectionResult {
        private final String protocol;
        private final boolean isMalicious;
        private final String threatType;
        private final String details;

        public InspectionResult(String protocol, boolean isMalicious, String threatType, String details) {
            this.protocol = protocol;
            this.isMalicious = isMalicious;
            this.threatType = threatType;
            this.details = details;
        }

        public String getProtocol() {
            return protocol;
        }

        public boolean isMalicious() {
            return isMalicious;
        }

        public String getThreatType() {
            return threatType;
        }

        public String getDetails() {
            return details;
        }
    }

    public static InspectionResult inspectPacket(Packet packet) {
        if (packet == null) {
            return new InspectionResult("Unknown", false, null, "Null packet");
        }

        // Get packet payload
        byte[] payload = getPayload(packet);
        if (payload == null || payload.length == 0) {
            return new InspectionResult("Unknown", false, null, "No payload");
        }

        // Convert payload to string for pattern matching
        String payloadStr = new String(payload);

        // Check for known protocols
        String detectedProtocol = detectProtocol(payloadStr);

        // Check for malware patterns
        for (Map.Entry<String, Pattern> entry : MALWARE_PATTERNS.entrySet()) {
            Matcher matcher = entry.getValue().matcher(payloadStr);
            if (matcher.find()) {
                return new InspectionResult(
                        detectedProtocol,
                        true,
                        entry.getKey(),
                        "Detected " + entry.getKey() + " pattern in payload");
            }
        }

        // Additional protocol-specific checks
        if ("HTTP".equals(detectedProtocol)) {
            // Check for suspicious HTTP headers
            if (payloadStr.contains("X-Forwarded-For") ||
                    payloadStr.contains("X-Remote-IP") ||
                    payloadStr.contains("X-Originating-IP")) {
                return new InspectionResult(
                        detectedProtocol,
                        true,
                        "SUSPICIOUS_HEADER",
                        "Suspicious HTTP header detected");
            }
        }

        return new InspectionResult(detectedProtocol, false, null, "No threats detected");
    }

    private static byte[] getPayload(Packet packet) {
        if (packet.contains(TcpPacket.class)) {
            TcpPacket tcp = packet.get(TcpPacket.class);
            if (tcp != null && tcp.getPayload() != null) {
                return tcp.getPayload().getRawData();
            }
        } else if (packet.contains(UdpPacket.class)) {
            UdpPacket udp = packet.get(UdpPacket.class);
            if (udp != null && udp.getPayload() != null) {
                return udp.getPayload().getRawData();
            }
        }
        return null;
    }

    private static String detectProtocol(String payload) {
        for (Map.Entry<String, Pattern> entry : PROTOCOL_PATTERNS.entrySet()) {
            if (entry.getValue().matcher(payload).find()) {
                return entry.getKey();
            }
        }
        return "Unknown";
    }
}