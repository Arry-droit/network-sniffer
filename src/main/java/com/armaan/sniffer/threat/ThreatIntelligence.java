package com.armaan.sniffer.threat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.json.JSONObject;
import org.json.JSONArray;

public class ThreatIntelligence {
    private static final String ABUSEIPDB_API_KEY = "YOUR_API_KEY"; // Replace with your API key
    private static final String VIRUSTOTAL_API_KEY = "YOUR_API_KEY"; // Replace with your API key

    private static final Set<String> KNOWN_MALWARE_IPS = ConcurrentHashMap.newKeySet();
    private static final Set<String> KNOWN_MALWARE_DOMAINS = ConcurrentHashMap.newKeySet();
    private static final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    static {
        // Start periodic updates
        scheduler.scheduleAtFixedRate(
                ThreatIntelligence::updateThreatData,
                0, // Initial delay
                1, // Period
                TimeUnit.HOURS // Time unit
        );
    }

    public static class ThreatResult {
        private final boolean isMalicious;
        private final String threatType;
        private final int confidence;
        private final String details;

        public ThreatResult(boolean isMalicious, String threatType, int confidence, String details) {
            this.isMalicious = isMalicious;
            this.threatType = threatType;
            this.confidence = confidence;
            this.details = details;
        }

        public boolean isMalicious() {
            return isMalicious;
        }

        public String getThreatType() {
            return threatType;
        }

        public int getConfidence() {
            return confidence;
        }

        public String getDetails() {
            return details;
        }
    }

    public static ThreatResult checkIP(String ip) {
        // Check local cache first
        if (KNOWN_MALWARE_IPS.contains(ip)) {
            return new ThreatResult(true, "KNOWN_MALWARE", 100, "IP found in local threat database");
        }

        try {
            // Check AbuseIPDB
            ThreatResult abuseResult = checkAbuseIPDB(ip);
            if (abuseResult.isMalicious()) {
                KNOWN_MALWARE_IPS.add(ip);
                return abuseResult;
            }

            // Check VirusTotal
            ThreatResult vtResult = checkVirusTotal(ip);
            if (vtResult.isMalicious()) {
                KNOWN_MALWARE_IPS.add(ip);
                return vtResult;
            }

            return new ThreatResult(false, null, 0, "No threats detected");
        } catch (Exception e) {
            return new ThreatResult(false, null, 0, "Error checking threat intelligence: " + e.getMessage());
        }
    }

    private static ThreatResult checkAbuseIPDB(String ip) throws Exception {
        URL url = new URL("https://api.abuseipdb.com/api/v2/check?ipAddress=" + ip);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Key", ABUSEIPDB_API_KEY);
        conn.setRequestProperty("Accept", "application/json");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }

            JSONObject json = new JSONObject(response.toString());
            JSONObject data = json.getJSONObject("data");

            int abuseConfidence = data.getInt("abuseConfidenceScore");
            if (abuseConfidence > 50) {
                return new ThreatResult(
                        true,
                        "ABUSEIPDB_THREAT",
                        abuseConfidence,
                        "IP reported as malicious on AbuseIPDB");
            }
        }

        return new ThreatResult(false, null, 0, "No threats detected on AbuseIPDB");
    }

    private static ThreatResult checkVirusTotal(String ip) throws Exception {
        URL url = new URL(
                "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=" + VIRUSTOTAL_API_KEY + "&ip=" + ip);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }

            JSONObject json = new JSONObject(response.toString());
            int positives = json.getInt("positives");
            int total = json.getInt("total");

            if (positives > 0) {
                return new ThreatResult(
                        true,
                        "VIRUSTOTAL_THREAT",
                        (positives * 100) / total,
                        positives + " out of " + total + " security vendors flagged this IP");
            }
        }

        return new ThreatResult(false, null, 0, "No threats detected on VirusTotal");
    }

    private static void updateThreatData() {
        try {
            // Update from AbuseIPDB blacklist
            updateFromAbuseIPDB();

            // Update from VirusTotal
            updateFromVirusTotal();

            // Clean up old entries (optional)
            cleanupOldEntries();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void updateFromAbuseIPDB() throws Exception {
        URL url = new URL("https://api.abuseipdb.com/api/v2/blacklist");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setRequestProperty("Key", ABUSEIPDB_API_KEY);
        conn.setRequestProperty("Accept", "application/json");

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }

            JSONObject json = new JSONObject(response.toString());
            JSONArray data = json.getJSONArray("data");

            for (int i = 0; i < data.length(); i++) {
                JSONObject entry = data.getJSONObject(i);
                String ip = entry.getString("ipAddress");
                KNOWN_MALWARE_IPS.add(ip);
            }
        }
    }

    private static void updateFromVirusTotal() {
        // Implement VirusTotal blacklist update
        // This would require additional API endpoints and handling
    }

    private static void cleanupOldEntries() {
        // Implement cleanup logic for old entries
        // This could be based on timestamp or other criteria
    }

    public static void shutdown() {
        scheduler.shutdown();
    }
}