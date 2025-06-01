package com.armaan.sniffer.config;

import java.util.Properties;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

public class SnifferConfig {
    private static final String CONFIG_FILE = "sniffer_config.properties";
    private static Properties properties = new Properties();

    // Default values
    private static final int DEFAULT_SNAPLEN = 65536;
    private static final int DEFAULT_TIMEOUT = 10000;
    private static final int DEFAULT_PACKET_COUNT = 50;
    private static final int DEFAULT_DPI_THRESHOLD = 1000;
    private static final boolean DEFAULT_ENABLE_DPI = true;
    private static final boolean DEFAULT_ENABLE_ML = true;

    static {
        loadConfig();
    }

    public static void loadConfig() {
        try (FileInputStream in = new FileInputStream(CONFIG_FILE)) {
            properties.load(in);
        } catch (IOException e) {
            // If file doesn't exist, create with defaults
            setDefaults();
            saveConfig();
        }
    }

    public static void saveConfig() {
        try (FileOutputStream out = new FileOutputStream(CONFIG_FILE)) {
            properties.store(out, "Network Sniffer Configuration");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void setDefaults() {
        properties.setProperty("snapLen", String.valueOf(DEFAULT_SNAPLEN));
        properties.setProperty("timeout", String.valueOf(DEFAULT_TIMEOUT));
        properties.setProperty("packetCount", String.valueOf(DEFAULT_PACKET_COUNT));
        properties.setProperty("dpiThreshold", String.valueOf(DEFAULT_DPI_THRESHOLD));
        properties.setProperty("enableDPI", String.valueOf(DEFAULT_ENABLE_DPI));
        properties.setProperty("enableML", String.valueOf(DEFAULT_ENABLE_ML));
    }

    // Getters
    public static int getSnapLen() {
        return Integer.parseInt(properties.getProperty("snapLen", String.valueOf(DEFAULT_SNAPLEN)));
    }

    public static int getTimeout() {
        return Integer.parseInt(properties.getProperty("timeout", String.valueOf(DEFAULT_TIMEOUT)));
    }

    public static int getPacketCount() {
        return Integer.parseInt(properties.getProperty("packetCount", String.valueOf(DEFAULT_PACKET_COUNT)));
    }

    public static int getDpiThreshold() {
        return Integer.parseInt(properties.getProperty("dpiThreshold", String.valueOf(DEFAULT_DPI_THRESHOLD)));
    }

    public static boolean isDpiEnabled() {
        return Boolean.parseBoolean(properties.getProperty("enableDPI", String.valueOf(DEFAULT_ENABLE_DPI)));
    }

    public static boolean isMlEnabled() {
        return Boolean.parseBoolean(properties.getProperty("enableML", String.valueOf(DEFAULT_ENABLE_ML)));
    }

    // Setters
    public static void setSnapLen(int value) {
        properties.setProperty("snapLen", String.valueOf(value));
        saveConfig();
    }

    public static void setTimeout(int value) {
        properties.setProperty("timeout", String.valueOf(value));
        saveConfig();
    }

    public static void setPacketCount(int value) {
        properties.setProperty("packetCount", String.valueOf(value));
        saveConfig();
    }

    public static void setDpiThreshold(int value) {
        properties.setProperty("dpiThreshold", String.valueOf(value));
        saveConfig();
    }

    public static void setDpiEnabled(boolean value) {
        properties.setProperty("enableDPI", String.valueOf(value));
        saveConfig();
    }

    public static void setMlEnabled(boolean value) {
        properties.setProperty("enableML", String.valueOf(value));
        saveConfig();
    }
}