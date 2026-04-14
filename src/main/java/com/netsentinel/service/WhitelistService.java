package com.netsentinel.service;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class WhitelistService {

    private final Set<String> whitelistedIps = new HashSet<>();

    public WhitelistService(String whitelistResourcePath) {
        loadWhitelist(whitelistResourcePath);
    }

    private void loadWhitelist(String resourcePath) {
        try (BufferedReader reader = openReader(resourcePath)) {
            if (reader == null) {
                return;
            }
            String line;
            while ((line = reader.readLine()) != null) {
                String trimmed = line.trim();
                if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                    whitelistedIps.add(trimmed);
                }
            }
        } catch (IOException e) {
            throw new IllegalStateException("Impossible de charger la whitelist: " + resourcePath, e);
        }
    }

    public boolean isWhitelisted(String ip) {
        return whitelistedIps.contains(ip);
    }

    public List<LogEntry> filterLogs(List<LogEntry> logs) {
        List<LogEntry> filtered = new ArrayList<>();
        for (LogEntry log : logs) {
            if (!isWhitelisted(log.getIp())) {
                filtered.add(log);
            }
        }
        return filtered;
    }

    public List<Alert> filterAlerts(List<Alert> alerts) {
        List<Alert> filtered = new ArrayList<>();
        for (Alert alert : alerts) {
            String ip = alert.getIp();
            if (ip == null || !isWhitelisted(ip)) {
                filtered.add(alert);
            }
        }
        return filtered;
    }

    private BufferedReader openReader(String resourcePath) throws IOException {
        InputStream is = getClass().getResourceAsStream(resourcePath);
        if (is != null) {
            return new BufferedReader(new InputStreamReader(is));
        }

        String normalizedPath = resourcePath.startsWith("/") ? resourcePath.substring(1) : resourcePath;
        Path filePath = Path.of(normalizedPath);
        if (Files.exists(filePath)) {
            return Files.newBufferedReader(filePath);
        }

        filePath = Path.of(resourcePath);
        if (Files.exists(filePath)) {
            return Files.newBufferedReader(filePath);
        }

        return null;
    }
}