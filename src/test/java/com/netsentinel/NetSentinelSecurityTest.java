package com.netsentinel;

import com.netsentinel.detector.BruteForceDetector;
import com.netsentinel.detector.SqlInjectionDetector;
import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.model.ThreatType;
import com.netsentinel.parser.LogParser;
import com.netsentinel.service.CorrelationService;
import com.netsentinel.service.WhitelistService;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class NetSentinelSecurityTest {

    private final LogParser parser = new LogParser();

    @Test
    void parsesApacheCombinedLogLineCorrectly() {
        String line = "192.168.1.45 - - [15/Mar/2025:10:23:45 +0100] \"GET /index.html HTTP/1.1\" 200 5423 \"-\" \"Mozilla/5.0\"";

        Optional<LogEntry> parsed = parser.parseLine(line);

        assertTrue(parsed.isPresent());
        LogEntry entry = parsed.orElseThrow();
        assertEquals("192.168.1.45", entry.getIp());
        assertEquals("anonymous", entry.getUser());
        assertEquals(LocalDateTime.of(2025, 3, 15, 10, 23, 45), entry.getTimestamp());
        assertEquals("GET", entry.getMethod());
        assertEquals("/index.html", entry.getUrl());
        assertEquals(200, entry.getStatusCode());
        assertEquals(5423L, entry.getResponseSize());
        assertEquals("-", entry.getReferer());
        assertEquals("Mozilla/5.0", entry.getUserAgent());
    }

    @Test
    void fifteenUnauthorizedRequestsInTwoMinutesTriggerBruteforceAlert() {
        List<LogEntry> logs = buildRepeatedFailures("10.0.0.12", 15, 401, 8);

        List<Alert> alerts = new BruteForceDetector().detect(logs);

        assertEquals(1, alerts.size());
        assertEquals(ThreatType.BRUTE_FORCE, alerts.get(0).getThreatType());
        assertEquals(Severity.MEDIUM, alerts.get(0).getSeverity());
    }

    @Test
    void suspiciousSqlUrlTriggersSqlInjectionAlert() {
        LogEntry entry = log("203.0.113.50", LocalDateTime.of(2025, 3, 15, 10, 24, 15),
            "GET", "/search?q=' OR 1=1--", 200, "-", "sqlmap/1.5");

        List<Alert> alerts = new SqlInjectionDetector().detect(List.of(entry));

        assertEquals(1, alerts.size());
        assertEquals(ThreatType.SQL_INJECTION, alerts.get(0).getThreatType());
    }

    @Test
    void whitelistedIpDoesNotGenerateAlerts() throws IOException {
        Path whitelistFile = Files.createTempFile("netsentinel-whitelist", ".txt");
        Files.writeString(whitelistFile, "192.168.1.10\n");

        WhitelistService whitelistService = new WhitelistService(whitelistFile.toString());
        List<LogEntry> logs = List.of(
            log("192.168.1.10", LocalDateTime.of(2025, 3, 15, 10, 0, 0), "POST", "/login", 401, "-", "curl/7.68")
        );

        List<LogEntry> filteredLogs = whitelistService.filterLogs(logs);
        List<Alert> alerts = new BruteForceDetector().detect(filteredLogs);

        assertTrue(filteredLogs.isEmpty());
        assertTrue(alerts.isEmpty());
    }

    @Test
    void correlationIncreasesSeverityForMultipleDetectors() {
        LocalDateTime detectedAt = LocalDateTime.of(2025, 3, 15, 10, 30, 0);
        List<Alert> alerts = List.of(
            new Alert(ThreatType.BRUTE_FORCE, Severity.MEDIUM, "198.51.100.10", detectedAt, "Bruteforce"),
            new Alert(ThreatType.SQL_INJECTION, Severity.HIGH, "198.51.100.10", detectedAt.plusSeconds(1), "SQLi")
        );

        List<Alert> correlated = new CorrelationService().correlate(alerts);

        assertEquals(Severity.HIGH, correlated.get(0).getSeverity());
        assertEquals(Severity.CRITICAL, correlated.get(1).getSeverity());
    }

    private List<LogEntry> buildRepeatedFailures(String ip, int count, int statusCode, int secondsBetweenRequests) {
        List<LogEntry> logs = new java.util.ArrayList<>();
        LocalDateTime start = LocalDateTime.of(2025, 3, 15, 10, 0, 0);
        for (int index = 0; index < count; index++) {
            logs.add(log(ip, start.plusSeconds((long) index * secondsBetweenRequests),
                "POST", "/login", statusCode, "287", "curl/7.68"));
        }
        return logs;
    }

    private LogEntry log(String ip, LocalDateTime timestamp, String method, String url, int statusCode,
                         String responseSize, String userAgent) {
        long size = "-".equals(responseSize) ? 0L : Long.parseLong(responseSize);
        return new LogEntry(ip, "anonymous", timestamp, method, url, statusCode, size, "-", userAgent);
    }
}
