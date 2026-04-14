package com.netsentinel;

import com.netsentinel.detector.BruteForceDetector;
import com.netsentinel.detector.DdosDetector;
import com.netsentinel.detector.ScanDetector;
import com.netsentinel.detector.SqlInjectionDetector;
import com.netsentinel.detector.ThreatDetector;
import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.parser.LogParser;
import com.netsentinel.service.LogIndexer;
import com.netsentinel.service.StatisticsService;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class Main {

    private static final String CLEAN_LOG_PATH = "src/main/resources/access_log_clean.txt";
    private static final String ATTACK_LOG_PATH = "src/main/resources/access_log_attack.txt";

    public static void main(String[] args) {
        LogParser parser = new LogParser();
        LogIndexer indexer = new LogIndexer();
        StatisticsService statisticsService = new StatisticsService();

        try {
            String filePath = resolveInputFile(args);
            List<LogEntry> logs = parser.parseLogFile(filePath);

            Map<String, List<LogEntry>> logsByIp = indexer.indexByIp(logs);
            TreeMap<LocalDateTime, List<LogEntry>> logsByTime = indexer.indexByTime(logs);

            System.out.printf("Fichier analyse: %s%n", filePath);
            System.out.printf("IPs indexees: %d%n", logsByIp.size());
            System.out.printf("Horodatages indexes: %d%n%n", logsByTime.size());

            statisticsService.printDashboard(logs);

            List<ThreatDetector> detectors = List.of(
                new BruteForceDetector(),
                new SqlInjectionDetector(),
                new DdosDetector(),
                new ScanDetector()
            );

            List<Alert> alerts = runThreatDetection(detectors, logs);
            printAlerts(alerts);
        } catch (IOException e) {
            System.err.println("Erreur lors de la lecture du fichier : " + e.getMessage());
        }
    }

    private static String resolveInputFile(String[] args) {
        if (args.length == 0) {
            return CLEAN_LOG_PATH;
        }
        if ("attack".equalsIgnoreCase(args[0])) {
            return ATTACK_LOG_PATH;
        }
        if ("clean".equalsIgnoreCase(args[0])) {
            return CLEAN_LOG_PATH;
        }
        return args[0];
    }

    private static List<Alert> runThreatDetection(List<ThreatDetector> detectors, List<LogEntry> logs) {
        List<Alert> alerts = new ArrayList<>();
        for (ThreatDetector detector : detectors) {
            alerts.addAll(detector.detect(logs));
        }
        return alerts;
    }

    private static void printAlerts(List<Alert> alerts) {
        System.out.println();
        System.out.println("==== Alertes de securite ====");
        if (alerts.isEmpty()) {
            System.out.println("Aucune menace detectee.");
            return;
        }

        alerts.stream()
            .sorted((left, right) -> left.getDetectedAt().compareTo(right.getDetectedAt()))
            .forEach(alert -> System.out.println("- " + alert));
        System.out.printf("Total alertes: %d%n", alerts.size());
    }
}