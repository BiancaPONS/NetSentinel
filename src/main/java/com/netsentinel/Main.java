package com.netsentinel;

import com.netsentinel.model.LogEntry;
import com.netsentinel.parser.LogParser;
import com.netsentinel.service.LogIndexer;
import com.netsentinel.service.StatisticsService;

import java.io.IOException;
import java.time.LocalDateTime;
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
}