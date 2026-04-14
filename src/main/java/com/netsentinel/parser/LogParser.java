package com.netsentinel.parser;

import com.netsentinel.model.LogEntry;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogParser {
    
    private static final Pattern APACHE_COMBINED_PATTERN = Pattern.compile(
        "^(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+\\[([^\\]]+)]\\s+\"([A-Z]+)\\s+(\\S+)\\s+HTTP/([\\d.]+)\"\\s+(\\d{3})\\s+(\\d+|-)\\s+\"([^\"]*)\"\\s+\"([^\"]*)\"\\s*$"
    );
    
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = 
        DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);
    
    public List<LogEntry> parseLogFile(String filename) throws IOException {
        List<LogEntry> logEntries = new ArrayList<>();
        int invalidLines = 0;
        int lineNumber = 0;
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                Optional<LogEntry> entry = parseSingleLine(line, lineNumber);
                if (entry.isPresent()) {
                    logEntries.add(entry.get());
                    continue;
                }
                invalidLines++;
            }
        }
        
        System.out.printf(" %d lignes parsées, %d lignes invalides ignorées%n", 
                         logEntries.size(), invalidLines);
        return logEntries;
    }
    
    public Optional<LogEntry> parseLine(String line) {
        return parseSingleLine(line, 1);
    }

    private Optional<LogEntry> parseSingleLine(String line, int lineNumber) {
        Matcher matcher = APACHE_COMBINED_PATTERN.matcher(line);
        
        if (!matcher.matches()) {
            // Debug seulement pour les 5 premières erreurs
            if (lineNumber <= 5) {
                System.err.printf("Ligne %d invalide : %.100s%n", lineNumber, line);
            }
            return Optional.empty();
        }
        
        try {
            String ip = matcher.group(1);
            String authUser = matcher.group(3);
            String timestampStr = matcher.group(4);
            String method = matcher.group(5);
            String url = matcher.group(6);
            int statusCode = Integer.parseInt(matcher.group(8));
            String sizeStr = matcher.group(9);
            String referer = matcher.group(10);
            String userAgent = matcher.group(11);
            
            OffsetDateTime offsetDateTime = OffsetDateTime.parse(timestampStr, TIMESTAMP_FORMATTER);
            LocalDateTime timestamp = offsetDateTime.toLocalDateTime();
            long responseSize = "-".equals(sizeStr) ? 0L : Long.parseLong(sizeStr);
            String user = "-".equals(authUser) ? "anonymous" : authUser;
            
            return Optional.of(new LogEntry(ip, user, timestamp, method, url, statusCode,
                responseSize, referer, userAgent));
        } catch (DateTimeParseException | NumberFormatException e) {
            if (lineNumber <= 5) {
                System.err.printf("Erreur parsing ligne %d : %s%n", lineNumber, e.getMessage());
            }
            return Optional.empty();
        }
    }
}