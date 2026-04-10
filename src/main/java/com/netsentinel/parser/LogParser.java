package main.java.com.netsentinel.parser;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import main.java.com.netsentinel.model.LogEntry;


public class LogParser {
    private static final Pattern APACHE_PATTERN = Pattern.compile(
    "^(\\S+)\\s+(-|\\S+)\\s+\\[([^\\]]+)\\]\\s+\"([A-Z]+)\\s+(.*?)\\s+HTTP/[\\d\\.]+\"\\s+(\\d{3})\\s+(\\d+|--)\\s+\"(.*?)\"\\s+\"(.*)\"\\s*$"
);
    
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = 
        DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ssXXX");
    
    /**
     * Parse un fichier de logs et retourne une List<LogEntry>
     */
    public List<LogEntry> parseLogFile(String filename) throws IOException {
        List<LogEntry> logEntries = new ArrayList<>();
        int invalidLines = 0;
        
        try (BufferedReader reader = new BufferedReader(new FileReader(filename))) {
            String line;
            int lineNumber = 0;
            
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                LogEntry entry = parseSingleLine(line, lineNumber);
                if (entry != null) {
                    logEntries.add(entry);
                } else {
                    invalidLines++;
                }
            }
        }
        
        System.out.printf("%d lignes parsées, %d lignes invalides ignorées%n", 
                         logEntries.size(), invalidLines);
        return logEntries;
    }
    
    /**
     * Parse une seule ligne de log
     */
    private LogEntry parseSingleLine(String line, int lineNumber) {
        Matcher matcher = APACHE_PATTERN.matcher(line);
        
        if (!matcher.matches()) {
            System.err.printf("Ligne %d invalide : %s%n", lineNumber, line.substring(0, Math.min(100, line.length())));
            return null;
        }
        
        try {
            String ip = matcher.group(1);
            String user = matcher.group(2);
            String timestampStr = matcher.group(3);
            String method = matcher.group(4);
            String url = matcher.group(5);
            int statusCode = Integer.parseInt(matcher.group(6));
            long responseSize = parseSize(matcher.group(7));
            String referer = matcher.group(8);
            String userAgent = matcher.group(9);
            
            LocalDateTime timestamp = LocalDateTime.parse(timestampStr, TIMESTAMP_FORMATTER);
            
            return new LogEntry(ip, user, timestamp, method, url, statusCode, 
                              responseSize, referer, userAgent);
        } catch (DateTimeParseException | NumberFormatException e) {
            System.err.printf("Erreur parsing ligne %d : %s%n", lineNumber, e.getMessage());
            return null;
        }
    }
    
    private long parseSize(String sizeStr) {
        if ("-".equals(sizeStr)) {
            return 0L;
        }
        return Long.parseLong(sizeStr);
    }
}
