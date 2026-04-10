package main.java.com.netsentinel.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Objects;

public class LogEntry {
    private final String ip;
    private final String user;
    private final LocalDateTime timestamp;
    private final String method;
    private final String url;
    private final int statusCode;
    private final long responseSize;
    private final String referer;
    private final String userAgent;
    
    // Constructeur
    public LogEntry(String ip, String user, LocalDateTime timestamp, 
                   String method, String url, int statusCode, 
                   long responseSize, String referer, String userAgent) {
        this.ip = ip;
        this.user = user;
        this.timestamp = timestamp;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.responseSize = responseSize;
        this.referer = referer;
        this.userAgent = userAgent;
    }
    
    // Getters
    public String getIp() { return ip; }
    public String getUser() { return user; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public int getStatusCode() { return statusCode; }
    public long getResponseSize() { return responseSize; }
    public String getReferer() { return referer; }
    public String getUserAgent() { return userAgent; }
    
    // toString() pour debug
    @Override
    public String toString() {
        return String.format("%s - %s [%s] \"%s %s\" %d %d \"%s\" \"%s\"", 
            ip, user, timestamp.format(DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z")),
            method, url, statusCode, responseSize, referer, userAgent);
    }
    
    // equals() et hashCode() pour les tests et les Maps
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        LogEntry logEntry = (LogEntry) o;
        return statusCode == logEntry.statusCode &&
               responseSize == logEntry.responseSize &&
               Objects.equals(ip, logEntry.ip) &&
               Objects.equals(user, logEntry.user) &&
               Objects.equals(timestamp, logEntry.timestamp) &&
               Objects.equals(method, logEntry.method) &&
               Objects.equals(url, logEntry.url) &&
               Objects.equals(referer, logEntry.referer) &&
               Objects.equals(userAgent, logEntry.userAgent);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(ip, user, timestamp, method, url, statusCode, responseSize, referer, userAgent);
    }
}