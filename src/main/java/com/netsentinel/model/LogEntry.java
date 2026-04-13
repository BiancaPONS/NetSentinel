package com.netsentinel.model;

import java.time.LocalDateTime;
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
    
    public String getIp() { return ip; }
    public String getUser() { return user; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public int getStatusCode() { return statusCode; }
    public long getResponseSize() { return responseSize; }
    public String getReferer() { return referer; }
    public String getUserAgent() { return userAgent; }
    
    @Override
    public String toString() {
        return String.format("LogEntry{ip='%s', user='%s', timestamp=%s, method='%s', url='%s', statusCode=%d, responseSize=%d, referer='%s', userAgent='%s'}",
            ip, user, timestamp,
            method, url, statusCode, responseSize, referer, userAgent);
    }
}