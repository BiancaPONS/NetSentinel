import java.time.LocalDateTime;

public class Alert {
    private String ip;
    private ThreatType threatType;
    private Severity severity;
    private LocalDateTime timestamp;
    private String description;

    public Alert(String ip, ThreatType threatType, Severity severity,
                 LocalDateTime timestamp, String description) {
        this.ip = ip;
        this.threatType = threatType;
        this.severity = severity;
        this.timestamp = timestamp;
        this.description = description;
    }

    public String getIp() { return ip; }
    public ThreatType getThreatType() { return threatType; }
    public Severity getSeverity() { return severity; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public String getDescription() { return description; }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }
}