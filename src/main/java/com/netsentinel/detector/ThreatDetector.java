import java.util.List;

public interface ThreatDetector {
    List<Alert> detect(List<LogEntry> logs);
    ThreatType getThreatType();
}