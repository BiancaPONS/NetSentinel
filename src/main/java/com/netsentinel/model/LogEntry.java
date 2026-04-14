import java.time.LocalDateTime;

public interface LogEntry {
    String getIp();
    int getStatusCode();
    LocalDateTime getTimestamp();
}