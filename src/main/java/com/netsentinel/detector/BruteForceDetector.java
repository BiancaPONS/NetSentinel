// BruteForceDetector.java
import java.time.Duration;
import java.util.*;

public class BruteForceDetector implements ThreatDetector {

    private final WhitelistService whitelistService;
    private final int mediumThreshold;
    private final int highThreshold;
    private final Duration window;

    public BruteForceDetector(WhitelistService whitelistService) {
        this(whitelistService, 10, 50, Duration.ofMinutes(5));
    }

    public BruteForceDetector(WhitelistService whitelistService,
                              int mediumThreshold,
                              int highThreshold,
                              Duration window) {
        this.whitelistService = whitelistService;
        this.mediumThreshold = mediumThreshold;
        this.highThreshold = highThreshold;
        this.window = window;
    }

    @Override
    public ThreatType getThreatType() {
        return ThreatType.BRUTE_FORCE;
    }

    @Override
    public List<Alert> detect(List<LogEntry> logs) {
        List<Alert> alerts = new ArrayList<>();

        // regrouper les réponses 401/403 par IP
        Map<String, List<LogEntry>> byIp = new HashMap<>();
        for (LogEntry entry : logs) {
            if (whitelistService.isWhitelisted(entry.getIp())) {
                continue;
            }
            int status = entry.getStatusCode();
            if (status == 401 || status == 403) {
                byIp.computeIfAbsent(entry.getIp(), k -> new ArrayList<>()).add(entry);
            }
        }

        for (Map.Entry<String, List<LogEntry>> e : byIp.entrySet()) {
            String ip = e.getKey();
            List<LogEntry> failures = e.getValue();
            failures.sort(Comparator.comparing(LogEntry::getTimestamp));

            int n = failures.size();
            int left = 0;

            for (int right = 0; right < n; right++) {
                while (left < right &&
                        Duration.between(failures.get(left).getTimestamp(),
                                         failures.get(right).getTimestamp())
                                .compareTo(window) > 0) {
                    left++;
                }

                int count = right - left + 1;
                if (count > mediumThreshold) {
                    Severity severity = count > highThreshold ? Severity.HIGH : Severity.MEDIUM;
                    Alert alert = new Alert(
                            ip,
                            ThreatType.BRUTE_FORCE,
                            severity,
                            failures.get(right).getTimestamp(),
                            "Brute-force: " + count + " échecs 401/403 en moins de " + window.toMinutes() + " minutes"
                    );
                    alerts.add(alert);
                    break; // une alerte par IP suffit
                }
            }
        }

        return alerts;
    }
}