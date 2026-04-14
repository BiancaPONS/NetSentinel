// CorrelationService.java
import java.util.*;
import java.util.stream.Collectors;

public class CorrelationService {

    public List<Alert> correlate(List<Alert> alerts) {
        Map<String, List<Alert>> alertsByIp = alerts.stream()
                .collect(Collectors.groupingBy(Alert::getIp));

        for (Map.Entry<String, List<Alert>> entry : alertsByIp.entrySet()) {
            List<Alert> ipAlerts = entry.getValue();

            Set<ThreatType> types = ipAlerts.stream()
                    .map(Alert::getThreatType)
                    .collect(Collectors.toSet());

            int detectorCount = types.size();

            if (detectorCount >= 3) {
                for (Alert alert : ipAlerts) {
                    alert.setSeverity(Severity.CRITICAL);
                }
            } else if (detectorCount == 2) {
                for (Alert alert : ipAlerts) {
                    alert.setSeverity(increaseSeverity(alert.getSeverity()));
                }
            }
            // 1 détecteur → rien à faire
        }
        return alerts;
    }

    private Severity increaseSeverity(Severity s) {
        return switch (s) {
            case LOW -> Severity.MEDIUM;
            case MEDIUM -> Severity.HIGH;
            case HIGH, CRITICAL -> Severity.CRITICAL;
        };
    }
}