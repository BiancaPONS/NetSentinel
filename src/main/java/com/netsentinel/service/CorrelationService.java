package com.netsentinel.service;

import com.netsentinel.model.Alert;
import com.netsentinel.model.Severity;
import com.netsentinel.model.ThreatType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class CorrelationService {

    public List<Alert> correlate(List<Alert> alerts) {
        Map<String, List<Alert>> alertsByIp = alerts.stream()
        .filter(alert -> alert.getIp() != null)
        .collect(Collectors.groupingBy(Alert::getIp));

    List<Alert> correlatedAlerts = new ArrayList<>(alerts);

        for (Map.Entry<String, List<Alert>> entry : alertsByIp.entrySet()) {
            List<Alert> ipAlerts = entry.getValue();

            Set<ThreatType> types = ipAlerts.stream()
                    .map(Alert::getThreatType)
                    .collect(Collectors.toSet());

            int detectorCount = types.size();

            if (detectorCount >= 3) {
                for (Alert alert : ipAlerts) {
                    replaceSeverity(correlatedAlerts, alert, Severity.CRITICAL);
                }
            } else if (detectorCount == 2) {
                for (Alert alert : ipAlerts) {
                    replaceSeverity(correlatedAlerts, alert, increaseSeverity(alert.getSeverity()));
                }
            }
            // 1 détecteur → rien à faire
        }
        return correlatedAlerts;
    }

    private void replaceSeverity(List<Alert> alerts, Alert target, Severity newSeverity) {
        for (int i = 0; i < alerts.size(); i++) {
            Alert alert = alerts.get(i);
            if (sameAlert(alert, target)) {
                alerts.set(i, alert.withSeverity(newSeverity));
                return;
            }
        }
    }

    private boolean sameAlert(Alert left, Alert right) {
        return left.getThreatType() == right.getThreatType()
                && equals(left.getIp(), right.getIp())
                && left.getDetectedAt().equals(right.getDetectedAt())
                && left.getMessage().equals(right.getMessage());
    }

    private boolean equals(Object left, Object right) {
        return left == null ? right == null : left.equals(right);
    }

    private Severity increaseSeverity(Severity s) {
        return switch (s) {
            case LOW -> Severity.MEDIUM;
            case MEDIUM -> Severity.HIGH;
            case HIGH, CRITICAL -> Severity.CRITICAL;
        };
    }
}