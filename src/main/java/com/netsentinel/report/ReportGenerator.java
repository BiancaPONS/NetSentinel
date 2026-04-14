package com.netsentinel.report;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.model.ThreatType;
import com.netsentinel.service.StatisticsService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class ReportGenerator {

    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void generateSecurityReport(
        String analyzedFile,
        List<LogEntry> logs,
        List<Alert> alerts,
        StatisticsService statisticsService,
        String outputFilePath
    ) throws IOException {
        StringBuilder report = new StringBuilder();

        appendTitle(report, "RAPPORT DE SECURITE NETSENTINEL");
        appendKeyValue(report, "Fichier analyse", analyzedFile);
        appendKeyValue(report, "Genere le", LocalDateTime.now().format(DATE_FORMATTER));
        report.append('\n');

        appendExecutiveSummary(report, logs, alerts, statisticsService);
        appendTimeline(report, alerts);
        appendDetailsByIp(report, alerts);
        appendRecommendations(report);
        appendBlockingRules(report, alerts);
        appendResidualRisks(report);
        appendImprovements(report);

        Path outputPath = Path.of(outputFilePath);
        Path parent = outputPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(outputPath, report.toString(), StandardCharsets.UTF_8);
    }

    private void appendExecutiveSummary(StringBuilder report, List<LogEntry> logs, List<Alert> alerts,
                                        StatisticsService statisticsService) {
        appendSectionHeader(report, "1) RESUME EXECUTIF");
        appendKeyValue(report, "Total requetes analysees", String.valueOf(statisticsService.totalRequests(logs)));
        appendKeyValue(report, "Total alertes", String.valueOf(alerts.size()));

        report.append('\n').append("Alertes par severite").append('\n');
        for (Severity severity : Severity.values()) {
            long count = alerts.stream().filter(alert -> alert.getSeverity() == severity).count();
            report.append(String.format("  - %-8s : %d%n", severity, count));
        }

        report.append('\n').append("Top 10 IPs les plus dangereuses").append('\n');
        Map<String, Long> dangerousIps = alerts.stream()
            .filter(alert -> alert.getIp() != null)
            .collect(Collectors.groupingBy(Alert::getIp, Collectors.counting()))
            .entrySet()
            .stream()
            .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder()))
            .limit(10)
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (left, right) -> left, LinkedHashMap::new));

        if (dangerousIps.isEmpty()) {
            report.append("  - Aucune alerte liee a une IP\n");
        } else {
            int rank = 1;
            for (Map.Entry<String, Long> entry : dangerousIps.entrySet()) {
                report.append(String.format("  %2d. %-16s  %4d alertes%n", rank, entry.getKey(), entry.getValue()));
                rank++;
            }
        }
        report.append('\n');
    }

    private void appendTimeline(StringBuilder report, List<Alert> alerts) {
        appendSectionHeader(report, "2) TIMELINE DES INCIDENTS");
        List<Alert> sortedAlerts = new ArrayList<>(alerts);
        sortedAlerts.sort(Comparator.comparing(Alert::getDetectedAt));

        if (sortedAlerts.isEmpty()) {
            report.append("Aucune alerte detectee.\n\n");
            return;
        }

        report.append(String.format("%-19s | %-8s | %-13s | %-15s | %s%n",
            "Date", "Severite", "Type", "Source", "Message"));
        report.append(repeat('-', 110)).append('\n');

        for (Alert alert : sortedAlerts) {
            String source = alert.getIp() == null ? "global" : alert.getIp();
            report.append(String.format("%-19s | %-8s | %-13s | %-15s | %s%n",
                alert.getDetectedAt().format(DATE_FORMATTER),
                alert.getSeverity(),
                alert.getThreatType(),
                source,
                alert.getMessage()));
        }
        report.append('\n');
    }

    private void appendDetailsByIp(StringBuilder report, List<Alert> alerts) {
        appendSectionHeader(report, "3) DETAIL PAR IP SUSPECTE");
        Map<String, List<Alert>> alertsByIp = alerts.stream()
            .filter(alert -> alert.getIp() != null)
            .collect(Collectors.groupingBy(Alert::getIp, TreeMap::new, Collectors.toList()));

        if (alertsByIp.isEmpty()) {
            report.append("Aucune IP suspecte detectee.\n\n");
            return;
        }

        for (Map.Entry<String, List<Alert>> entry : alertsByIp.entrySet()) {
            String ip = entry.getKey();
            List<Alert> ipAlerts = entry.getValue();

            report.append(ip).append('\n');
            report.append("  Nombre total d'alertes: ").append(ipAlerts.size()).append('\n');

            Map<ThreatType, Long> threatCounts = ipAlerts.stream()
                .collect(Collectors.groupingBy(Alert::getThreatType, Collectors.counting()));
            report.append("  Par type: ");
            for (ThreatType threatType : ThreatType.values()) {
                long count = threatCounts.getOrDefault(threatType, 0L);
                if (count > 0) {
                    report.append(threatType).append('=').append(count).append(' ');
                }
            }
            report.append('\n');

            ipAlerts.stream()
                .sorted(Comparator.comparing(Alert::getDetectedAt))
                .forEach(alert -> report.append(String.format("    - [%s][%s][%s] %s%n",
                    alert.getDetectedAt().format(DATE_FORMATTER),
                    alert.getSeverity(),
                    alert.getThreatType(),
                    alert.getMessage())));

            report.append('\n');
        }
    }

    private void appendRecommendations(StringBuilder report) {
        appendSectionHeader(report, "4) RECOMMANDATIONS");
        report.append("- BRUTE_FORCE  : Appliquer du rate limiting, MFA, verrouillage temporaire des comptes.\n");
        report.append("- SQL_INJECTION: Utiliser des requetes parametrees et renforcer la validation des entrees.\n");
        report.append("- DDOS         : Activer WAF/CDN/scrubbing et surveiller les pics en temps reel.\n");
        report.append("- SCAN         : Reduire la surface exposee et alerter sur la reconnaissance agressive.\n\n");
    }

    private void appendBlockingRules(StringBuilder report, List<Alert> alerts) {
        appendSectionHeader(report, "5) REGLES DE BLOCAGE");
        Set<String> blockedIps = alerts.stream()
            .filter(alert -> alert.getIp() != null)
            .filter(alert -> alert.getSeverity() == Severity.HIGH || alert.getSeverity() == Severity.CRITICAL)
            .map(Alert::getIp)
            .collect(Collectors.toCollection(java.util.LinkedHashSet::new));

        if (blockedIps.isEmpty()) {
            report.append("Aucune IP a bloquer.\n\n");
            return;
        }

        for (String ip : blockedIps) {
            report.append("- iptables -A INPUT -s ").append(ip).append(" -j DROP\n");
        }
        report.append('\n');
    }

    private void appendResidualRisks(StringBuilder report) {
        appendSectionHeader(report, "6) SURFACES D'ATTAQUE RESIDUELLES");
        report.append("- Les heuristiques peuvent etre contournees en restant juste sous les seuils.\n");
        report.append("- Les attaquants peuvent alterner IPs/proxies et ralentir le rythme pour eviter la detection.\n");
        report.append("- Des faux positifs restent possibles sur certains motifs ambigus dans URL/User-Agent.\n\n");
    }

    private void appendImprovements(StringBuilder report) {
        appendSectionHeader(report, "7) PROPOSITIONS D'AMELIORATION");
        report.append("- Rendre les seuils de detection configurables (fichier de config ou variables).\n");
        report.append("- Ajouter decode URL + normalisation avancee avant detection SQLi.\n");
        report.append("- Integrer des donnees de reputation IP/ASN et exporter vers SIEM.\n");
        report.append("- Ajouter des tests de non-regression sur jeux de logs attaques/legitimes.\n");
    }

    private void appendTitle(StringBuilder report, String title) {
        report.append(repeat('=', title.length())).append('\n');
        report.append(title).append('\n');
        report.append(repeat('=', title.length())).append('\n');
    }

    private void appendSectionHeader(StringBuilder report, String title) {
        report.append(title).append('\n');
        report.append(repeat('-', title.length())).append('\n');
    }

    private void appendKeyValue(StringBuilder report, String key, String value) {
        report.append(String.format("%-24s : %s%n", key, value));
    }

    private String repeat(char c, int count) {
        return String.valueOf(c).repeat(Math.max(0, count));
    }
}
