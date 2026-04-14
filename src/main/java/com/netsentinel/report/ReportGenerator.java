package com.netsentinel.report;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.service.StatisticsService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;

public class ReportGenerator {

	private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

	public void generateSimpleReport(
		String analyzedFile,
		List<LogEntry> logs,
		List<Alert> alerts,
		StatisticsService statisticsService,
		String outputFilePath
	) throws IOException {
		long totalRequests = statisticsService.totalRequests(logs);
		Map<String, Long> topIps = statisticsService.topIps(logs, 10);
		Map<Integer, Long> statusCodes = statisticsService.statusCodeDistribution(logs);
		Map<String, Long> topUrls = statisticsService.topUrls(logs, 10);

		long criticalAlerts = alerts.stream().filter(alert -> alert.getSeverity() == Severity.CRITICAL).count();
		long highAlerts = alerts.stream().filter(alert -> alert.getSeverity() == Severity.HIGH).count();

		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html>\n");
		html.append("<html lang=\"fr\">\n<head>\n<meta charset=\"UTF-8\">\n");
		html.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
		html.append("<title>NetSentinel - Rapport</title>\n");
		html.append("<style>");
		html.append("body{font-family:Segoe UI,Tahoma,sans-serif;margin:0;background:#f4f6f8;color:#222;}");
		html.append(".container{max-width:980px;margin:0 auto;padding:20px;}");
		html.append("h1{margin:0 0 8px 0;}h2{margin:24px 0 10px 0;font-size:1.1rem;}");
		html.append(".subtitle{color:#666;margin-bottom:18px;}");
		html.append(".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;}");
		html.append(".card{background:#fff;border:1px solid #e4e8ee;border-radius:8px;padding:12px;}");
		html.append(".card .label{font-size:.8rem;color:#666;}.card .value{font-size:1.4rem;font-weight:700;margin-top:6px;}");
		html.append("table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e8ee;border-radius:8px;overflow:hidden;}");
		html.append("th,td{text-align:left;padding:10px;border-bottom:1px solid #edf1f5;vertical-align:top;}");
		html.append("th{background:#f8fafc;font-weight:600;}tr:last-child td{border-bottom:none;}");
		html.append(".tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.75rem;font-weight:600;}");
		html.append(".critical{background:#fee2e2;color:#991b1b;}.high{background:#fff3cd;color:#8a6d3b;}.medium{background:#e8f1ff;color:#1e40af;}.low{background:#e9f7ef;color:#166534;}");
		html.append(".empty{background:#fff;border:1px dashed #cdd6e2;border-radius:8px;padding:12px;color:#666;}");
		html.append("</style>\n</head>\n<body>\n<div class=\"container\">\n");

		html.append("<h1>Rapport NetSentinel</h1>\n");
		html.append("<div class=\"subtitle\">Genere le ")
			.append(escapeHtml(LocalDateTime.now().format(DATE_FORMATTER)))
			.append(" | Fichier analyse: ")
			.append(escapeHtml(analyzedFile))
			.append("</div>\n");

		html.append("<div class=\"cards\">\n");
		html.append(metricCard("Requetes", String.valueOf(totalRequests)));
		html.append(metricCard("IPs uniques", String.valueOf(logs.stream().map(LogEntry::getIp).distinct().count())));
		html.append(metricCard("Alertes", String.valueOf(alerts.size())));
		html.append(metricCard("Critiques", String.valueOf(criticalAlerts)));
		html.append(metricCard("Hautes", String.valueOf(highAlerts)));
		html.append("</div>\n");

		html.append("<h2>Top IP</h2>\n");
		html.append(buildCountTable(topIps, "IP", "Requetes"));

		html.append("<h2>Codes HTTP</h2>\n");
		html.append(buildCountTable(statusCodes, "Code", "Occurrences"));

		html.append("<h2>Top URLs</h2>\n");
		html.append(buildCountTable(topUrls, "URL", "Requetes"));

		html.append("<h2>Alertes de securite</h2>\n");
		html.append(buildAlertsTable(alerts));

		html.append("</div>\n</body>\n</html>\n");

		Path outputPath = Path.of(outputFilePath);
		Path parent = outputPath.getParent();
		if (parent != null) {
			Files.createDirectories(parent);
		}
		Files.writeString(outputPath, html.toString(), StandardCharsets.UTF_8);
	}

	private String metricCard(String label, String value) {
		return "<div class=\"card\"><div class=\"label\">" + escapeHtml(label) + "</div><div class=\"value\">"
			+ escapeHtml(value) + "</div></div>\n";
	}

	private String buildCountTable(Map<?, Long> map, String col1, String col2) {
		if (map.isEmpty()) {
			return "<div class=\"empty\">Aucune donnee</div>\n";
		}

		StringBuilder table = new StringBuilder();
		table.append("<table><thead><tr><th>")
			.append(escapeHtml(col1))
			.append("</th><th>")
			.append(escapeHtml(col2))
			.append("</th></tr></thead><tbody>");

		for (Map.Entry<?, Long> entry : map.entrySet()) {
			table.append("<tr><td>")
				.append(escapeHtml(String.valueOf(entry.getKey())))
				.append("</td><td>")
				.append(entry.getValue())
				.append("</td></tr>");
		}

		table.append("</tbody></table>\n");
		return table.toString();
	}

	private String buildAlertsTable(List<Alert> alerts) {
		if (alerts.isEmpty()) {
			return "<div class=\"empty\">Aucune alerte detectee</div>\n";
		}

		StringBuilder table = new StringBuilder();
		table.append("<table><thead><tr><th>Date</th><th>Gravite</th><th>Type</th><th>IP</th><th>Message</th></tr></thead><tbody>");

		alerts.stream()
			.sorted((left, right) -> left.getDetectedAt().compareTo(right.getDetectedAt()))
			.forEach(alert -> {
				String css = severityClass(alert.getSeverity());
				table.append("<tr><td>")
					.append(escapeHtml(alert.getDetectedAt().format(DATE_FORMATTER)))
					.append("</td><td><span class=\"tag ")
					.append(css)
					.append("\">")
					.append(escapeHtml(alert.getSeverity().name()))
					.append("</span></td><td>")
					.append(escapeHtml(alert.getThreatType().name()))
					.append("</td><td>")
					.append(escapeHtml(alert.getSourceIp() == null ? "global" : alert.getSourceIp()))
					.append("</td><td>")
					.append(escapeHtml(alert.getMessage()))
					.append("</td></tr>");
			});

		table.append("</tbody></table>\n");
		return table.toString();
	}

	private String severityClass(Severity severity) {
		return switch (severity) {
			case CRITICAL -> "critical";
			case HIGH -> "high";
			case MEDIUM -> "medium";
			case LOW -> "low";
		};
	}

	private String escapeHtml(String text) {
		if (text == null) {
			return "";
		}
		return text
			.replace("&", "&amp;")
			.replace("<", "&lt;")
			.replace(">", "&gt;")
			.replace("\"", "&quot;")
			.replace("'", "&#39;");
	}
}
