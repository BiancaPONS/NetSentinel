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
		html.append(":root{--bg:#f2f5f8;--text:#18212b;--muted:#627181;--card:#ffffff;--line:#dce5ee;--accent:#0f766e;--accent-soft:#dff7f3;--alert:#9a3412;}");
		html.append("*{box-sizing:border-box;}body{font-family:\"Trebuchet MS\",\"Segoe UI\",sans-serif;margin:0;color:var(--text);");
		html.append("background:radial-gradient(circle at 15% -10%,#d8f6e8 0%,transparent 28%),radial-gradient(circle at 90% 0%,#dbeafe 0%,transparent 26%),var(--bg);}");
		html.append(".container{max-width:1060px;margin:0 auto;padding:24px 16px 40px;}");
		html.append(".hero{background:linear-gradient(120deg,#0b3b56,#0f766e);color:#fff;border-radius:14px;padding:18px 20px;box-shadow:0 12px 28px rgba(11,59,86,.22);}");
		html.append("h1{margin:0;font-size:1.6rem;letter-spacing:.4px;}h2{margin:26px 0 10px;font-size:1.05rem;}");
		html.append(".subtitle{opacity:.9;font-size:.92rem;margin-top:6px;}");
		html.append(".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:14px;}");
		html.append(".card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;box-shadow:0 2px 8px rgba(16,24,40,.05);}");
		html.append(".card .label{font-size:.76rem;letter-spacing:.3px;text-transform:uppercase;color:var(--muted);} .card .value{font-size:1.55rem;font-weight:800;margin-top:6px;}");
		html.append(".split{display:grid;grid-template-columns:1fr 1fr;gap:14px;}@media(max-width:860px){.split{grid-template-columns:1fr;}}");
		html.append(".panel{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px;}");
		html.append("table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px;overflow:hidden;}");
		html.append("th,td{text-align:left;padding:10px;border-bottom:1px solid #eaf0f6;vertical-align:top;font-size:.92rem;}th{background:#f8fbfe;font-weight:700;}tr:last-child td{border-bottom:none;}");
		html.append(".bar-row{display:grid;grid-template-columns:minmax(120px,1fr) 1.4fr auto;gap:10px;align-items:center;margin:8px 0;}");
		html.append(".bar-key{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:.9rem;color:#243647;}");
		html.append(".bar-wrap{height:10px;background:#e9f1f7;border-radius:999px;overflow:hidden;}");
		html.append(".bar-fill{height:100%;background:linear-gradient(90deg,var(--accent),#14b8a6);}");
		html.append(".bar-val{font-size:.83rem;color:var(--muted);font-weight:700;}");
		html.append(".tag{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.74rem;font-weight:700;}");
		html.append(".critical{background:#fee2e2;color:#991b1b;}.high{background:#ffedd5;color:var(--alert);}.medium{background:#e0ecff;color:#1d4ed8;}.low{background:#e8f7ef;color:#166534;}");
		html.append(".empty{background:#fff;border:1px dashed #c6d3e2;border-radius:12px;padding:14px;color:#516171;}");
		html.append("</style>\n</head>\n<body>\n<div class=\"container\">\n");

		html.append("<section class=\"hero\">\n<h1>Rapport NetSentinel</h1>\n");
		html.append("<div class=\"subtitle\">Genere le ")
			.append(escapeHtml(LocalDateTime.now().format(DATE_FORMATTER)))
			.append(" | Fichier analyse: ")
			.append(escapeHtml(analyzedFile))
			.append("</div>\n</section>\n");

		html.append("<div class=\"cards\">\n");
		html.append(metricCard("Requetes", String.valueOf(totalRequests)));
		html.append(metricCard("IPs uniques", String.valueOf(logs.stream().map(LogEntry::getIp).distinct().count())));
		html.append(metricCard("Alertes", String.valueOf(alerts.size())));
		html.append(metricCard("Critiques", String.valueOf(criticalAlerts)));
		html.append(metricCard("Hautes", String.valueOf(highAlerts)));
		html.append("</div>\n");

		html.append("<h2>Graphes rapides</h2>\n");
		html.append("<div class=\"split\">\n");
		html.append("<div class=\"panel\"><strong>Top IP</strong>");
		html.append(buildBarChart(topIps));
		html.append("</div>");
		html.append("<div class=\"panel\"><strong>Codes HTTP</strong>");
		html.append(buildBarChart(statusCodes));
		html.append("</div>");
		html.append("</div>\n");

		html.append("<h2>Top IP (tableau)</h2>\n");
		html.append(buildCountTable(topIps, "IP", "Requetes"));

		html.append("<h2>Codes HTTP (tableau)</h2>\n");
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

	private String buildBarChart(Map<?, Long> map) {
		if (map.isEmpty()) {
			return "<div class=\"empty\">Aucune donnee</div>\n";
		}

		long max = map.values().stream().mapToLong(Long::longValue).max().orElse(1L);
		StringBuilder bars = new StringBuilder();
		bars.append("<div>");
		for (Map.Entry<?, Long> entry : map.entrySet()) {
			double pct = max == 0 ? 0.0 : (entry.getValue() * 100.0 / max);
			bars.append("<div class=\"bar-row\"><div class=\"bar-key\">")
				.append(escapeHtml(String.valueOf(entry.getKey())))
				.append("</div><div class=\"bar-wrap\"><div class=\"bar-fill\" style=\"width:")
				.append(String.format("%.1f", pct))
				.append("%\"></div></div><div class=\"bar-val\">")
				.append(entry.getValue())
				.append("</div></div>");
		}
		bars.append("</div>");
		return bars.toString();
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
