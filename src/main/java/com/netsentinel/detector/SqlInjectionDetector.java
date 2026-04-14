package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.model.ThreatType;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class SqlInjectionDetector implements ThreatDetector {

	private static final List<Pattern> SQLI_PATTERNS = List.of(
		Pattern.compile("(?i)(?:\\%27|'|\\%22|\")\\s*(?:or|and)\\s*(?:\\d+|''|[a-z_][a-z0-9_]*)\\s*=\\s*(?:\\d+|''|[a-z_][a-z0-9_]*)"),
		Pattern.compile("(?i)union(?:\\s|\\+|%20)+select"),
		Pattern.compile("(?i)(?:--|#|/\\*)"),
		Pattern.compile("(?i)(?:information_schema|xp_cmdshell|sleep\\s*\\()"),
		Pattern.compile("(?i)(?:drop\\s+table|insert\\s+into|delete\\s+from|update\\s+\\S+\\s+set|truncate\\s+table)")
	);

	@Override
	public String getName() {
		return "SqlInjectionDetector";
	}

	@Override
	public List<Alert> detect(List<LogEntry> logs) {
		List<Alert> alerts = new ArrayList<>();
		for (LogEntry entry : logs) {
			if (!containsSuspiciousSqlPattern(entry.getUrl())) {
				continue;
			}

			String message = String.format("Pattern SQL suspect detecte dans l'URL: %s", entry.getUrl());
			alerts.add(new Alert(
				ThreatType.SQL_INJECTION,
				Severity.HIGH,
				entry.getIp(),
				entry.getTimestamp(),
				message
			));
		}
		return alerts;
	}

	private boolean containsSuspiciousSqlPattern(String url) {
		String normalized = url == null ? "" : url.toLowerCase();
		for (Pattern pattern : SQLI_PATTERNS) {
			if (pattern.matcher(normalized).find()) {
				return true;
			}
		}
		return false;
	}
}
