package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.model.ThreatType;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ScanDetector implements ThreatDetector {

	private static final Set<String> SENSITIVE_PATHS = Set.of(
		"/admin",
		"/administrator",
		"/admin/login",
		"/wp-login.php",
		"/wp-admin",
		"/.env",
		"/phpmyadmin",
		"/phpinfo.php",
		"/config.yml",
		"/.git/config",
		"/.git/HEAD",
		"/backup.sql"
	);

	private static final List<String> SCANNER_SIGNATURES = List.of(
		"sqlmap",
		"nikto",
		"nmap",
		"dirbuster",
		"gobuster"
	);

	@Override
	public String getName() {
		return "ScanDetector";
	}

	@Override
	public List<Alert> detect(List<LogEntry> logs) {
		Map<String, Set<String>> reasonsByIp = new HashMap<>();
		Map<String, Set<String>> distinct404UrlsByIp = new HashMap<>();
		Map<String, java.time.LocalDateTime> lastSeenByIp = new HashMap<>();

		for (LogEntry entry : logs) {
			String ip = entry.getIp();
			String path = normalizePath(entry.getUrl());
			String ua = entry.getUserAgent() == null ? "" : entry.getUserAgent().toLowerCase();
			lastSeenByIp.put(ip, entry.getTimestamp());

			if (SENSITIVE_PATHS.contains(path)) {
				reasonsByIp.computeIfAbsent(ip, k -> new LinkedHashSet<>())
					.add("Acces a un chemin sensible: " + path);
			}

			for (String signature : SCANNER_SIGNATURES) {
				if (ua.contains(signature)) {
					reasonsByIp.computeIfAbsent(ip, k -> new LinkedHashSet<>())
						.add("User-Agent de scanner detecte: " + signature);
					break;
				}
			}

			if (entry.getStatusCode() == 404) {
				distinct404UrlsByIp.computeIfAbsent(ip, k -> new HashSet<>()).add(path);
			}
		}

		for (Map.Entry<String, Set<String>> entry : distinct404UrlsByIp.entrySet()) {
			if (entry.getValue().size() > 20) {
				reasonsByIp.computeIfAbsent(entry.getKey(), k -> new LinkedHashSet<>())
					.add("Scan de repertoires: plus de 20 URLs 404 differentes");
			}
		}

		List<Alert> alerts = new ArrayList<>();
		for (Map.Entry<String, Set<String>> candidate : reasonsByIp.entrySet()) {
			String ip = candidate.getKey();
			Set<String> reasons = candidate.getValue();
			boolean hasDirectoryScan = reasons.stream().anyMatch(reason -> reason.contains("404"));
			Severity severity = hasDirectoryScan ? Severity.HIGH : Severity.MEDIUM;

			String message = String.join(" | ", reasons);
			alerts.add(new Alert(
				ThreatType.SCAN,
				severity,
				ip,
				lastSeenByIp.getOrDefault(ip, java.time.LocalDateTime.now()),
				message
			));
		}
		return alerts;
	}

	private String normalizePath(String url) {
		if (url == null || url.isBlank()) {
			return "/";
		}
		String path = url.toLowerCase();
		int queryIndex = path.indexOf('?');
		if (queryIndex >= 0) {
			path = path.substring(0, queryIndex);
		}
		int fragmentIndex = path.indexOf('#');
		if (fragmentIndex >= 0) {
			path = path.substring(0, fragmentIndex);
		}
		return path.isBlank() ? "/" : path;
	}
}
