package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.model.ThreatType;

import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceDetector implements ThreatDetector {

	private static final int WINDOW_MINUTES = 5;
	private static final int MEDIUM_THRESHOLD = 10;
	private static final int HIGH_THRESHOLD = 50;

	@Override
	public String getName() {
		return "BruteForceDetector";
	}

	@Override
	public List<Alert> detect(List<LogEntry> logs) {
		List<LogEntry> sortedLogs = logs.stream()
			.sorted(Comparator.comparing(LogEntry::getTimestamp))
			.toList();

		Map<String, Deque<LocalDateTime>> failedAttemptsByIp = new HashMap<>();
		Map<String, Integer> maxAttemptsInWindowByIp = new HashMap<>();
		Map<String, LocalDateTime> detectionTimeByIp = new HashMap<>();

		for (LogEntry entry : sortedLogs) {
			if (!isAuthFailure(entry)) {
				continue;
			}

			Deque<LocalDateTime> window = failedAttemptsByIp.computeIfAbsent(entry.getIp(), key -> new ArrayDeque<>());
			window.addLast(entry.getTimestamp());

			LocalDateTime windowStart = entry.getTimestamp().minusMinutes(WINDOW_MINUTES);
			while (!window.isEmpty() && window.peekFirst().isBefore(windowStart)) {
				window.pollFirst();
			}

			int current = window.size();
			int previous = maxAttemptsInWindowByIp.getOrDefault(entry.getIp(), 0);
			if (current > previous) {
				maxAttemptsInWindowByIp.put(entry.getIp(), current);
				detectionTimeByIp.put(entry.getIp(), entry.getTimestamp());
			}
		}

		List<Alert> alerts = new ArrayList<>();
		for (Map.Entry<String, Integer> candidate : maxAttemptsInWindowByIp.entrySet()) {
			int attempts = candidate.getValue();
			if (attempts <= MEDIUM_THRESHOLD) {
				continue;
			}

			Severity severity = attempts > HIGH_THRESHOLD ? Severity.HIGH : Severity.MEDIUM;
			String ip = candidate.getKey();
			LocalDateTime detectedAt = detectionTimeByIp.getOrDefault(ip, LocalDateTime.now());
			String message = String.format(
				"Tentatives de connexion suspectes: %d reponses 401/403 en %d minutes",
				attempts,
				WINDOW_MINUTES
			);

			alerts.add(new Alert(ThreatType.BRUTE_FORCE, severity, ip, detectedAt, message));
		}
		return alerts;
	}

	private boolean isAuthFailure(LogEntry entry) {
		return entry.getStatusCode() == 401 || entry.getStatusCode() == 403;
	}
}
