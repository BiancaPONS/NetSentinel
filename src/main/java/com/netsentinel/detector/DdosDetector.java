package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;
import com.netsentinel.model.Severity;
import com.netsentinel.model.ThreatType;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DdosDetector implements ThreatDetector {

	private static final int WINDOW_SECONDS = 10;
	private static final double IP_SPIKE_MULTIPLIER = 10.0;
	private static final double DISTRIBUTED_SPIKE_MULTIPLIER = 50.0;

	@Override
	public String getName() {
		return "DdosDetector";
	}

	@Override
	public List<Alert> detect(List<LogEntry> logs) {
		if (logs.isEmpty()) {
			return List.of();
		}

		List<LogEntry> sortedLogs = logs.stream()
			.sorted(Comparator.comparing(LogEntry::getTimestamp))
			.toList();

		double averageRps = computeAverageRequestsPerSecond(sortedLogs);
		double ipThreshold = averageRps * IP_SPIKE_MULTIPLIER * WINDOW_SECONDS;
		double distributedThreshold = averageRps * DISTRIBUTED_SPIKE_MULTIPLIER * WINDOW_SECONDS;

		List<Alert> alerts = new ArrayList<>();
		alerts.addAll(detectIpSpikes(sortedLogs, ipThreshold));
		Alert distributed = detectDistributedSpike(sortedLogs, distributedThreshold);
		if (distributed != null) {
			alerts.add(distributed);
		}
		return alerts;
	}

	private List<Alert> detectIpSpikes(List<LogEntry> sortedLogs, double ipThreshold) {
		Map<String, Deque<LocalDateTime>> windowsByIp = new HashMap<>();
		Map<String, Integer> maxByIp = new HashMap<>();
		Map<String, LocalDateTime> detectionTimeByIp = new HashMap<>();

		for (LogEntry entry : sortedLogs) {
			Deque<LocalDateTime> window = windowsByIp.computeIfAbsent(entry.getIp(), key -> new ArrayDeque<>());
			window.addLast(entry.getTimestamp());

			LocalDateTime windowStart = entry.getTimestamp().minusSeconds(WINDOW_SECONDS);
			while (!window.isEmpty() && window.peekFirst().isBefore(windowStart)) {
				window.pollFirst();
			}

			int current = window.size();
			if (current > maxByIp.getOrDefault(entry.getIp(), 0)) {
				maxByIp.put(entry.getIp(), current);
				detectionTimeByIp.put(entry.getIp(), entry.getTimestamp());
			}
		}

		List<Alert> alerts = new ArrayList<>();
		for (Map.Entry<String, Integer> max : maxByIp.entrySet()) {
			if (max.getValue() <= ipThreshold) {
				continue;
			}
			String message = String.format(
				"Pic de trafic: %d requetes en %d secondes (seuil %.2f)",
				max.getValue(), WINDOW_SECONDS, ipThreshold
			);
			alerts.add(new Alert(
				ThreatType.DDOS,
				Severity.HIGH,
				max.getKey(),
				detectionTimeByIp.getOrDefault(max.getKey(), sortedLogs.get(sortedLogs.size() - 1).getTimestamp()),
				message
			));
		}
		return alerts;
	}

	private Alert detectDistributedSpike(List<LogEntry> sortedLogs, double distributedThreshold) {
		Deque<LocalDateTime> globalWindow = new ArrayDeque<>();
		int maxGlobal = 0;
		LocalDateTime detectedAt = sortedLogs.get(sortedLogs.size() - 1).getTimestamp();

		for (LogEntry entry : sortedLogs) {
			globalWindow.addLast(entry.getTimestamp());
			LocalDateTime windowStart = entry.getTimestamp().minusSeconds(WINDOW_SECONDS);
			while (!globalWindow.isEmpty() && globalWindow.peekFirst().isBefore(windowStart)) {
				globalWindow.pollFirst();
			}

			if (globalWindow.size() > maxGlobal) {
				maxGlobal = globalWindow.size();
				detectedAt = entry.getTimestamp();
			}
		}

		if (maxGlobal <= distributedThreshold) {
			return null;
		}

		String message = String.format(
			"Volume global anormal: %d requetes en %d secondes (seuil %.2f)",
			maxGlobal, WINDOW_SECONDS, distributedThreshold
		);
		return new Alert(ThreatType.DDOS, Severity.CRITICAL, null, detectedAt, message);
	}

	private double computeAverageRequestsPerSecond(List<LogEntry> sortedLogs) {
		LocalDateTime first = sortedLogs.get(0).getTimestamp();
		LocalDateTime last = sortedLogs.get(sortedLogs.size() - 1).getTimestamp();
		long seconds = Math.max(1, Duration.between(first, last).getSeconds());
		return (double) sortedLogs.size() / seconds;
	}
}
