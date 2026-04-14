package com.netsentinel.service;

import com.netsentinel.model.LogEntry;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class StatisticsService {

	private static final int DASHBOARD_WIDTH = 72;
	private static final int BAR_WIDTH = 28;

	public long totalRequests(List<LogEntry> logs) {
		return logs.size();
	}

	public Map<String, Long> topIps(List<LogEntry> logs, int limit) {
		return topBy(logs, LogEntry::getIp, limit);
	}

	public Map<Integer, Long> statusCodeDistribution(List<LogEntry> logs) {
		return logs.stream()
			.collect(Collectors.groupingBy(LogEntry::getStatusCode, Collectors.counting()))
			.entrySet()
			.stream()
			.sorted(Map.Entry.comparingByKey())
			.collect(Collectors.toMap(
				Map.Entry::getKey,
				Map.Entry::getValue,
				(left, right) -> left,
				LinkedHashMap::new
			));
	}

	public Map<String, Long> topUrls(List<LogEntry> logs, int limit) {
		return topBy(logs, LogEntry::getUrl, limit);
	}

	public Map<String, Long> topUserAgents(List<LogEntry> logs, int limit) {
		return topBy(logs, LogEntry::getUserAgent, limit);
	}

	public void printDashboard(List<LogEntry> logs) {
		long totalRequests = totalRequests(logs);

		printLine('=');
		printCentered("NETSENTINEL - DASHBOARD LOGS");
		printLine('=');
		printSummaryCard(totalRequests, logs.size(), topIps(logs, 10).size());

		printRanking("Top 10 IP", topIps(logs, 10), totalRequests);
		printRanking("Distribution codes HTTP", statusCodeDistribution(logs), totalRequests);
		printRanking("Top 10 URLs", topUrls(logs, 10), totalRequests);
		printRanking("Top 5 User-Agents", topUserAgents(logs, 5), totalRequests);
		printLine('=');
	}

	private <T> Map<T, Long> topBy(List<LogEntry> logs, Function<LogEntry, T> keyExtractor, int limit) {
		return logs.stream()
			.collect(Collectors.groupingBy(keyExtractor, Collectors.counting()))
			.entrySet()
			.stream()
			.sorted(Map.Entry.<T, Long>comparingByValue(Comparator.reverseOrder()))
			.limit(limit)
			.collect(Collectors.toMap(
				Map.Entry::getKey,
				Map.Entry::getValue,
				(left, right) -> left,
				LinkedHashMap::new
			));
	}

	private void printRanking(String title, Map<?, Long> values, long total) {
		System.out.println();
		System.out.println("[ " + title + " ]");
		if (values.isEmpty()) {
			System.out.println("Aucune donnee.");
			return;
		}

		long maxValue = values.values().stream().mapToLong(Long::longValue).max().orElse(1L);
		int index = 1;
		for (Map.Entry<?, Long> entry : values.entrySet()) {
			String label = trimLabel(String.valueOf(entry.getKey()), 28);
			long value = entry.getValue();
			double percentage = total == 0 ? 0.0 : (value * 100.0) / total;
			String bar = buildBar(value, maxValue, BAR_WIDTH);
			System.out.printf("%2d. %-28s |%s| %6d (%5.1f%%)%n", index, label, bar, value, percentage);
			index++;
		}
	}

	private void printSummaryCard(long totalRequests, int logEntries, int uniqueTopIpCount) {
		System.out.printf("%-20s : %d%n", "Requetes totales", totalRequests);
		System.out.printf("%-20s : %d%n", "Lignes de log", logEntries);
		System.out.printf("%-20s : %d%n", "IPs top analysees", uniqueTopIpCount);
		printLine('-');
	}

	private void printCentered(String text) {
		if (text.length() >= DASHBOARD_WIDTH) {
			System.out.println(text);
			return;
		}
		int leftPadding = (DASHBOARD_WIDTH - text.length()) / 2;
		System.out.printf("%" + leftPadding + "s%s%n", "", text);
	}

	private void printLine(char character) {
		System.out.println(String.valueOf(character).repeat(DASHBOARD_WIDTH));
	}

	private String buildBar(long value, long maxValue, int width) {
		if (maxValue <= 0 || width <= 0) {
			return "";
		}
		int filled = (int) Math.round((value * 1.0 / maxValue) * width);
		filled = Math.max(0, Math.min(width, filled));
		return "#".repeat(filled) + "-".repeat(width - filled);
	}

	private String trimLabel(String label, int maxLength) {
		if (label.length() <= maxLength) {
			return label;
		}
		if (maxLength <= 3) {
			return label.substring(0, maxLength);
		}
		return label.substring(0, maxLength - 3) + "...";
	}
}
