package com.netsentinel.service;

import com.netsentinel.model.LogEntry;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class StatisticsService {

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
		System.out.println("==== Dashboard Logs ====");
		System.out.printf("Nombre total de requetes: %d%n", totalRequests(logs));

		printRanking("Top 10 IP", topIps(logs, 10));
		printRanking("Distribution codes HTTP", statusCodeDistribution(logs));
		printRanking("Top 10 URLs", topUrls(logs, 10));
		printRanking("Top 5 User-Agents", topUserAgents(logs, 5));
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

	private void printRanking(String title, Map<?, Long> values) {
		System.out.println();
		System.out.println(title + ":");
		values.forEach((key, value) -> System.out.printf("- %s -> %d%n", key, value));
	}
}
