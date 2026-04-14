package com.netsentinel.service;

import com.netsentinel.model.LogEntry;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class LogIndexer {

	public Map<String, List<LogEntry>> indexByIp(List<LogEntry> logs) {
		Map<String, List<LogEntry>> logsByIp = new LinkedHashMap<>();
		for (LogEntry log : logs) {
			logsByIp.computeIfAbsent(log.getIp(), key -> new ArrayList<>()).add(log);
		}
		return logsByIp;
	}

	public TreeMap<LocalDateTime, List<LogEntry>> indexByTime(List<LogEntry> logs) {
		TreeMap<LocalDateTime, List<LogEntry>> logsByTime = new TreeMap<>();
		for (LogEntry log : logs) {
			logsByTime.computeIfAbsent(log.getTimestamp(), key -> new ArrayList<>()).add(log);
		}
		return logsByTime;
	}
}
