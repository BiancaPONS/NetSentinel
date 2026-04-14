package com.netsentinel.detector;

import com.netsentinel.model.Alert;
import com.netsentinel.model.LogEntry;

import java.util.List;

public interface ThreatDetector {
	String getName();

	List<Alert> detect(List<LogEntry> logs);
}
