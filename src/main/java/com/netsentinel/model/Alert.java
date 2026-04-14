package com.netsentinel.model;

import java.time.LocalDateTime;

public class Alert {
	private final ThreatType threatType;
	private final Severity severity;
	private final String sourceIp;
	private final LocalDateTime detectedAt;
	private final String message;

	public Alert(ThreatType threatType, Severity severity, String sourceIp,
				 LocalDateTime detectedAt, String message) {
		this.threatType = threatType;
		this.severity = severity;
		this.sourceIp = sourceIp;
		this.detectedAt = detectedAt;
		this.message = message;
	}

	public ThreatType getThreatType() {
		return threatType;
	}

	public Severity getSeverity() {
		return severity;
	}

	public String getSourceIp() {
		return sourceIp;
	}

	public LocalDateTime getDetectedAt() {
		return detectedAt;
	}

	public String getMessage() {
		return message;
	}

	@Override
	public String toString() {
		String ipPart = sourceIp == null ? "global" : sourceIp;
		return String.format("[%s][%s][%s] %s (%s)",
			severity, threatType, ipPart, message, detectedAt);
	}
}
