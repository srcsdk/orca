package com.orca.siem;

import java.time.Instant;
import java.util.*;

/**
 * represents a parsed log event for siem processing.
 */
public class LogEvent {

    private String source;
    private String message;
    private String rawLog;
    private Instant timestamp;
    private Instant processedAt;
    private int severity;
    private String facility;
    private Map<String, String> fields;

    public LogEvent() {
        this.fields = new HashMap<>();
        this.timestamp = Instant.now();
        this.severity = 1;
    }

    public LogEvent(String source, String message) {
        this();
        this.source = source;
        this.message = message;
    }

    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public String getRawLog() { return rawLog; }
    public void setRawLog(String rawLog) { this.rawLog = rawLog; }

    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }

    public Instant getProcessedAt() { return processedAt; }
    public void setProcessedAt(Instant processedAt) { this.processedAt = processedAt; }

    public int getSeverity() { return severity; }
    public void setSeverity(int severity) { this.severity = severity; }

    public String getFacility() { return facility; }
    public void setFacility(String facility) { this.facility = facility; }

    public Map<String, String> getFields() { return fields; }
    public void setField(String key, String value) { this.fields.put(key, value); }
    public String getField(String key) { return this.fields.get(key); }

    public String severityName() {
        switch (severity) {
            case 5: return "CRITICAL";
            case 4: return "ERROR";
            case 3: return "WARNING";
            case 2: return "NOTICE";
            case 1: return "INFO";
            default: return "DEBUG";
        }
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s - %s",
            severityName(), source, timestamp, message);
    }
}
