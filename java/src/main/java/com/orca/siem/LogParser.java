package com.orca.siem;

/**
 * interface for log format parsers.
 */
public interface LogParser {
    boolean canParse(String rawLog);
    LogEvent parse(String rawLog);
}
