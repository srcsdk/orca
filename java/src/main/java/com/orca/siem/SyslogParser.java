package com.orca.siem;

import java.time.Instant;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * parse rfc3164 syslog format messages.
 */
public class SyslogParser implements LogParser {

    private static final Pattern SYSLOG_PATTERN = Pattern.compile(
        "<(\\d+)>(\\w{3}\\s+\\d+\\s+[\\d:]+)\\s+(\\S+)\\s+(\\S+?)(?:\\[(\\d+)\\])?:\\s+(.*)"
    );

    @Override
    public boolean canParse(String rawLog) {
        return rawLog != null && rawLog.startsWith("<");
    }

    @Override
    public LogEvent parse(String rawLog) {
        Matcher m = SYSLOG_PATTERN.matcher(rawLog);
        if (!m.matches()) return null;

        int priority = Integer.parseInt(m.group(1));
        int facility = priority / 8;
        int severity = priority % 8;

        LogEvent event = new LogEvent();
        event.setRawLog(rawLog);
        event.setSource(m.group(3));
        event.setMessage(m.group(6));
        event.setFacility(facilityName(facility));
        event.setSeverity(mapSeverity(severity));
        event.setField("process", m.group(4));
        if (m.group(5) != null) {
            event.setField("pid", m.group(5));
        }
        event.setField("syslog_timestamp", m.group(2));
        return event;
    }

    private int mapSeverity(int syslogSeverity) {
        if (syslogSeverity <= 1) return 5;
        if (syslogSeverity <= 3) return 4;
        if (syslogSeverity == 4) return 3;
        if (syslogSeverity == 5) return 2;
        return 1;
    }

    private String facilityName(int facility) {
        String[] names = {
            "kern", "user", "mail", "daemon", "auth", "syslog",
            "lpr", "news", "uucp", "cron", "authpriv", "ftp",
            "ntp", "audit", "alert", "clock",
            "local0", "local1", "local2", "local3",
            "local4", "local5", "local6", "local7"
        };
        return facility < names.length ? names[facility] : "unknown";
    }
}
