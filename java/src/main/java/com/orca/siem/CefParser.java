package com.orca.siem;

/**
 * parse common event format (cef) log messages.
 * cef is used by enterprise security products (arcsight, splunk, qradar).
 */
public class CefParser implements LogParser {

    private static final String CEF_PREFIX = "CEF:";

    @Override
    public boolean canParse(String rawLog) {
        return rawLog != null && rawLog.contains(CEF_PREFIX);
    }

    @Override
    public LogEvent parse(String rawLog) {
        int cefStart = rawLog.indexOf(CEF_PREFIX);
        if (cefStart < 0) return null;

        String cefPart = rawLog.substring(cefStart + CEF_PREFIX.length());
        String[] headers = splitCefHeaders(cefPart);
        if (headers.length < 7) return null;

        LogEvent event = new LogEvent();
        event.setRawLog(rawLog);
        event.setField("cef_version", headers[0].trim());
        event.setField("device_vendor", headers[1].trim());
        event.setField("device_product", headers[2].trim());
        event.setField("device_version", headers[3].trim());
        event.setField("signature_id", headers[4].trim());
        event.setMessage(headers[5].trim());
        event.setSeverity(mapCefSeverity(headers[6].trim()));
        event.setSource(headers[1].trim() + "/" + headers[2].trim());

        if (headers.length > 7) {
            parseExtension(event, headers[7]);
        }
        return event;
    }

    private String[] splitCefHeaders(String cef) {
        String[] parts = new String[8];
        int idx = 0;
        int start = 0;
        boolean escaped = false;

        for (int i = 0; i < cef.length() && idx < 7; i++) {
            char c = cef.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (c == '\\') {
                escaped = true;
                continue;
            }
            if (c == '|') {
                parts[idx++] = cef.substring(start, i);
                start = i + 1;
            }
        }
        if (idx < 8) {
            parts[idx] = cef.substring(start);
        }
        return parts;
    }

    private void parseExtension(LogEvent event, String extension) {
        if (extension == null) return;
        String[] pairs = extension.trim().split("\\s+(?=\\w+=)");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0 && eq < pair.length() - 1) {
                String key = pair.substring(0, eq).trim();
                String value = pair.substring(eq + 1).trim();
                event.setField(key, value);
            }
        }
    }

    private int mapCefSeverity(String severity) {
        try {
            int level = Integer.parseInt(severity);
            if (level >= 9) return 5;
            if (level >= 7) return 4;
            if (level >= 4) return 3;
            if (level >= 1) return 2;
            return 1;
        } catch (NumberFormatException e) {
            return 1;
        }
    }
}
