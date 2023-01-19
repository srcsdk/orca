package com.orca.siem;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

/**
 * parse json-structured log messages.
 */
public class JsonLogParser implements LogParser {

    @Override
    public boolean canParse(String rawLog) {
        return rawLog != null && rawLog.trim().startsWith("{");
    }

    @Override
    public LogEvent parse(String rawLog) {
        try {
            JsonObject obj = JsonParser.parseString(rawLog).getAsJsonObject();
            LogEvent event = new LogEvent();
            event.setRawLog(rawLog);

            if (obj.has("msg")) {
                event.setMessage(obj.get("msg").getAsString());
            } else if (obj.has("message")) {
                event.setMessage(obj.get("message").getAsString());
            }

            if (obj.has("source")) {
                event.setSource(obj.get("source").getAsString());
            } else if (obj.has("host")) {
                event.setSource(obj.get("host").getAsString());
            }

            if (obj.has("level")) {
                event.setSeverity(mapLevel(obj.get("level").getAsString()));
            }

            for (String key : obj.keySet()) {
                JsonElement val = obj.get(key);
                if (val.isJsonPrimitive()) {
                    event.setField(key, val.getAsString());
                }
            }
            return event;
        } catch (JsonSyntaxException e) {
            return null;
        }
    }

    private int mapLevel(String level) {
        switch (level.toLowerCase()) {
            case "critical": case "fatal": case "emergency": return 5;
            case "error": case "err": return 4;
            case "warning": case "warn": return 3;
            case "notice": return 2;
            case "info": case "information": return 1;
            default: return 0;
        }
    }
}
