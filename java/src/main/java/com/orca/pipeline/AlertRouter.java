package com.orca.pipeline;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * routes security alerts to appropriate handlers based on severity and type.
 * supports priority queuing and deduplication.
 */
public class AlertRouter {

    private final Map<String, List<Consumer<Alert>>> handlers;
    private final Set<String> seen;
    private final int dedup_window;
    private long total_routed;

    public AlertRouter() {
        this(1000);
    }

    public AlertRouter(int dedup_window) {
        this.handlers = new ConcurrentHashMap<>();
        this.seen = Collections.newSetFromMap(new ConcurrentHashMap<>());
        this.dedup_window = dedup_window;
        this.total_routed = 0;
    }

    public void register(String alertType, Consumer<Alert> handler) {
        handlers.computeIfAbsent(alertType, k -> new ArrayList<>()).add(handler);
    }

    public boolean route(Alert alert) {
        String key = alert.fingerprint();
        if (seen.contains(key)) return false;

        seen.add(key);
        if (seen.size() > dedup_window) {
            seen.clear();
        }

        List<Consumer<Alert>> typeHandlers = handlers.get(alert.getType());
        if (typeHandlers != null) {
            for (Consumer<Alert> handler : typeHandlers) {
                handler.accept(alert);
            }
        }

        List<Consumer<Alert>> globalHandlers = handlers.get("*");
        if (globalHandlers != null) {
            for (Consumer<Alert> handler : globalHandlers) {
                handler.accept(alert);
            }
        }

        total_routed++;
        return true;
    }

    public long getTotalRouted() {
        return total_routed;
    }

    public Set<String> registeredTypes() {
        return handlers.keySet();
    }

    public static class Alert {
        private final String type;
        private final int severity;
        private final String source;
        private final String message;
        private final long timestamp;

        public Alert(String type, int severity, String source, String message) {
            this.type = type;
            this.severity = severity;
            this.source = source;
            this.message = message;
            this.timestamp = System.currentTimeMillis();
        }

        public String getType() { return type; }
        public int getSeverity() { return severity; }
        public String getSource() { return source; }
        public String getMessage() { return message; }
        public long getTimestamp() { return timestamp; }

        public String fingerprint() {
            return type + ":" + source + ":" + message.hashCode();
        }

        @Override
        public String toString() {
            return String.format("[%s] sev=%d src=%s msg=%s", type, severity, source, message);
        }
    }

    public static void main(String[] args) {
        AlertRouter router = new AlertRouter();
        router.register("intrusion", a -> System.out.println("intrusion handler: " + a));
        router.register("*", a -> System.out.println("global handler: " + a));

        Alert alert = new Alert("intrusion", 5, "firewall", "blocked port scan");
        router.route(alert);
        System.out.println("total routed: " + router.getTotalRouted());
    }
}
