package com.orca.siem;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * high-throughput log ingestion engine for siem.
 * processes syslog, json, and cef format logs in parallel.
 */
public class LogIngester {

    private final BlockingQueue<LogEvent> eventQueue;
    private final ExecutorService workers;
    private final List<LogParser> parsers;
    private volatile boolean running;
    private long totalIngested;
    private long totalErrors;

    public LogIngester(int queueSize, int workerCount) {
        this.eventQueue = new LinkedBlockingQueue<>(queueSize);
        this.workers = Executors.newFixedThreadPool(workerCount);
        this.parsers = new ArrayList<>();
        this.running = false;
        this.totalIngested = 0;
        this.totalErrors = 0;
        registerDefaultParsers();
    }

    private void registerDefaultParsers() {
        parsers.add(new SyslogParser());
        parsers.add(new JsonLogParser());
        parsers.add(new CefParser());
    }

    public void start() {
        running = true;
        for (int i = 0; i < Runtime.getRuntime().availableProcessors(); i++) {
            workers.submit(this::processLoop);
        }
    }

    public void stop() {
        running = false;
        workers.shutdown();
        try {
            workers.awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    public void ingest(String rawLog) {
        for (LogParser parser : parsers) {
            if (parser.canParse(rawLog)) {
                LogEvent event = parser.parse(rawLog);
                if (event != null) {
                    try {
                        eventQueue.offer(event, 100, TimeUnit.MILLISECONDS);
                        totalIngested++;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    return;
                }
            }
        }
        totalErrors++;
    }

    public void ingestFile(Path logFile) throws IOException {
        try (BufferedReader reader = Files.newBufferedReader(logFile)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isBlank()) {
                    ingest(line);
                }
            }
        }
    }

    public void watchDirectory(Path dir) {
        workers.submit(() -> {
            try (WatchService watcher = FileSystems.getDefault().newWatchService()) {
                dir.register(watcher, StandardWatchEventKinds.ENTRY_MODIFY);
                while (running) {
                    WatchKey key = watcher.poll(1, TimeUnit.SECONDS);
                    if (key == null) continue;
                    for (WatchEvent<?> event : key.pollEvents()) {
                        Path changed = dir.resolve((Path) event.context());
                        ingestFile(changed);
                    }
                    key.reset();
                }
            } catch (IOException | InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });
    }

    private void processLoop() {
        while (running) {
            try {
                LogEvent event = eventQueue.poll(500, TimeUnit.MILLISECONDS);
                if (event != null) {
                    processEvent(event);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private void processEvent(LogEvent event) {
        event.setProcessedAt(Instant.now());
        int severity = classifySeverity(event);
        event.setSeverity(severity);
    }

    private int classifySeverity(LogEvent event) {
        String message = event.getMessage().toLowerCase();
        if (message.contains("critical") || message.contains("emergency")) return 5;
        if (message.contains("error") || message.contains("fail")) return 4;
        if (message.contains("warn")) return 3;
        if (message.contains("notice")) return 2;
        return 1;
    }

    public LogEvent poll() {
        return eventQueue.poll();
    }

    public Map<String, Object> stats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("ingested", totalIngested);
        stats.put("errors", totalErrors);
        stats.put("queue_size", eventQueue.size());
        stats.put("running", running);
        return stats;
    }

    public static void main(String[] args) {
        LogIngester ingester = new LogIngester(10000, 4);
        ingester.start();
        ingester.ingest("<34>Oct 11 22:14:15 server sshd[1234]: Failed password for root from 10.0.0.1");
        ingester.ingest("{\"level\":\"error\",\"msg\":\"connection refused\",\"ts\":\"2022-01-01T00:00:00Z\"}");
        System.out.println("stats: " + ingester.stats());
        ingester.stop();
    }
}
