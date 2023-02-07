package com.orca.pipeline;

import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Predicate;

/**
 * high-throughput data streaming pipeline for security event processing.
 * supports filtering, transformation, and fan-out to multiple consumers.
 */
public class DataStream<T> {

    private final BlockingQueue<T> queue;
    private final List<Predicate<T>> filters;
    private final List<Consumer<T>> consumers;
    private final ExecutorService executor;
    private volatile boolean running;
    private final String name;

    public DataStream(String name, int capacity) {
        this.name = name;
        this.queue = new LinkedBlockingQueue<>(capacity);
        this.filters = new CopyOnWriteArrayList<>();
        this.consumers = new CopyOnWriteArrayList<>();
        this.executor = Executors.newSingleThreadExecutor();
        this.running = false;
    }

    public DataStream(String name) {
        this(name, 10000);
    }

    public void addFilter(Predicate<T> filter) {
        filters.add(filter);
    }

    public void addConsumer(Consumer<T> consumer) {
        consumers.add(consumer);
    }

    public boolean publish(T item) {
        if (!running) return false;
        return queue.offer(item);
    }

    public void start() {
        running = true;
        executor.submit(this::processLoop);
    }

    public void stop() {
        running = false;
        executor.shutdown();
        try {
            executor.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void processLoop() {
        while (running) {
            try {
                T item = queue.poll(100, TimeUnit.MILLISECONDS);
                if (item == null) continue;
                if (passesFilters(item)) {
                    for (Consumer<T> consumer : consumers) {
                        try {
                            consumer.accept(item);
                        } catch (Exception e) {
                            System.err.println("consumer error in " + name + ": " + e.getMessage());
                        }
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }

    private boolean passesFilters(T item) {
        for (Predicate<T> filter : filters) {
            if (!filter.test(item)) return false;
        }
        return true;
    }

    public int pending() {
        return queue.size();
    }

    public boolean isRunning() {
        return running;
    }

    public String getName() {
        return name;
    }

    public static void main(String[] args) {
        DataStream<String> stream = new DataStream<>("test-stream");
        stream.addFilter(s -> s.length() > 0);
        stream.addConsumer(s -> System.out.println("received: " + s));
        stream.start();
        stream.publish("hello from pipeline");
        try { Thread.sleep(200); } catch (InterruptedException e) { /* */ }
        stream.stop();
    }
}
