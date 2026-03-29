package com.codesentinel.service;

import com.codesentinel.model.PullRequestEvent;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

/**
 * In-memory event queue for PR processing.
 * Designed for easy swap to Kafka or RabbitMQ in production.
 */
@Service
@Slf4j
public class EventQueueService {

    @Value("${codesentinel.queue.capacity:100}")
    private int capacity;

    private LinkedBlockingQueue<PullRequestEvent> queue;

    @PostConstruct
    public void init() {
        this.queue = new LinkedBlockingQueue<>(capacity);
        log.info("Event queue initialized with capacity: {}", capacity);
    }

    /**
     * Enqueues a PR event for async processing.
     * Returns false if the queue is full.
     */
    public boolean enqueue(PullRequestEvent event) {
        boolean added = queue.offer(event);
        if (added) {
            log.debug("Enqueued event #{} (queue size: {})", event.getId(), queue.size());
        } else {
            log.warn("Queue full! Failed to enqueue event #{}", event.getId());
        }
        return added;
    }

    /**
     * Dequeues a PR event, blocking for up to the specified timeout.
     * Returns null if no event is available within the timeout.
     */
    public PullRequestEvent dequeue(long timeoutMs) {
        try {
            return queue.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.warn("Queue poll interrupted");
            return null;
        }
    }

    /**
     * Returns the current queue size.
     */
    public int size() {
        return queue.size();
    }

    /**
     * Returns true if the queue is empty.
     */
    public boolean isEmpty() {
        return queue.isEmpty();
    }
}
