package com.threatscope.threatscope.rule;

import com.threatscope.threatscope.model.*;
import com.threatscope.threatscope.repository.LogEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class BruteForceRule implements DetectionRule {

    private final LogEventRepository logRepository;

    @Value("${threatscope.detection.bruteforce.threshold:5}")
    private int threshold;

    @Value("${threatscope.detection.bruteforce.window-seconds:300}")
    private long windowSeconds;

    @Override
    public String name() { return "BRUTE_FORCE_LOGIN"; }

    @Override
    public List<Alert> evaluate() {
        List<LogEvent> failed = logRepository.findByEventTypeOrderByEventTimeAsc(EventType.LOGIN_FAILED);

        // Group failed logins by source IP (each list stays sorted by time)
        Map<String, List<LogEvent>> byIp = failed.stream()
                .filter(e -> e.getSourceIp() != null)
                .collect(Collectors.groupingBy(LogEvent::getSourceIp));

        List<Alert> alerts = new ArrayList<>();

        for (Map.Entry<String, List<LogEvent>> entry : byIp.entrySet()) {
            List<LogEvent> events = entry.getValue();

            // Sliding window with two pointers: find the busiest window for this IP
            int left = 0, best = 0, bestLeft = 0, bestRight = 0;
            for (int right = 0; right < events.size(); right++) {
                while (Duration.between(events.get(left).getEventTime(),
                        events.get(right).getEventTime()).getSeconds() > windowSeconds) {
                    left++;
                }
                int count = right - left + 1;
                if (count > best) {
                    best = count;
                    bestLeft = left;
                    bestRight = right;
                }
            }

            if (best >= threshold) {
                LocalDateTime start = events.get(bestLeft).getEventTime();
                LocalDateTime end = events.get(bestRight).getEventTime();
                alerts.add(Alert.builder()
                        .ruleName(name())
                        .severity(severityFor(best))
                        .sourceIp(entry.getKey())
                        .description(best + " failed logins from " + entry.getKey()
                                + " within " + windowSeconds + "s")
                        .eventCount(best)
                        .windowStart(start)
                        .windowEnd(end)
                        .createdAt(LocalDateTime.now())
                        .build());
            }
        }
        return alerts;
    }

    private Severity severityFor(int count) {
        if (count >= 20) return Severity.CRITICAL;
        if (count >= 10) return Severity.HIGH;
        return Severity.MEDIUM;
    }
    @Test
    void reportsTwoSeparateBurstsFromSameIp() {
        List<LogEvent> events = new java.util.ArrayList<>();
        LocalDateTime t = LocalDateTime.of(2026, 11, 11, 10, 0, 0);
        for (int i = 0; i < 6; i++) events.add(failureAt("3.3.3.3", t.plusSeconds(i * 2L)));
        // second burst one hour later
        for (int i = 0; i < 6; i++) events.add(failureAt("3.3.3.3", t.plusHours(1).plusSeconds(i * 2L)));

        List<Alert> alerts = ruleWith(events).evaluate();
        assertEquals(2, alerts.size());
    }

    private LogEvent failureAt(String ip, LocalDateTime time) {
        return LogEvent.builder().sourceIp(ip)
                .eventType(EventType.LOGIN_FAILED).eventTime(time).build();
    }
}