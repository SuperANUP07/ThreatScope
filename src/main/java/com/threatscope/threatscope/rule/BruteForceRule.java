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
    public String name() {
        return "BRUTE_FORCE_LOGIN";
    }

    @Override
    public List<Alert> evaluate() {
        List<LogEvent> failed = logRepository.findByEventTypeOrderByEventTimeAsc(EventType.LOGIN_FAILED);

        Map<String, List<LogEvent>> byIp = failed.stream()
                .filter(e -> e.getSourceIp() != null)
                .collect(Collectors.groupingBy(LogEvent::getSourceIp));

        List<Alert> alerts = new ArrayList<>();

        for (Map.Entry<String, List<LogEvent>> entry : byIp.entrySet()) {
            List<LogEvent> events = entry.getValue();
            int left = 0, right = 0;

            while (right < events.size()) {
                // shrink the window until it fits inside windowSeconds
                while (seconds(events.get(left), events.get(right)) > windowSeconds) left++;

                if (right - left + 1 >= threshold) {
                    // extend to include every event still inside this burst
                    int end = right;
                    while (end + 1 < events.size()
                            && seconds(events.get(left), events.get(end + 1)) <= windowSeconds) end++;

                    int count = end - left + 1;
                    alerts.add(Alert.builder()
                            .ruleName(name())
                            .severity(severityFor(count))
                            .sourceIp(entry.getKey())
                            .description(count + " failed logins from " + entry.getKey()
                                    + " within " + windowSeconds + "s")
                            .eventCount(count)
                            .windowStart(events.get(left).getEventTime())
                            .windowEnd(events.get(end).getEventTime())
                            .createdAt(LocalDateTime.now())
                            .build());

                    left = end + 1;    // start fresh after this burst
                    right = end + 1;
                } else {
                    right++;
                }
            }
        }
        return alerts;
    }

    private long seconds(LogEvent a, LogEvent b) {
        return Duration.between(a.getEventTime(), b.getEventTime()).getSeconds();
    }
}

