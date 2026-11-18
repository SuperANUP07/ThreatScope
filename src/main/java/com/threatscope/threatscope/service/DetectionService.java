package com.threatscope.threatscope.service;

import com.threatscope.threatscope.model.Alert;
import com.threatscope.threatscope.repository.AlertRepository;
import com.threatscope.threatscope.rule.DetectionRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class DetectionService {

    private final List<DetectionRule> rules;   // Spring injects every DetectionRule bean
    private final AlertRepository alertRepository;

    @Scheduled(fixedDelayString = "${threatscope.detection.interval-ms:60000}")
    public int runAll() {
        int created = 0;
        for (DetectionRule rule : rules) {
            for (Alert alert : rule.evaluate()) {
                // Skip if this exact alert already exists, so reruns don't create duplicates
                if (!alertRepository.existsByRuleNameAndSourceIpAndWindowStart(
                        alert.getRuleName(), alert.getSourceIp(), alert.getWindowStart())) {
                    alertRepository.save(alert);
                    created++;
                    log.warn("ALERT [{}] {} - {}", alert.getSeverity(), alert.getRuleName(), alert.getDescription());
                }
            }
        }
        log.info("Detection run finished, {} new alert(s)", created);
        return created;
    }
}