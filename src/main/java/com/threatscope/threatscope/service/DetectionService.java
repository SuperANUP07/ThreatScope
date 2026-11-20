package com.threatscope.threatscope.service;

import com.threatscope.threatscope.model.Alert;
import com.threatscope.threatscope.repository.AlertRepository;
import com.threatscope.threatscope.rule.DetectionRule;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.dao.DataIntegrityViolationException;

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
            try {
                for (Alert alert : rule.evaluate()) {
                    if (!alertRepository.existsByRuleNameAndSourceIpAndWindowStart(
                            alert.getRuleName(), alert.getSourceIp(), alert.getWindowStart())) {
                        try {
                            alertRepository.save(alert);
                            created++;
                            log.warn("ALERT [{}] {} - {}", alert.getSeverity(),
                                    alert.getRuleName(), alert.getDescription());
                        } catch (DataIntegrityViolationException e) {
                            log.debug("Alert already exists (concurrent run), skipping");
                        }
                    }
                }
            } catch (Exception e) {
                log.error("Rule {} failed", rule.name(), e);   // one bad rule won't stop the others
            }
        }
        log.info("Detection run finished, {} new alert(s)", created);
        return created;
    }
}