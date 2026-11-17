package com.threatscope.threatscope.repository;

import com.threatscope.threatscope.model.Alert;
import org.springframework.data.jpa.repository.JpaRepository;
import java.time.LocalDateTime;

public interface AlertRepository extends JpaRepository<Alert, Long> {
    boolean existsByRuleNameAndSourceIpAndWindowStart(
            String ruleName, String sourceIp, LocalDateTime windowStart);
}