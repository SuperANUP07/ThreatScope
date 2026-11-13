package com.threatscope.threatscope.repository;

import com.threatscope.threatscope.model.LogEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LogEventRepository extends JpaRepository<LogEvent, Long> {
    Page<LogEvent> findBySourceIp(String sourceIp, Pageable pageable);
}