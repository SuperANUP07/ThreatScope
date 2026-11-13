package com.threatscope.threatscope.service;

import com.threatscope.threatscope.dto.*;
import com.threatscope.threatscope.model.LogEvent;
import com.threatscope.threatscope.repository.LogEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class LogEventService {

    private final LogEventRepository repository;

    public LogEventResponse create(LogEventRequest req) {
        LogEvent event = LogEvent.builder()
                .eventTime(req.eventTime())
                .sourceIp(req.sourceIp())
                .username(req.username())
                .eventType(req.eventType())
                .source(req.source())
                .message(req.message())
                .ingestedAt(LocalDateTime.now())
                .build();
        return LogEventResponse.from(repository.save(event));
    }

    public Page<LogEventResponse> list(String sourceIp, Pageable pageable) {
        Page<LogEvent> page = (sourceIp == null || sourceIp.isBlank())
                ? repository.findAll(pageable)
                : repository.findBySourceIp(sourceIp, pageable);
        return page.map(LogEventResponse::from);
    }
}