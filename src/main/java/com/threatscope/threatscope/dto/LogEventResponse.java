package com.threatscope.threatscope.dto;

import com.threatscope.threatscope.model.EventType;
import com.threatscope.threatscope.model.LogEvent;
import java.time.LocalDateTime;

public record LogEventResponse(
        Long id, LocalDateTime eventTime, String sourceIp, String username,
        EventType eventType, String source, String message, LocalDateTime ingestedAt
) {
    public static LogEventResponse from(LogEvent e) {
        return new LogEventResponse(e.getId(), e.getEventTime(), e.getSourceIp(),
                e.getUsername(), e.getEventType(), e.getSource(),
                e.getMessage(), e.getIngestedAt());
    }
}