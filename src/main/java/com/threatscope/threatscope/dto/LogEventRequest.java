package com.threatscope.threatscope.dto;

import com.threatscope.threatscope.model.EventType;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.time.LocalDateTime;

public record LogEventRequest(
        @NotNull LocalDateTime eventTime,
        String sourceIp,
        String username,
        @NotNull EventType eventType,
        String source,
        @Size(max = 1000) String message
) {}