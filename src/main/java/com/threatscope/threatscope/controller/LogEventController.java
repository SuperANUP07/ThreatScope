package com.threatscope.threatscope.controller;

import com.threatscope.threatscope.dto.*;
import com.threatscope.threatscope.service.LogEventService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.*;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
public class LogEventController {

    private final LogEventService service;

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public LogEventResponse create(@Valid @RequestBody LogEventRequest request) {
        return service.create(request);
    }

    @GetMapping
    public Page<LogEventResponse> list(
            @RequestParam(required = false) String sourceIp,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Pageable pageable = PageRequest.of(page, size, Sort.by("eventTime").descending());
        return service.list(sourceIp, pageable);
    }
}