package com.threatscope.threatscope.controller;

import com.threatscope.threatscope.model.Alert;
import com.threatscope.threatscope.repository.AlertRepository;
import com.threatscope.threatscope.service.DetectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class DetectionController {

    private final DetectionService detectionService;
    private final AlertRepository alertRepository;

    @PostMapping("/detection/run")
    public Map<String, Integer> run() {
        return Map.of("alertsCreated", detectionService.runAll());
    }

    @GetMapping("/alerts")
    public List<Alert> alerts() {
        return alertRepository.findAll(Sort.by("createdAt").descending());
    }
}