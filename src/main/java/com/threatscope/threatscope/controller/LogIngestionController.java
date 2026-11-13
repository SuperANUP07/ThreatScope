package com.threatscope.threatscope.controller;

import com.threatscope.threatscope.dto.IngestResult;
import com.threatscope.threatscope.service.LogIngestionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
public class LogIngestionController {

    private final LogIngestionService ingestionService;

    @PostMapping("/upload")
    public ResponseEntity<?> upload(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("File is empty");
        }
        return ResponseEntity.ok(ingestionService.ingest(file));
    }
}