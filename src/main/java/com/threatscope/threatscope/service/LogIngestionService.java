package com.threatscope.threatscope.service;

import com.threatscope.threatscope.dto.IngestResult;
import com.threatscope.threatscope.model.LogEvent;
import com.threatscope.threatscope.parser.LogParser;
import com.threatscope.threatscope.repository.LogEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.time.Year;
import java.util.List;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class LogIngestionService {

    private final LogParser parser;
    private final LogEventRepository repository;

    public IngestResult ingest(MultipartFile file) throws IOException {
        int year = Year.now().getValue();

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {

            List<String> lines = reader.lines().toList();

            List<LogEvent> events = lines.stream()
                    .map(line -> parser.parse(line, year))
                    .flatMap(Optional::stream)
                    .toList();

            repository.saveAll(events);
            return new IngestResult(lines.size(), events.size(), lines.size() - events.size());
        }
    }
}