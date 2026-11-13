package com.threatscope.threatscope.parser;

import com.threatscope.threatscope.model.LogEvent;
import java.util.Optional;

public interface LogParser {
    Optional<LogEvent> parse(String line, int year);
}