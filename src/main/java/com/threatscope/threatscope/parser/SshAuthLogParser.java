package com.threatscope.threatscope.parser;

import com.threatscope.threatscope.model.EventType;
import com.threatscope.threatscope.model.LogEvent;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class SshAuthLogParser implements LogParser {

    // Example: Nov 11 10:15:30 server sshd[1234]: <message>
    private static final Pattern SYSLOG = Pattern.compile(
            "^(\\w{3})\\s+(\\d{1,2})\\s+(\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+([\\w.-]+)(?:\\[\\d+])?:\\s+(.*)$");

    private static final Pattern FAILED = Pattern.compile(
            "Failed \\w+ for (?:invalid user )?(\\S+) from ([\\d.]+) port \\d+");
    private static final Pattern INVALID_USER = Pattern.compile(
            "Invalid user (\\S+) from ([\\d.]+)");
    private static final Pattern ACCEPTED = Pattern.compile(
            "Accepted \\w+ for (\\S+) from ([\\d.]+) port \\d+");

    private static final DateTimeFormatter TS =
            DateTimeFormatter.ofPattern("MMM d HH:mm:ss yyyy", Locale.ENGLISH);

    @Override
    public Optional<LogEvent> parse(String line, int year) {
        if (line == null || line.isBlank()) return Optional.empty();

        Matcher sys = SYSLOG.matcher(line.trim());
        if (!sys.matches()) return Optional.empty();

        String process = sys.group(5);
        String message = sys.group(6);
        if (!process.equals("sshd")) return Optional.empty();

        LocalDateTime time;
        try {
            // syslog lines have no year, so we supply it
            time = LocalDateTime.parse(
                    sys.group(1) + " " + sys.group(2) + " " + sys.group(3) + " " + year, TS);
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }

        EventType type;
        Matcher m;
        if ((m = FAILED.matcher(message)).find()) {
            type = EventType.LOGIN_FAILED;
        } else if ((m = INVALID_USER.matcher(message)).find()) {
            type = EventType.LOGIN_FAILED;
        } else if ((m = ACCEPTED.matcher(message)).find()) {
            type = EventType.LOGIN_SUCCESS;
        } else {
            return Optional.empty();
        }

        return Optional.of(LogEvent.builder()
                .eventTime(time)
                .sourceIp(m.group(2))
                .username(m.group(1))
                .eventType(type)
                .source(process)
                .message(line.length() > 1000 ? line.substring(0, 1000) : line)
                .ingestedAt(LocalDateTime.now())
                .build());
    }
}