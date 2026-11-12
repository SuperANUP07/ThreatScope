package com.threatscope.threatscope.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "log_events", indexes = {
        @Index(name = "idx_log_source_ip", columnList = "sourceIp"),
        @Index(name = "idx_log_event_time", columnList = "eventTime")
})
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class LogEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime eventTime;

    private String sourceIp;
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private EventType eventType;

    private String source;

    @Column(length = 1000)
    private String message;

    private LocalDateTime ingestedAt;
}