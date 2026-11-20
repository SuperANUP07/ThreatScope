package com.threatscope.threatscope.model;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "alerts",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_alert_rule_ip_window",
                columnNames = {"ruleName", "sourceIp", "windowStart"}),
        indexes = {
                @Index(name = "idx_alert_ip", columnList = "sourceIp"),
                @Index(name = "idx_alert_created", columnList = "createdAt")
        })
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor @Builder
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String ruleName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    private String sourceIp;

    @Column(length = 500)
    private String description;

    private int eventCount;
    private LocalDateTime windowStart;
    private LocalDateTime windowEnd;
    private LocalDateTime createdAt;
}