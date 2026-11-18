# ThreatScope

Java-based SIEM and threat intelligence platform built with Spring Boot.

## Features
- [x] Security log event API (REST, validation, pagination)
- [x] SSH auth log upload and regex parsing
- [x] Rule-based detection engine (brute-force, sliding window)
- [ ] Port scan detection
- [ ] Alert management APIs
- [ ] IOC enrichment (VirusTotal / AbuseIPDB)
- [ ] JWT security with roles
- [ ] SOC dashboard

## Tech stack
Java 17, Spring Boot 3, Spring Data JPA, Spring Security, MySQL, Maven, JUnit 5, Mockito

## Run locally
1. Create the database and user (see below).
2. Set the environment variable `DB_PASSWORD`.
3. Run `./mvnw spring-boot:run`

## API
| Method | Endpoint | Description |
|---|---|---|
| POST | /api/logs | Create a log event |
| GET | /api/logs?sourceIp= | List events (paginated) |
| POST | /api/logs/upload | Upload an auth.log file |
| GET | /api/alerts | List alerts |
| POST | /api/detection/run | Run detection now |

## Architecture
Controller > Service > Repository, with a `DetectionRule` interface so new rules plug in without changing existing code.
