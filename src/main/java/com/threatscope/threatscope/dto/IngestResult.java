package com.threatscope.threatscope.dto;

public record IngestResult(int totalLines, int parsed, int skipped) {}