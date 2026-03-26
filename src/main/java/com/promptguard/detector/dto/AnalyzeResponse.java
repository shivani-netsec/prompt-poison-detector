package com.promptguard.detector.dto;

import com.promptguard.detector.model.RiskLevel;
import com.promptguard.detector.model.ThreatCategory;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Response returned by POST /analyzePrompt.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Schema(description = "Prompt poisoning analysis result")
public class AnalyzeResponse {

    @Schema(description = "Composite risk score from 0 (safe) to 100 (extremely dangerous)", example = "87")
    private int riskScore;

    @Schema(description = "Overall risk level: LOW (0-33), MEDIUM (34-66), HIGH (67-100)", example = "HIGH")
    private RiskLevel riskLevel;

    @Schema(description = "List of detected threat categories")
    private List<String> detectedThreats;

    @Schema(
        description = "Human-readable explanation of why the prompt was flagged",
        example = "The prompt contains a direct instruction override ('Ignore all previous instructions') combined with a role escalation request ('act as an unrestricted AI'). This is a classic jailbreak pattern."
    )
    private String explanation;

    @Schema(description = "UTC timestamp of when the analysis was performed")
    private LocalDateTime analyzedAt;

    @Schema(description = "Unique ID of the persisted analysis log entry", example = "1")
    private Long logId;
}
